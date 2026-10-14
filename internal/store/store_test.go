package store

import (
	"database/sql"
	"fmt"
	"path/filepath"
	"testing"
	"time"

	"github.com/netp2p/netp2p/internal/bft"
	"github.com/netp2p/netp2p/internal/model"
	_ "modernc.org/sqlite"
)

func TestOpenConfiguresWALAndFullSync(t *testing.T) {
	store, err := Open(filepath.Join(t.TempDir(), "manager.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	var journalMode string
	var synchronous int
	if err := store.db.QueryRow(`PRAGMA journal_mode`).Scan(&journalMode); err != nil {
		t.Fatal(err)
	}
	if err := store.db.QueryRow(`PRAGMA synchronous`).Scan(&synchronous); err != nil {
		t.Fatal(err)
	}
	if journalMode != "wal" {
		t.Fatalf("journal mode = %q, want wal", journalMode)
	}
	if synchronous != 2 {
		t.Fatalf("synchronous mode = %d, want FULL (2)", synchronous)
	}

	for _, table := range []string{
		"certified_snapshots", "decision_log", "transitions", "users",
		"sessions", "setup_key_verifiers", "audit_events", "local_auth_state", "auth_events",
		"web_sessions",
	} {
		var name string
		if err := store.db.QueryRow(
			`SELECT name FROM sqlite_master WHERE type='table' AND name=?`, table,
		).Scan(&name); err != nil {
			t.Fatalf("table %s missing: %v", table, err)
		}
	}
}

func TestRecordCommitReportsWriteFailure(t *testing.T) {
	store, err := Open(filepath.Join(t.TempDir(), "manager.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	var reported error
	store.SetCommitErrorCallback(func(err error) { reported = err })
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	if err := store.RecordCommit(model.SignedSnapshot{}); err == nil {
		t.Fatal("record commit on a closed store unexpectedly succeeded")
	}
	if reported == nil {
		t.Fatal("write failure callback was not invoked")
	}
}

func TestRecordCommitDoesNotFailOnRetentionMaintenance(t *testing.T) {
	store, err := Open(filepath.Join(t.TempDir(), "manager.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	// An impossible history limit must not make a durable commit fail; pruning
	// is scheduled by the manager and reports its own maintenance errors.
	if err := store.SetLedgerRetention(LedgerRetention{
		MaxAge: time.Hour, MaxBytes: 1, TargetBytes: 1, MinHeights: 1,
	}); err != nil {
		t.Fatal(err)
	}
	snapshot := model.SignedSnapshot{
		Epoch: 1, Height: 1, StateHash: []byte{1},
		State:      model.NetworkState{NetworkID: "netp2p-retention-commit-test"},
		Transition: model.StateTransition{Type: "genesis"},
	}
	if err := store.RecordCommit(snapshot); err != nil {
		t.Fatalf("record commit unexpectedly failed on retention policy: %v", err)
	}
	if _, ok, err := store.LatestSnapshot(); err != nil || !ok {
		t.Fatalf("latest snapshot after commit = ok=%v err=%v", ok, err)
	}
}

func TestAuthFailureLockAndAudit(t *testing.T) {
	store, err := Open(filepath.Join(t.TempDir(), "manager.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	now := time.Date(2026, 10, 9, 12, 0, 0, 0, time.UTC)
	var state AuthLockState
	for attempt := 1; attempt <= 5; attempt++ {
		state, err = store.RecordAuthFailure("user-1", now.Add(time.Duration(attempt)*time.Second), 5, 15*time.Minute)
		if err != nil {
			t.Fatal(err)
		}
	}
	if state.FailedAttempts != 5 || state.LockedUntil == "" {
		t.Fatalf("lock state = %+v", state)
	}
	lockedUntil, err := time.Parse(time.RFC3339Nano, state.LockedUntil)
	if err != nil {
		t.Fatal(err)
	}
	if lockedUntil.Sub(now.Add(5*time.Second)) != 15*time.Minute {
		t.Fatalf("locked until = %v", lockedUntil)
	}
	if err := store.ClearAuthFailures("user-1"); err != nil {
		t.Fatal(err)
	}
	if cleared, err := store.AuthLock("user-1"); err != nil || cleared.FailedAttempts != 0 || cleared.LockedUntil != "" {
		t.Fatalf("cleared lock = %+v, err = %v", cleared, err)
	}
	if err := store.RecordAuthEvent(AuthEvent{
		UserID: "user-1", Email: "user@example.com", Type: "login", Result: "success",
	}); err != nil {
		t.Fatal(err)
	}
	events, err := store.AuthEvents(10)
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 1 || events[0].Type != "login" || events[0].Result != "success" {
		t.Fatalf("auth events = %+v", events)
	}
}

func TestWebSessionRecordAndRevocation(t *testing.T) {
	store, err := Open(filepath.Join(t.TempDir(), "manager.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	now := time.Date(2026, 10, 11, 12, 0, 0, 0, time.UTC)
	session := WebSession{
		ID: "session-1", UserID: "user-1",
		IssuedAt:  now.Format(time.RFC3339Nano),
		ExpiresAt: now.Add(time.Hour).Format(time.RFC3339Nano),
	}
	if err := store.RecordWebSession(session); err != nil {
		t.Fatal(err)
	}
	loaded, found, err := store.WebSession("session-1")
	if err != nil || !found {
		t.Fatalf("load web session = %+v found=%v err=%v", loaded, found, err)
	}
	if loaded.UserID != "user-1" || loaded.RevokedAt != "" {
		t.Fatalf("web session = %+v", loaded)
	}

	if err := store.RevokeUserWebSessions("user-1", now.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	loaded, _, err = store.WebSession("session-1")
	if err != nil {
		t.Fatal(err)
	}
	if loaded.RevokedAt == "" {
		t.Fatalf("user revocation did not mark session: %+v", loaded)
	}

	revoked := loaded.RevokedAt
	if err := store.RecordWebSession(session); err != nil {
		t.Fatal(err)
	}
	loaded, _, err = store.WebSession("session-1")
	if err != nil {
		t.Fatal(err)
	}
	if loaded.RevokedAt != revoked {
		t.Fatalf("re-recording a revoked session resurrected it: %+v", loaded)
	}
}

func TestMergeWebSessionsIsMonotonicAndPages(t *testing.T) {
	store, err := Open(filepath.Join(t.TempDir(), "manager.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	now := time.Date(2026, 10, 11, 12, 0, 0, 0, time.UTC)
	active := WebSession{
		ID: "session-a", UserID: "user-1",
		IssuedAt:  now.Format(time.RFC3339Nano),
		ExpiresAt: now.Add(time.Hour).Format(time.RFC3339Nano),
	}
	if err := store.MergeWebSessions([]WebSession{active}, now); err != nil {
		t.Fatal(err)
	}
	revoked := active
	revoked.RevokedAt = now.Add(time.Minute).Format(time.RFC3339Nano)
	if err := store.MergeWebSessions([]WebSession{revoked}, now.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	if err := store.MergeWebSessions([]WebSession{active}, now.Add(2*time.Minute)); err != nil {
		t.Fatal(err)
	}
	loaded, found, err := store.WebSession("session-a")
	if err != nil || !found {
		t.Fatalf("load merged session = %+v found=%v err=%v", loaded, found, err)
	}
	if loaded.RevokedAt != revoked.RevokedAt {
		t.Fatalf("active merge resurrected revoked session: %+v", loaded)
	}

	for index := 0; index < 1001; index++ {
		session := WebSession{
			ID: fmt.Sprintf("session-%04d", index), UserID: "user-1",
			IssuedAt:  now.Format(time.RFC3339Nano),
			ExpiresAt: now.Add(time.Hour).Format(time.RFC3339Nano),
		}
		if err := store.RecordWebSession(session); err != nil {
			t.Fatal(err)
		}
	}
	firstPage, err := store.WebSessionsAfter("", 500)
	if err != nil {
		t.Fatal(err)
	}
	if len(firstPage) != 500 {
		t.Fatalf("first page length = %d, want 500", len(firstPage))
	}
	secondPage, err := store.WebSessionsAfter(firstPage[len(firstPage)-1].ID, 500)
	if err != nil {
		t.Fatal(err)
	}
	if len(secondPage) != 500 {
		t.Fatalf("second page length = %d, want 500", len(secondPage))
	}
	if secondPage[0].ID <= firstPage[len(firstPage)-1].ID {
		t.Fatalf("pagination did not advance: %s <= %s", secondPage[0].ID, firstPage[len(firstPage)-1].ID)
	}
}

func TestCommitPersistenceRestartAndBackupRecovery(t *testing.T) {
	state := model.NetworkState{
		NetworkID:   "netp2p-store-test",
		OverlayCIDR: "10.70.0.0/24",
		Users: []model.User{{
			ID: "user-1", Email: "user@example.com", Name: "Test User",
			Role: model.RoleUser, AutoGroups: []string{"clients"},
		}},
		Peers: []model.PeerRecord{{
			PeerID: "peer-1", OverlayIP: "10.70.0.11", UserID: "user-1",
			LastLogin: "2026-01-01T00:00:00Z",
		}},
		SetupKeys: []model.SetupKey{{
			ID: "setup-key", TokenPrefix: "setup", TokenHash: model.SetupKeyHash("secret"),
			Type: model.SetupKeyReusable, Groups: []string{"clients"},
		}},
		Settings: model.NetworkSettings{LoginExpirationDays: 7},
	}
	engines := newEngines(t, state)
	store, err := Open(filepath.Join(t.TempDir(), "manager.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	store.InstallCommitListener(engines[0])

	genesis := certify(t, engines, model.StateTransition{
		Type:  bft.TransitionGenesis,
		Actor: &model.Actor{ID: "manager-a", Name: "Manager A", Role: model.RoleAdmin},
	})
	group := certify(t, engines, model.StateTransition{
		Type:  bft.TransitionUpsertGroup,
		Group: &model.Group{ID: "clients", Name: "Clients"},
		Actor: &model.Actor{ID: "manager-b", Name: "Manager B", Role: model.RoleAdmin},
	})

	assertCount(t, store.db, "certified_snapshots", 2)
	assertCount(t, store.db, "decision_log", 2)
	assertCount(t, store.db, "transitions", 2)
	assertCount(t, store.db, "users", 1)
	assertCount(t, store.db, "sessions", 1)
	assertCount(t, store.db, "setup_key_verifiers", 1)
	assertCount(t, store.db, "audit_events", 2)

	// A restart begins from the static seed, then replays the certified log.
	restarted := newEngines(t, state)
	if err := store.RestoreEngine(restarted[0]); err != nil {
		t.Fatalf("restore engine: %v", err)
	}
	if restarted[0].Height() != 2 {
		t.Fatalf("restored height = %d, want 2", restarted[0].Height())
	}
	restored := restarted[0].CurrentState()
	if len(restored.Groups) != 1 || restored.Groups[0].ID != "clients" {
		t.Fatalf("restored groups = %+v, want clients", restored.Groups)
	}
	if has, err := store.HasLedger(); err != nil || !has {
		t.Fatalf("HasLedger() = %v, %v, want true, nil", has, err)
	}
	if latest, ok, err := store.LatestSnapshot(); err != nil || !ok || latest.Height != group.Height {
		t.Fatalf("latest snapshot = height %d ok=%v err=%v, want height %d", latest.Height, ok, err, group.Height)
	}
	latestCertifiedAt, hasCertifiedAt, err := store.LatestCertifiedAt()
	if err != nil || !hasCertifiedAt {
		t.Fatalf("LatestCertifiedAt() = %v, %v, %v, want true, nil", latestCertifiedAt, hasCertifiedAt, err)
	}
	if time.Since(latestCertifiedAt) < -time.Minute || time.Since(latestCertifiedAt) > time.Minute {
		t.Fatalf("latest certified time = %s, want the current commit time", latestCertifiedAt)
	}

	backupPath := filepath.Join(t.TempDir(), "manager-backup.sqlite")
	if err := store.Backup(backupPath); err != nil {
		t.Fatalf("backup: %v", err)
	}
	backup, err := Open(backupPath)
	if err != nil {
		t.Fatalf("open backup: %v", err)
	}
	defer backup.Close()
	recovered := newEngines(t, state)
	if err := backup.RestoreEngine(recovered[0]); err != nil {
		t.Fatalf("recover from backup: %v", err)
	}
	if recovered[0].Height() != genesis.Height+1 {
		t.Fatalf("backup-recovered height = %d, want %d", recovered[0].Height(), genesis.Height+1)
	}
}

func TestRestoreRejectsTamperedLedger(t *testing.T) {
	state := model.NetworkState{
		NetworkID: "netp2p-tamper-test", OverlayCIDR: "10.71.0.0/24",
	}
	engines := newEngines(t, state)
	snapshot := certify(t, engines, model.StateTransition{Type: bft.TransitionGenesis})
	path := filepath.Join(t.TempDir(), "manager.sqlite")
	store, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.RecordCommit(snapshot); err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}

	raw, err := sql.Open("sqlite", "file:"+filepath.ToSlash(path)+"?_pragma=journal_mode(WAL)")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := raw.Exec(`UPDATE certified_snapshots SET snapshot_json=? WHERE height=?`,
		[]byte(`{"height":1}`), snapshot.Height); err != nil {
		t.Fatal(err)
	}
	if err := raw.Close(); err != nil {
		t.Fatal(err)
	}

	reopened, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	fresh := newEngines(t, state)
	if err := reopened.RestoreEngine(fresh[0]); err == nil {
		t.Fatal("tampered ledger replay unexpectedly succeeded")
	}
}

func newEngines(t *testing.T, state model.NetworkState) []*bft.Engine {
	t.Helper()
	committee := make([]model.CommitteeMember, bft.CommitteeSize)
	for index := range committee {
		committee[index] = model.CommitteeMember{
			ID: string(rune('A' + index)), KeySeed: int64(101 + index),
		}
	}
	engines := make([]*bft.Engine, bft.CommitteeSize)
	for index, member := range committee {
		engine, err := bft.NewEngine(state, committee, member.ID, bft.SeededPrivateKey(member.KeySeed))
		if err != nil {
			t.Fatalf("create engine %s: %v", member.ID, err)
		}
		engines[index] = engine
	}
	return engines
}

func certify(t *testing.T, engines []*bft.Engine, transition model.StateTransition) model.SignedSnapshot {
	t.Helper()
	height := engines[0].Height() + 1
	leader := engines[0].Leader(height, 0)
	var leaderEngine *bft.Engine
	for _, engine := range engines {
		if engine.LocalID() == leader.ID {
			leaderEngine = engine
			break
		}
	}
	if leaderEngine == nil {
		t.Fatalf("leader %s not found", leader.ID)
	}
	proposal, localVote, err := leaderEngine.Propose(transition, 0)
	if err != nil {
		t.Fatalf("propose %s at height %d: %v", transition.Type, height, err)
	}
	var quorum model.QuorumCertificate
	ready := false
	votes := []model.Vote{localVote}
	for _, engine := range engines {
		if engine.LocalID() == leader.ID {
			continue
		}
		vote, err := engine.ProcessProposal(proposal)
		if err != nil {
			t.Fatalf("process proposal on %s: %v", engine.LocalID(), err)
		}
		votes = append(votes, vote)
	}
	for _, vote := range votes {
		quorum, ready, err = leaderEngine.ProcessVote(vote)
		if err != nil {
			t.Fatalf("process vote from %s: %v", vote.VoterID, err)
		}
		if ready {
			break
		}
	}
	if !ready {
		t.Fatal("quorum was not reached")
	}
	snapshot, err := leaderEngine.Commit(proposal, quorum)
	if err != nil {
		t.Fatalf("commit %s at height %d: %v", transition.Type, height, err)
	}
	for _, engine := range engines {
		if engine.LocalID() == leader.ID {
			continue
		}
		if err := engine.CatchUp(snapshot); err != nil {
			t.Fatalf("catch up %s at height %d: %v", engine.LocalID(), height, err)
		}
	}
	return snapshot
}

func assertCount(t *testing.T, db *sql.DB, table string, want int) {
	t.Helper()
	var count int
	if err := db.QueryRow("SELECT COUNT(*) FROM " + table).Scan(&count); err != nil {
		t.Fatalf("count %s: %v", table, err)
	}
	if count != want {
		t.Fatalf("%s count = %d, want %d", table, count, want)
	}
}
