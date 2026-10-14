package store

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/netp2p/netp2p/internal/model"
)

func TestLedgerRetentionPrunesByAgeFirst(t *testing.T) {
	store := openRetentionStore(t)
	defer store.Close()
	recordRetentionSnapshots(t, store, 3)

	now := time.Date(2026, 10, 11, 12, 0, 0, 0, time.UTC)
	setCertifiedAt(t, store, 1, now.Add(-15*24*time.Hour))
	setCertifiedAt(t, store, 2, now.Add(-13*24*time.Hour))
	setCertifiedAt(t, store, 3, now)
	if err := store.SetLedgerRetention(LedgerRetention{
		MaxAge: 14 * 24 * time.Hour, MaxBytes: 1 << 20,
		TargetBytes: 1 << 20, MinHeights: 1,
	}); err != nil {
		t.Fatal(err)
	}

	result, err := store.PruneLedger(now)
	if err != nil {
		t.Fatalf("prune by age: %v", err)
	}
	if result.RemovedSnapshots != 1 || result.RetainedSnapshots != 2 {
		t.Fatalf("age prune result = %+v", result)
	}
	assertCount(t, store.db, "certified_snapshots", 2)
	assertCount(t, store.db, "decision_log", 2)
	assertCount(t, store.db, "transitions", 2)
	assertCount(t, store.db, "audit_events", 2)
	var latest uint64
	if err := store.db.QueryRow(`SELECT MAX(height) FROM certified_snapshots`).Scan(&latest); err != nil {
		t.Fatal(err)
	}
	if latest != 3 {
		t.Fatalf("latest height = %d, want 3", latest)
	}
}

func TestLedgerRetentionPrunesBySizeToLatestCheckpoint(t *testing.T) {
	store := openRetentionStore(t)
	defer store.Close()
	recordRetentionSnapshots(t, store, 3)

	_, limit, err := store.historyRows()
	if err != nil {
		t.Fatal(err)
	}
	if err := store.SetLedgerRetention(LedgerRetention{
		MaxAge: 14 * 24 * time.Hour, MaxBytes: limit,
		TargetBytes: 1, MinHeights: 1,
	}); err != nil {
		t.Fatal(err)
	}
	result, err := store.PruneLedger(time.Now().UTC())
	if err != nil {
		t.Fatalf("prune by size: %v", err)
	}
	if result.RemovedSnapshots != 2 || result.RetainedSnapshots != 1 {
		t.Fatalf("size prune result = %+v", result)
	}
	if result.HistoryBytes > limit {
		t.Fatalf("history bytes after prune = %d, want <= %d", result.HistoryBytes, limit)
	}
	assertCount(t, store.db, "certified_snapshots", 1)
	assertCount(t, store.db, "decision_log", 1)
	assertCount(t, store.db, "transitions", 1)
	assertCount(t, store.db, "audit_events", 1)
}

func openRetentionStore(t *testing.T) *Store {
	t.Helper()
	store, err := Open(filepath.Join(t.TempDir(), "manager.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	return store
}

func recordRetentionSnapshots(t *testing.T, store *Store, count int) {
	t.Helper()
	for height := 1; height <= count; height++ {
		snapshot := model.SignedSnapshot{
			Epoch: uint64(height), Height: uint64(height),
			StateHash: []byte{byte(height)},
			State: model.NetworkState{
				NetworkID: "netp2p-retention-test",
				Peers:     []model.PeerRecord{{PeerID: "peer-a", UserID: "user-a"}},
				Users:     []model.User{{ID: "user-a", Role: "user"}},
			},
			Transition: model.StateTransition{Type: "genesis"},
		}
		if err := store.RecordCommit(snapshot); err != nil {
			t.Fatalf("record snapshot %d: %v", height, err)
		}
	}
}

func setCertifiedAt(t *testing.T, store *Store, height uint64, at time.Time) {
	t.Helper()
	if _, err := store.db.Exec(
		`UPDATE certified_snapshots SET certified_at = ? WHERE height = ?`,
		at.UTC().Format(time.RFC3339Nano), height,
	); err != nil {
		t.Fatalf("set certified_at for height %d: %v", height, err)
	}
}
