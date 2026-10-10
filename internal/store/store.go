// Package store provides the manager's embedded SQLite persistence layer.
package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/netp2p/netp2p/internal/bft"
	"github.com/netp2p/netp2p/internal/model"
	_ "modernc.org/sqlite"
)

const schema = `
CREATE TABLE IF NOT EXISTS certified_snapshots (
	height INTEGER PRIMARY KEY,
	epoch INTEGER NOT NULL,
	state_hash BLOB NOT NULL,
	snapshot_json BLOB NOT NULL,
	certified_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS decision_log (
	sequence INTEGER PRIMARY KEY AUTOINCREMENT,
	height INTEGER NOT NULL UNIQUE,
	transition_type TEXT NOT NULL,
	transition_hash BLOB NOT NULL,
	actor_id TEXT NOT NULL,
	actor_name TEXT NOT NULL,
	actor_role TEXT NOT NULL,
	result TEXT NOT NULL,
	recorded_at TEXT NOT NULL,
	FOREIGN KEY (height) REFERENCES certified_snapshots(height)
);

CREATE TABLE IF NOT EXISTS transitions (
	sequence INTEGER PRIMARY KEY AUTOINCREMENT,
	height INTEGER NOT NULL UNIQUE,
	type TEXT NOT NULL,
	payload_json BLOB NOT NULL,
	state_hash BLOB NOT NULL,
	created_at TEXT NOT NULL,
	FOREIGN KEY (height) REFERENCES certified_snapshots(height)
);

CREATE TABLE IF NOT EXISTS users (
	id TEXT PRIMARY KEY,
	email TEXT NOT NULL,
	name TEXT NOT NULL,
	role TEXT NOT NULL,
	auto_groups_json BLOB NOT NULL,
	blocked INTEGER NOT NULL,
	issued TEXT NOT NULL,
	last_login TEXT NOT NULL,
	snapshot_height INTEGER NOT NULL,
	FOREIGN KEY (snapshot_height) REFERENCES certified_snapshots(height)
);

CREATE TABLE IF NOT EXISTS sessions (
	id TEXT PRIMARY KEY,
	user_id TEXT NOT NULL,
	peer_id TEXT NOT NULL,
	issued_at TEXT NOT NULL,
	expires_at TEXT NOT NULL,
	state TEXT NOT NULL,
	snapshot_height INTEGER NOT NULL,
	FOREIGN KEY (snapshot_height) REFERENCES certified_snapshots(height)
);

CREATE TABLE IF NOT EXISTS setup_key_verifiers (
	id TEXT PRIMARY KEY,
	token_prefix TEXT NOT NULL,
	token_hash BLOB NOT NULL UNIQUE,
	type TEXT NOT NULL,
	groups_json BLOB NOT NULL,
	expires_at TEXT NOT NULL,
	usage_limit INTEGER NOT NULL,
	used_count INTEGER NOT NULL,
	revoked INTEGER NOT NULL,
	created_at TEXT NOT NULL,
	last_used_at TEXT NOT NULL,
	snapshot_height INTEGER NOT NULL,
	FOREIGN KEY (snapshot_height) REFERENCES certified_snapshots(height)
);

CREATE TABLE IF NOT EXISTS audit_events (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	height INTEGER NOT NULL,
	actor_id TEXT NOT NULL,
	actor_name TEXT NOT NULL,
	actor_role TEXT NOT NULL,
	event_type TEXT NOT NULL,
	result TEXT NOT NULL,
	details_json BLOB NOT NULL,
	recorded_at TEXT NOT NULL,
	FOREIGN KEY (height) REFERENCES certified_snapshots(height)
);

CREATE INDEX IF NOT EXISTS decision_log_height_idx ON decision_log(height);
CREATE INDEX IF NOT EXISTS transitions_height_idx ON transitions(height);
CREATE INDEX IF NOT EXISTS sessions_user_idx ON sessions(user_id);
CREATE INDEX IF NOT EXISTS audit_events_height_idx ON audit_events(height);

CREATE TABLE IF NOT EXISTS local_auth_state (
	user_id TEXT PRIMARY KEY,
	failed_attempts INTEGER NOT NULL,
	locked_until TEXT NOT NULL,
	updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS auth_events (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	user_id TEXT NOT NULL,
	email TEXT NOT NULL,
	event_type TEXT NOT NULL,
	result TEXT NOT NULL,
	remote_address TEXT NOT NULL,
	user_agent TEXT NOT NULL,
	recorded_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS auth_events_recorded_idx ON auth_events(recorded_at);
`

// Store is a durable SQLite ledger and certified-state projection. A single
// connection serializes writers and keeps SQLite transaction semantics simple.
type Store struct {
	db   *sql.DB
	path string
}

// Open creates or opens the database with WAL and full fsync durability.
func Open(path string) (*Store, error) {
	if path == "" {
		return nil, fmt.Errorf("store path is required")
	}
	directory := filepath.Dir(path)
	if err := os.MkdirAll(directory, 0o700); err != nil {
		return nil, fmt.Errorf("create store directory: %w", err)
	}
	dsn := "file:" + filepath.ToSlash(filepath.Clean(path)) +
		"?_pragma=journal_mode(WAL)&_pragma=synchronous(FULL)" +
		"&_pragma=foreign_keys(ON)&_pragma=busy_timeout(5000)"
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("open sqlite store: %w", err)
	}
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)
	db.SetConnMaxLifetime(0)

	pingContext, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := db.PingContext(pingContext); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("ping sqlite store: %w", err)
	}
	var journalMode string
	if err := db.QueryRow(`PRAGMA journal_mode`).Scan(&journalMode); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("read sqlite journal mode: %w", err)
	}
	if !strings.EqualFold(journalMode, "wal") {
		_ = db.Close()
		return nil, fmt.Errorf("sqlite journal mode is %q, want WAL", journalMode)
	}
	var synchronous int
	if err := db.QueryRow(`PRAGMA synchronous`).Scan(&synchronous); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("read sqlite synchronous mode: %w", err)
	}
	if synchronous != 2 {
		_ = db.Close()
		return nil, fmt.Errorf("sqlite synchronous mode is %d, want FULL", synchronous)
	}
	if _, err := db.Exec(schema); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("initialize sqlite schema: %w", err)
	}
	return &Store{db: db, path: path}, nil
}

// Close closes the database and checkpoints its WAL.
func (store *Store) Close() error {
	if store == nil || store.db == nil {
		return nil
	}
	_, checkpointErr := store.db.Exec(`PRAGMA wal_checkpoint(TRUNCATE)`)
	closeErr := store.db.Close()
	if checkpointErr != nil {
		return fmt.Errorf("checkpoint sqlite WAL: %w", checkpointErr)
	}
	if closeErr != nil {
		return fmt.Errorf("close sqlite store: %w", closeErr)
	}
	return nil
}

// Path returns the database path.
func (store *Store) Path() string {
	if store == nil {
		return ""
	}
	return store.path
}

// InstallCommitListener persists every snapshot accepted by the engine. SQLite
// errors are logged rather than emitted through the listener signature.
func (store *Store) InstallCommitListener(engine *bft.Engine) {
	engine.OnCommit(func(snapshot model.SignedSnapshot) {
		if err := store.RecordCommit(snapshot); err != nil {
			log.Printf("persist certified snapshot at height %d: %v", snapshot.Height, err)
		}
	})
}

// RecordCommit atomically records a certified decision and refreshes the
// queryable projections derived from its state.
func (store *Store) RecordCommit(snapshot model.SignedSnapshot) error {
	if store == nil || store.db == nil {
		return fmt.Errorf("store is closed")
	}
	snapshotJSON, err := json.Marshal(snapshot)
	if err != nil {
		return fmt.Errorf("encode snapshot: %w", err)
	}
	transitionJSON, err := json.Marshal(snapshot.Transition)
	if err != nil {
		return fmt.Errorf("encode transition: %w", err)
	}
	certifiedAt := time.Now().UTC().Format(time.RFC3339Nano)
	actor := actorFields(snapshot.Transition.Actor)
	transitionHash := bft.TransitionHash(snapshot.Transition)

	tx, err := store.db.Begin()
	if err != nil {
		return fmt.Errorf("begin snapshot transaction: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	_, err = tx.Exec(`
		INSERT INTO certified_snapshots
			(height, epoch, state_hash, snapshot_json, certified_at)
		VALUES (?, ?, ?, ?, ?)
		ON CONFLICT(height) DO NOTHING`,
		snapshot.Height, snapshot.Epoch, snapshot.StateHash, snapshotJSON, certifiedAt)
	if err != nil {
		return fmt.Errorf("insert certified snapshot: %w", err)
	}
	_, err = tx.Exec(`
		INSERT INTO decision_log
			(height, transition_type, transition_hash, actor_id, actor_name, actor_role, result, recorded_at)
		VALUES (?, ?, ?, ?, ?, ?, 'certified', ?)
		ON CONFLICT(height) DO NOTHING`,
		snapshot.Height, snapshot.Transition.Type, transitionHash,
		actor.id, actor.name, actor.role, certifiedAt)
	if err != nil {
		return fmt.Errorf("insert decision log: %w", err)
	}
	_, err = tx.Exec(`
		INSERT INTO transitions
			(height, type, payload_json, state_hash, created_at)
		VALUES (?, ?, ?, ?, ?)
		ON CONFLICT(height) DO NOTHING`,
		snapshot.Height, snapshot.Transition.Type, transitionJSON, snapshot.StateHash, certifiedAt)
	if err != nil {
		return fmt.Errorf("insert transition: %w", err)
	}

	if err := refreshUsers(tx, snapshot, certifiedAt); err != nil {
		return err
	}
	if err := refreshSetupKeyVerifiers(tx, snapshot, certifiedAt); err != nil {
		return err
	}
	if err := refreshSessions(tx, snapshot, certifiedAt); err != nil {
		return err
	}
	_, err = tx.Exec(`
		INSERT INTO audit_events
			(height, actor_id, actor_name, actor_role, event_type, result, details_json, recorded_at)
		VALUES (?, ?, ?, ?, ?, 'certified', ?, ?)`,
		snapshot.Height, actor.id, actor.name, actor.role,
		snapshot.Transition.Type, transitionJSON, certifiedAt)
	if err != nil {
		return fmt.Errorf("insert audit event: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit snapshot transaction: %w", err)
	}
	return nil
}

// Snapshots returns the certified decision log in height order.
func (store *Store) Snapshots() ([]model.SignedSnapshot, error) {
	if store == nil || store.db == nil {
		return nil, fmt.Errorf("store is closed")
	}
	rows, err := store.db.Query(`
		SELECT snapshot_json FROM certified_snapshots ORDER BY height`)
	if err != nil {
		return nil, fmt.Errorf("query certified snapshots: %w", err)
	}
	defer rows.Close()
	var snapshots []model.SignedSnapshot
	for rows.Next() {
		var encoded []byte
		if err := rows.Scan(&encoded); err != nil {
			return nil, fmt.Errorf("scan certified snapshot: %w", err)
		}
		var snapshot model.SignedSnapshot
		if err := json.Unmarshal(encoded, &snapshot); err != nil {
			return nil, fmt.Errorf("decode certified snapshot at height %d: %w", snapshot.Height, err)
		}
		snapshots = append(snapshots, snapshot)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate certified snapshots: %w", err)
	}
	return snapshots, nil
}

// LatestSnapshot returns the highest certified snapshot.
func (store *Store) LatestSnapshot() (model.SignedSnapshot, bool, error) {
	if store == nil || store.db == nil {
		return model.SignedSnapshot{}, false, fmt.Errorf("store is closed")
	}
	var encoded []byte
	err := store.db.QueryRow(`
		SELECT snapshot_json FROM certified_snapshots ORDER BY height DESC LIMIT 1`).Scan(&encoded)
	if err == sql.ErrNoRows {
		return model.SignedSnapshot{}, false, nil
	}
	if err != nil {
		return model.SignedSnapshot{}, false, fmt.Errorf("query latest snapshot: %w", err)
	}
	var snapshot model.SignedSnapshot
	if err := json.Unmarshal(encoded, &snapshot); err != nil {
		return model.SignedSnapshot{}, false, fmt.Errorf("decode latest snapshot: %w", err)
	}
	return snapshot, true, nil
}

// HasLedger reports whether at least one certified snapshot is stored.
func (store *Store) HasLedger() (bool, error) {
	if store == nil || store.db == nil {
		return false, fmt.Errorf("store is closed")
	}
	var count int
	if err := store.db.QueryRow(`SELECT COUNT(*) FROM certified_snapshots`).Scan(&count); err != nil {
		return false, fmt.Errorf("count certified snapshots: %w", err)
	}
	return count > 0, nil
}

// RestoreEngine replays the decision log through the existing BFT catch-up
// path. Every snapshot is cryptographically validated before adoption.
func (store *Store) RestoreEngine(engine *bft.Engine) error {
	snapshots, err := store.Snapshots()
	if err != nil {
		return err
	}
	for _, snapshot := range snapshots {
		if err := engine.CatchUp(snapshot); err != nil {
			return fmt.Errorf("replay certified snapshot at height %d: %w", snapshot.Height, err)
		}
	}
	return nil
}

// Backup writes a compact standalone SQLite database. VACUUM INTO produces a
// transactionally consistent backup even while the source WAL is active.
func (store *Store) Backup(path string) error {
	if store == nil || store.db == nil {
		return fmt.Errorf("store is closed")
	}
	if path == "" {
		return fmt.Errorf("backup path is required")
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return fmt.Errorf("create backup directory: %w", err)
	}
	if _, err := os.Stat(path); err == nil {
		return fmt.Errorf("backup path already exists")
	} else if !os.IsNotExist(err) {
		return fmt.Errorf("check backup path: %w", err)
	}
	escaped := strings.ReplaceAll(filepath.ToSlash(filepath.Clean(path)), "'", "''")
	if _, err := store.db.Exec("VACUUM INTO '" + escaped + "'"); err != nil {
		return fmt.Errorf("create sqlite backup: %w", err)
	}
	return nil
}

type AuthLockState struct {
	FailedAttempts int
	LockedUntil    string
}

type AuthEvent struct {
	UserID        string `json:"userId"`
	Email         string `json:"email,omitempty"`
	Type          string `json:"type"`
	Result        string `json:"result"`
	RemoteAddress string `json:"remoteAddress,omitempty"`
	UserAgent     string `json:"userAgent,omitempty"`
	RecordedAt    string `json:"recordedAt"`
}

// AuthLock returns the local login-failure projection for a user.
func (store *Store) AuthLock(userID string) (AuthLockState, error) {
	if store == nil || store.db == nil {
		return AuthLockState{}, fmt.Errorf("store is closed")
	}
	var state AuthLockState
	err := store.db.QueryRow(
		`SELECT failed_attempts, locked_until FROM local_auth_state WHERE user_id=?`, userID,
	).Scan(&state.FailedAttempts, &state.LockedUntil)
	if err == sql.ErrNoRows {
		return AuthLockState{}, nil
	}
	if err != nil {
		return AuthLockState{}, fmt.Errorf("query auth lock: %w", err)
	}
	return state, nil
}

// RecordAuthFailure increments the failure count and locks the account after
// maxAttempts failures. The lock is intentionally manager-local: a brute-force
// attempt must not be able to grow the certified decision log.
func (store *Store) RecordAuthFailure(
	userID string, now time.Time, maxAttempts int, lockDuration time.Duration,
) (AuthLockState, error) {
	if store == nil || store.db == nil {
		return AuthLockState{}, fmt.Errorf("store is closed")
	}
	if userID == "" || maxAttempts <= 0 || lockDuration <= 0 {
		return AuthLockState{}, fmt.Errorf("invalid auth failure arguments")
	}
	nowText := now.UTC().Format(time.RFC3339Nano)
	tx, err := store.db.Begin()
	if err != nil {
		return AuthLockState{}, fmt.Errorf("begin auth failure transaction: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	var state AuthLockState
	err = tx.QueryRow(
		`SELECT failed_attempts, locked_until FROM local_auth_state WHERE user_id=?`, userID,
	).Scan(&state.FailedAttempts, &state.LockedUntil)
	if err == sql.ErrNoRows {
		state = AuthLockState{}
	} else if err != nil {
		return AuthLockState{}, fmt.Errorf("query auth failure state: %w", err)
	}
	if state.LockedUntil != "" {
		if lockedUntil, parseErr := time.Parse(time.RFC3339Nano, state.LockedUntil); parseErr == nil && now.UTC().Before(lockedUntil) {
			return state, nil
		}
	}
	state.FailedAttempts++
	if state.FailedAttempts >= maxAttempts {
		state.LockedUntil = now.Add(lockDuration).UTC().Format(time.RFC3339Nano)
	} else {
		state.LockedUntil = ""
	}
	if _, err := tx.Exec(`
		INSERT INTO local_auth_state (user_id, failed_attempts, locked_until, updated_at)
		VALUES (?, ?, ?, ?)
		ON CONFLICT(user_id) DO UPDATE SET
			failed_attempts=excluded.failed_attempts,
			locked_until=excluded.locked_until,
			updated_at=excluded.updated_at`,
		userID, state.FailedAttempts, state.LockedUntil, nowText,
	); err != nil {
		return AuthLockState{}, fmt.Errorf("record auth failure: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return AuthLockState{}, fmt.Errorf("commit auth failure: %w", err)
	}
	return state, nil
}

// ClearAuthFailures resets the lock after a successful login.
func (store *Store) ClearAuthFailures(userID string) error {
	if store == nil || store.db == nil {
		return fmt.Errorf("store is closed")
	}
	if _, err := store.db.Exec(`DELETE FROM local_auth_state WHERE user_id=?`, userID); err != nil {
		return fmt.Errorf("clear auth failures: %w", err)
	}
	return nil
}

// RecordAuthEvent writes a non-secret audit record.
func (store *Store) RecordAuthEvent(event AuthEvent) error {
	if store == nil || store.db == nil {
		return fmt.Errorf("store is closed")
	}
	if event.UserID == "" || event.Type == "" || event.Result == "" {
		return fmt.Errorf("user id, event type and result are required")
	}
	if event.RecordedAt == "" {
		event.RecordedAt = time.Now().UTC().Format(time.RFC3339Nano)
	}
	if _, err := store.db.Exec(`
		INSERT INTO auth_events
			(user_id, email, event_type, result, remote_address, user_agent, recorded_at)
		VALUES (?, ?, ?, ?, ?, ?, ?)`,
		event.UserID, event.Email, event.Type, event.Result,
		event.RemoteAddress, event.UserAgent, event.RecordedAt,
	); err != nil {
		return fmt.Errorf("insert auth event: %w", err)
	}
	return nil
}

// AuthEvents returns local authentication audit records, newest first.
func (store *Store) AuthEvents(limit int) ([]AuthEvent, error) {
	if store == nil || store.db == nil {
		return nil, fmt.Errorf("store is closed")
	}
	if limit <= 0 {
		limit = 100
	}
	if limit > 1000 {
		limit = 1000
	}
	rows, err := store.db.Query(`
		SELECT user_id, email, event_type, result, remote_address, user_agent, recorded_at
		FROM auth_events ORDER BY id DESC LIMIT ?`, limit)
	if err != nil {
		return nil, fmt.Errorf("query auth events: %w", err)
	}
	defer rows.Close()
	events := make([]AuthEvent, 0, limit)
	for rows.Next() {
		var event AuthEvent
		if err := rows.Scan(
			&event.UserID, &event.Email, &event.Type, &event.Result,
			&event.RemoteAddress, &event.UserAgent, &event.RecordedAt,
		); err != nil {
			return nil, fmt.Errorf("scan auth event: %w", err)
		}
		events = append(events, event)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate auth events: %w", err)
	}
	return events, nil
}

type actorFieldsResult struct {
	id, name, role string
}

func actorFields(actor *model.Actor) actorFieldsResult {
	result := actorFieldsResult{id: "unknown"}
	if actor == nil {
		return result
	}
	if actor.ID != "" {
		result.id = actor.ID
	}
	result.name = actor.Name
	result.role = actor.Role
	return result
}

func refreshUsers(tx *sql.Tx, snapshot model.SignedSnapshot, certifiedAt string) error {
	if _, err := tx.Exec(`DELETE FROM users`); err != nil {
		return fmt.Errorf("clear users projection: %w", err)
	}
	for _, user := range snapshot.State.Users {
		groups, err := json.Marshal(user.AutoGroups)
		if err != nil {
			return fmt.Errorf("encode user groups: %w", err)
		}
		_, err = tx.Exec(`
			INSERT INTO users
				(id, email, name, role, auto_groups_json, blocked, issued, last_login, snapshot_height)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			user.ID, user.Email, user.Name, user.Role, groups,
			user.Blocked, user.Issued, user.LastLogin, snapshot.Height)
		if err != nil {
			return fmt.Errorf("insert user %q: %w", user.ID, err)
		}
	}
	return nil
}

func refreshSetupKeyVerifiers(tx *sql.Tx, snapshot model.SignedSnapshot, certifiedAt string) error {
	if _, err := tx.Exec(`DELETE FROM setup_key_verifiers`); err != nil {
		return fmt.Errorf("clear setup-key projection: %w", err)
	}
	for _, key := range snapshot.State.SetupKeys {
		if len(key.TokenHash) == 0 {
			continue
		}
		groups, err := json.Marshal(key.Groups)
		if err != nil {
			return fmt.Errorf("encode setup-key groups: %w", err)
		}
		_, err = tx.Exec(`
			INSERT INTO setup_key_verifiers
				(id, token_prefix, token_hash, type, groups_json, expires_at, usage_limit,
				 used_count, revoked, created_at, last_used_at, snapshot_height)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			key.ID, key.TokenPrefix, key.TokenHash, key.Type, groups, key.ExpiresAt,
			key.UsageLimit, key.UsedCount, key.Revoked, key.CreatedAt, key.LastUsedAt, snapshot.Height)
		if err != nil {
			return fmt.Errorf("insert setup-key verifier %q: %w", key.ID, err)
		}
	}
	return nil
}

func refreshSessions(tx *sql.Tx, snapshot model.SignedSnapshot, certifiedAt string) error {
	if _, err := tx.Exec(`DELETE FROM sessions`); err != nil {
		return fmt.Errorf("clear sessions projection: %w", err)
	}
	users := make(map[string]model.User, len(snapshot.State.Users))
	for _, user := range snapshot.State.Users {
		users[user.ID] = user
	}
	for _, peer := range snapshot.State.Peers {
		if peer.UserID == "" {
			continue
		}
		user, known := users[peer.UserID]
		if !known {
			continue
		}
		state := "active"
		if user.Blocked {
			state = "revoked"
		}
		issuedAt := peer.LastLogin
		if issuedAt == "" {
			issuedAt = user.LastLogin
		}
		if issuedAt == "" {
			issuedAt = certifiedAt
		}
		_, err := tx.Exec(`
			INSERT INTO sessions
				(id, user_id, peer_id, issued_at, expires_at, state, snapshot_height)
			VALUES (?, ?, ?, ?, ?, ?, ?)`,
			peer.PeerID, peer.UserID, peer.PeerID, issuedAt,
			sessionExpiry(peer, snapshot.State.Settings.LoginExpirationDays), state, snapshot.Height)
		if err != nil {
			return fmt.Errorf("insert session for peer %q: %w", peer.PeerID, err)
		}
	}
	return nil
}

func sessionExpiry(peer model.PeerRecord, expirationDays int) string {
	if expirationDays <= 0 || peer.LastLogin == "" {
		return ""
	}
	issued, err := time.Parse(time.RFC3339, peer.LastLogin)
	if err != nil {
		return ""
	}
	return issued.AddDate(0, 0, expirationDays).UTC().Format(time.RFC3339)
}
