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
	"sync"
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
CREATE INDEX IF NOT EXISTS certified_snapshots_certified_at_idx ON certified_snapshots(certified_at);
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

CREATE TABLE IF NOT EXISTS web_sessions (
	id TEXT PRIMARY KEY,
	user_id TEXT NOT NULL,
	issued_at TEXT NOT NULL,
	expires_at TEXT NOT NULL,
	revoked_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS web_sessions_user_idx ON web_sessions(user_id);
`

const (
	DefaultLedgerMaxAge      = 14 * 24 * time.Hour
	DefaultLedgerMaxBytes    = int64(20 << 20)
	DefaultLedgerTargetBytes = int64(18 << 20)
)

type LedgerRetention struct {
	MaxAge      time.Duration
	MaxBytes    int64 // Applies to retained history payload bytes, not the SQLite file size.
	TargetBytes int64
	MinHeights  int
}

func DefaultLedgerRetention() LedgerRetention {
	return LedgerRetention{
		MaxAge:      DefaultLedgerMaxAge,
		MaxBytes:    DefaultLedgerMaxBytes,
		TargetBytes: DefaultLedgerTargetBytes,
		MinHeights:  1,
	}
}

func (policy LedgerRetention) Validate() error {
	if policy.MaxAge <= 0 {
		return fmt.Errorf("ledger max age must be positive")
	}
	if policy.MaxBytes <= 0 || policy.TargetBytes <= 0 {
		return fmt.Errorf("ledger byte limits must be positive")
	}
	if policy.TargetBytes > policy.MaxBytes {
		return fmt.Errorf("ledger target bytes cannot exceed max bytes")
	}
	if policy.MinHeights < 1 {
		return fmt.Errorf("ledger minimum retained heights must be at least 1")
	}
	return nil
}

type LedgerPruneResult struct {
	RemovedSnapshots  int   `json:"removedSnapshots"`
	RetainedSnapshots int   `json:"retainedSnapshots"`
	HistoryBytes      int64 `json:"historyBytes"`
	DatabaseBytes     int64 `json:"databaseBytes"`
}

// Store is a durable SQLite ledger and certified-state projection. A single
// connection serializes writers and keeps SQLite transaction semantics simple.
type Store struct {
	db             *sql.DB
	path           string
	retention      LedgerRetention
	commitErrorMu  sync.RWMutex
	commitErrorSub func(error)
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
	return &Store{db: db, path: path, retention: DefaultLedgerRetention()}, nil
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

// SetCommitErrorCallback subscribes to durable ledger write failures. The
// manager uses it to export a Prometheus counter without coupling the store to
// the metrics package.
func (store *Store) SetCommitErrorCallback(callback func(error)) {
	if store == nil {
		return
	}
	store.commitErrorMu.Lock()
	defer store.commitErrorMu.Unlock()
	store.commitErrorSub = callback
}

func (store *Store) reportCommitError(err error) {
	if store == nil || err == nil {
		return
	}
	store.commitErrorMu.RLock()
	callback := store.commitErrorSub
	store.commitErrorMu.RUnlock()
	if callback != nil {
		callback(err)
	}
}

// RecordCommit atomically records a certified decision and refreshes the
// queryable projections derived from its state.
func (store *Store) RecordCommit(snapshot model.SignedSnapshot) (err error) {
	success := false
	defer func() {
		if !success {
			store.reportCommitError(err)
		}
	}()
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

	if err = refreshUsers(tx, snapshot, certifiedAt); err != nil {
		return err
	}
	if err = refreshSetupKeyVerifiers(tx, snapshot, certifiedAt); err != nil {
		return err
	}
	if err = refreshSessions(tx, snapshot, certifiedAt); err != nil {
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
	if err = tx.Commit(); err != nil {
		return fmt.Errorf("commit snapshot transaction: %w", err)
	}
	success = true
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

// LatestCertifiedAt returns the durable commit timestamp for the latest
// snapshot. Metrics need this separately because SignedSnapshot intentionally
// carries no local database metadata.
func (store *Store) LatestCertifiedAt() (time.Time, bool, error) {
	if store == nil || store.db == nil {
		return time.Time{}, false, fmt.Errorf("store is closed")
	}
	var encoded string
	err := store.db.QueryRow(`
		SELECT certified_at FROM certified_snapshots ORDER BY height DESC LIMIT 1`).Scan(&encoded)
	if err == sql.ErrNoRows {
		return time.Time{}, false, nil
	}
	if err != nil {
		return time.Time{}, false, fmt.Errorf("query latest certified time: %w", err)
	}
	certifiedAt, err := time.Parse(time.RFC3339Nano, encoded)
	if err != nil {
		return time.Time{}, false, fmt.Errorf("decode latest certified time: %w", err)
	}
	return certifiedAt.UTC(), true, nil
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

// SetLedgerRetention changes the retention policy used after subsequent
// commits and by explicit PruneLedger calls.
func (store *Store) SetLedgerRetention(policy LedgerRetention) error {
	if store == nil || store.db == nil {
		return fmt.Errorf("store is closed")
	}
	if err := policy.Validate(); err != nil {
		return err
	}
	store.retention = policy
	return nil
}

// PruneLedger applies the age and size limits, whichever is reached first. The
// newest snapshot is always retained as the compact recovery checkpoint.
func (store *Store) PruneLedger(now time.Time) (LedgerPruneResult, error) {
	if store == nil || store.db == nil {
		return LedgerPruneResult{}, fmt.Errorf("store is closed")
	}
	policy := store.retention
	if err := policy.Validate(); err != nil {
		return LedgerPruneResult{}, err
	}
	var count, latest int
	if err := store.db.QueryRow(`
		SELECT COUNT(*), COALESCE(MAX(height), 0) FROM certified_snapshots`,
	).Scan(&count, &latest); err != nil {
		return LedgerPruneResult{}, fmt.Errorf("query ledger bounds: %w", err)
	}
	if count == 0 {
		return LedgerPruneResult{}, nil
	}
	historyRows, historyBytes, err := store.historyRows()
	if err != nil {
		return LedgerPruneResult{}, err
	}
	remove := make(map[uint64]struct{})

	ageRows, err := store.db.Query(`
		SELECT height FROM certified_snapshots
		WHERE height < ? AND certified_at < ?
		ORDER BY height`, latest, now.Add(-policy.MaxAge).Format(time.RFC3339Nano))
	if err != nil {
		return LedgerPruneResult{}, fmt.Errorf("query aged ledger rows: %w", err)
	}
	for ageRows.Next() {
		var height uint64
		if err := ageRows.Scan(&height); err != nil {
			_ = ageRows.Close()
			return LedgerPruneResult{}, fmt.Errorf("scan aged ledger height: %w", err)
		}
		remove[height] = struct{}{}
	}
	if err := ageRows.Err(); err != nil {
		_ = ageRows.Close()
		return LedgerPruneResult{}, fmt.Errorf("iterate aged ledger rows: %w", err)
	}
	if err := ageRows.Close(); err != nil {
		return LedgerPruneResult{}, fmt.Errorf("close aged ledger rows: %w", err)
	}

	if historyBytes >= policy.MaxBytes {
		for _, item := range historyRows {
			if historyBytes <= policy.TargetBytes {
				break
			}
			if item.height == uint64(latest) {
				continue
			}
			remove[item.height] = struct{}{}
			historyBytes -= item.bytes
		}
	}

	retained := count - len(remove)
	for retained < policy.MinHeights && len(remove) > 0 {
		var newest uint64
		found := false
		for height := range remove {
			if !found || height > newest {
				newest = height
				found = true
			}
		}
		if !found {
			break
		}
		delete(remove, newest)
		retained++
	}
	if len(remove) == 0 {
		databaseBytes, err := store.databaseSize()
		if err != nil {
			return LedgerPruneResult{}, err
		}
		return LedgerPruneResult{
			RemovedSnapshots:  0,
			RetainedSnapshots: count,
			HistoryBytes:      historyBytes,
			DatabaseBytes:     databaseBytes,
		}, nil
	}

	tx, err := store.db.Begin()
	if err != nil {
		return LedgerPruneResult{}, fmt.Errorf("begin ledger prune: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	for height := range remove {
		if _, err := tx.Exec(`DELETE FROM audit_events WHERE height = ?`, height); err != nil {
			return LedgerPruneResult{}, fmt.Errorf("delete audit events at height %d: %w", height, err)
		}
		if _, err := tx.Exec(`DELETE FROM decision_log WHERE height = ?`, height); err != nil {
			return LedgerPruneResult{}, fmt.Errorf("delete decision at height %d: %w", height, err)
		}
		if _, err := tx.Exec(`DELETE FROM transitions WHERE height = ?`, height); err != nil {
			return LedgerPruneResult{}, fmt.Errorf("delete transition at height %d: %w", height, err)
		}
		if _, err := tx.Exec(`DELETE FROM certified_snapshots WHERE height = ?`, height); err != nil {
			return LedgerPruneResult{}, fmt.Errorf("delete snapshot at height %d: %w", height, err)
		}
	}
	if err := tx.Commit(); err != nil {
		return LedgerPruneResult{}, fmt.Errorf("commit ledger prune: %w", err)
	}
	if _, err := store.db.Exec(`VACUUM`); err != nil {
		return LedgerPruneResult{}, fmt.Errorf("vacuum ledger: %w", err)
	}
	if _, err := store.db.Exec(`PRAGMA wal_checkpoint(TRUNCATE)`); err != nil {
		return LedgerPruneResult{}, fmt.Errorf("checkpoint ledger after prune: %w", err)
	}
	historyRows, historyBytes, err = store.historyRows()
	if err != nil {
		return LedgerPruneResult{}, err
	}
	var databaseBytes int64
	databaseBytes, err = store.databaseSize()
	if err != nil {
		return LedgerPruneResult{}, err
	}
	result := LedgerPruneResult{
		RemovedSnapshots:  len(remove),
		RetainedSnapshots: count - len(remove),
		HistoryBytes:      historyBytes,
		DatabaseBytes:     databaseBytes,
	}
	if historyBytes > policy.MaxBytes {
		return result, fmt.Errorf("ledger history remains %d bytes after pruning, exceeding %d bytes", historyBytes, policy.MaxBytes)
	}
	return result, nil
}

func (store *Store) historyRows() ([]ledgerHistoryRow, int64, error) {
	rows, err := store.db.Query(`
		SELECT cs.height,
		       LENGTH(cs.snapshot_json)
		     + COALESCE(ts.payload_bytes, 0)
		     + COALESCE(dl.hash_bytes, 0)
		     + COALESCE(ae.details_bytes, 0)
		FROM certified_snapshots AS cs
		LEFT JOIN (
			SELECT height, SUM(LENGTH(payload_json)) AS payload_bytes
			FROM transitions GROUP BY height
		) AS ts ON ts.height = cs.height
		LEFT JOIN (
			SELECT height, SUM(LENGTH(transition_hash)) AS hash_bytes
			FROM decision_log GROUP BY height
		) AS dl ON dl.height = cs.height
		LEFT JOIN (
			SELECT height, SUM(LENGTH(details_json)) AS details_bytes
			FROM audit_events GROUP BY height
		) AS ae ON ae.height = cs.height
		ORDER BY cs.height`)
	if err != nil {
		return nil, 0, fmt.Errorf("query ledger history sizes: %w", err)
	}
	defer rows.Close()

	history := make([]ledgerHistoryRow, 0, 16)
	var total int64
	for rows.Next() {
		var item ledgerHistoryRow
		if err := rows.Scan(&item.height, &item.bytes); err != nil {
			return nil, 0, fmt.Errorf("scan ledger history size: %w", err)
		}
		history = append(history, item)
		total += item.bytes
	}
	if err := rows.Err(); err != nil {
		return nil, 0, fmt.Errorf("iterate ledger history sizes: %w", err)
	}
	return history, total, nil
}

type ledgerHistoryRow struct {
	height uint64
	bytes  int64
}

func (store *Store) databaseSize() (int64, error) {
	if _, err := store.db.Exec(`PRAGMA wal_checkpoint(PASSIVE)`); err != nil {
		return 0, fmt.Errorf("checkpoint sqlite WAL before sizing: %w", err)
	}
	var pageCount, pageSize int64
	if err := store.db.QueryRow(`PRAGMA page_count`).Scan(&pageCount); err != nil {
		return 0, fmt.Errorf("read sqlite page count: %w", err)
	}
	if err := store.db.QueryRow(`PRAGMA page_size`).Scan(&pageSize); err != nil {
		return 0, fmt.Errorf("read sqlite page size: %w", err)
	}
	return pageCount * pageSize, nil
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

// RestoreFrom validates a backup and atomically replaces this store's SQLite
// database with it. The previous database is retained beside the new file until
// the replacement succeeds.
func (store *Store) RestoreFrom(backupPath string) error {
	if store == nil || store.db == nil {
		return fmt.Errorf("store is closed")
	}
	if backupPath == "" {
		return fmt.Errorf("backup path is required")
	}
	absoluteBackup, err := filepath.Abs(backupPath)
	if err != nil {
		return fmt.Errorf("resolve backup path: %w", err)
	}
	absoluteCurrent, err := filepath.Abs(store.path)
	if err != nil {
		return fmt.Errorf("resolve store path: %w", err)
	}
	if strings.EqualFold(absoluteBackup, absoluteCurrent) {
		return fmt.Errorf("backup path must differ from the active store path")
	}

	source, err := Open(absoluteBackup)
	if err != nil {
		return fmt.Errorf("open backup: %w", err)
	}
	snapshots, err := source.Snapshots()
	if err != nil {
		_ = source.Close()
		return err
	}
	if len(snapshots) == 0 {
		_ = source.Close()
		return fmt.Errorf("backup contains no certified snapshots")
	}
	for index, snapshot := range snapshots {
		if err := bft.ValidateSnapshot(snapshot); err != nil {
			_ = source.Close()
			return fmt.Errorf("invalid backup snapshot at height %d: %w", snapshot.Height, err)
		}
		if index > 0 && snapshot.Height != snapshots[index-1].Height+1 {
			_ = source.Close()
			return fmt.Errorf("backup has a height gap from %d to %d", snapshots[index-1].Height, snapshot.Height)
		}
	}

	directory := filepath.Dir(absoluteCurrent)
	temp, err := os.CreateTemp(directory, ".netp2p-restore-*")
	if err != nil {
		_ = source.Close()
		return fmt.Errorf("create restore staging file: %w", err)
	}
	tempPath := temp.Name()
	if err := temp.Close(); err != nil {
		_ = source.Close()
		_ = os.Remove(tempPath)
		return fmt.Errorf("close restore staging file: %w", err)
	}
	if err := os.Remove(tempPath); err != nil {
		_ = source.Close()
		return fmt.Errorf("clear restore staging file: %w", err)
	}
	escapedTemp := strings.ReplaceAll(filepath.ToSlash(tempPath), "'", "''")
	if _, err := source.db.Exec("VACUUM INTO '" + escapedTemp + "'"); err != nil {
		_ = source.Close()
		_ = os.Remove(tempPath)
		return fmt.Errorf("materialize validated backup: %w", err)
	}
	if err := source.Close(); err != nil {
		_ = os.Remove(tempPath)
		return fmt.Errorf("close backup: %w", err)
	}

	retention := store.retention
	if err := store.Close(); err != nil {
		_ = os.Remove(tempPath)
		return fmt.Errorf("close active store before restore: %w", err)
	}
	store.db = nil
	_ = os.Remove(absoluteCurrent + "-wal")
	_ = os.Remove(absoluteCurrent + "-shm")
	previous := absoluteCurrent + ".pre-restore"
	_ = os.Remove(previous)
	if err := os.Rename(absoluteCurrent, previous); err != nil {
		_ = os.Remove(tempPath)
		store.restoreFallback(absoluteCurrent, previous, retention)
		return fmt.Errorf("move active store aside: %w", err)
	}
	if err := os.Rename(tempPath, absoluteCurrent); err != nil {
		_ = os.Rename(previous, absoluteCurrent)
		_ = os.Remove(tempPath)
		store.restoreFallback(absoluteCurrent, previous, retention)
		return fmt.Errorf("install restored store: %w", err)
	}
	reopened, err := Open(absoluteCurrent)
	if err != nil {
		_ = os.Remove(absoluteCurrent)
		_ = os.Rename(previous, absoluteCurrent)
		_ = os.Remove(tempPath)
		store.restoreFallback(absoluteCurrent, previous, retention)
		return fmt.Errorf("reopen restored store: %w", err)
	}
	reopened.retention = retention
	store.db = reopened.db
	store.path = reopened.path
	store.retention = reopened.retention
	_ = os.Remove(previous)
	return nil
}

func (store *Store) restoreFallback(path, previous string, retention LedgerRetention) {
	reopened, err := Open(path)
	if err != nil {
		return
	}
	reopened.retention = retention
	store.db = reopened.db
	store.path = reopened.path
	store.retention = reopened.retention
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

// WebSession is a server-side browser-session record. The signed token or OIDC
// bearer remains with the browser, while this row carries revocation state.
type WebSession struct {
	ID        string `json:"id"`
	UserID    string `json:"userId"`
	IssuedAt  string `json:"issuedAt"`
	ExpiresAt string `json:"expiresAt"`
	RevokedAt string `json:"revokedAt,omitempty"`
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

// RecordWebSession persists a newly issued web session. IDs are generated by
// the session manager or derived from a token hash, so a duplicate is treated
// as a collision rather than as new state.
func (store *Store) RecordWebSession(session WebSession) error {
	if store == nil || store.db == nil {
		return fmt.Errorf("store is closed")
	}
	if session.ID == "" || session.UserID == "" || session.IssuedAt == "" || session.ExpiresAt == "" {
		return fmt.Errorf("web session id, user, issue time and expiry are required")
	}
	if _, err := store.db.Exec(`
		INSERT INTO web_sessions (id, user_id, issued_at, expires_at, revoked_at)
		VALUES (?, ?, ?, ?, '') ON CONFLICT(id) DO NOTHING`,
		session.ID, session.UserID, session.IssuedAt, session.ExpiresAt,
	); err != nil {
		return fmt.Errorf("insert web session: %w", err)
	}
	return nil
}

// WebSessions returns every browser-session record, including revoked
// tombstones. Committee members exchange this projection so a cookie issued by
// one manager remains valid and revocable on every other manager.
func (store *Store) WebSessions() ([]WebSession, error) {
	return store.WebSessionsAfter("", 0)
}

// WebSessionsAfter returns one ordered page of browser-session records. The
// gossip protocol pages this projection so a large console user base cannot
// exceed the control-plane frame limit.
func (store *Store) WebSessionsAfter(cursor string, limit int) ([]WebSession, error) {
	if store == nil || store.db == nil {
		return nil, fmt.Errorf("store is closed")
	}
	query := `
		SELECT id, user_id, issued_at, expires_at, revoked_at
		FROM web_sessions WHERE id>? ORDER BY id`
	args := []any{cursor}
	if limit > 0 {
		if limit > 1000 {
			limit = 1000
		}
		query += ` LIMIT ?`
		args = append(args, limit)
	}
	rows, err := store.db.Query(query, args...)
	if err != nil {
		return nil, fmt.Errorf("query web sessions: %w", err)
	}
	defer rows.Close()
	sessions := make([]WebSession, 0)
	for rows.Next() {
		var session WebSession
		if err := rows.Scan(
			&session.ID, &session.UserID, &session.IssuedAt,
			&session.ExpiresAt, &session.RevokedAt,
		); err != nil {
			return nil, fmt.Errorf("scan web session: %w", err)
		}
		sessions = append(sessions, session)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate web sessions: %w", err)
	}
	return sessions, nil
}

// MergeWebSessions applies a session projection received from another committee
// member. Revocation is monotonic: a tombstone can never be resurrected by a
// stale active record. Expired rows are pruned in the same transaction.
func (store *Store) MergeWebSessions(sessions []WebSession, now time.Time) error {
	if store == nil || store.db == nil {
		return fmt.Errorf("store is closed")
	}
	if len(sessions) > 100000 {
		return fmt.Errorf("too many web sessions: %d", len(sessions))
	}
	nowText := now.UTC().Format(time.RFC3339Nano)
	tx, err := store.db.Begin()
	if err != nil {
		return fmt.Errorf("begin web session merge: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	for _, session := range sessions {
		if session.ID == "" || session.UserID == "" {
			return fmt.Errorf("web session id and user are required")
		}
		issuedAt, err := time.Parse(time.RFC3339Nano, session.IssuedAt)
		if err != nil {
			return fmt.Errorf("web session %s has invalid issue time: %w", session.ID, err)
		}
		expiresAt, err := time.Parse(time.RFC3339Nano, session.ExpiresAt)
		if err != nil || !expiresAt.After(issuedAt) {
			return fmt.Errorf("web session %s has invalid expiry", session.ID)
		}
		if session.RevokedAt != "" {
			revokedAt, err := time.Parse(time.RFC3339Nano, session.RevokedAt)
			if err != nil || revokedAt.Before(issuedAt) {
				return fmt.Errorf("web session %s has invalid revocation time", session.ID)
			}
		}
		if _, err := tx.Exec(`
			INSERT INTO web_sessions (id, user_id, issued_at, expires_at, revoked_at)
			VALUES (?, ?, ?, ?, ?)
			ON CONFLICT(id) DO UPDATE SET
				user_id=excluded.user_id,
				issued_at=excluded.issued_at,
				expires_at=excluded.expires_at,
				revoked_at=CASE
					WHEN web_sessions.revoked_at<>'' THEN web_sessions.revoked_at
					ELSE excluded.revoked_at
				END
			WHERE web_sessions.user_id=excluded.user_id`,
			session.ID, session.UserID, session.IssuedAt, session.ExpiresAt, session.RevokedAt,
		); err != nil {
			return fmt.Errorf("merge web session: %w", err)
		}
	}
	if _, err := tx.Exec(
		`DELETE FROM web_sessions WHERE julianday(expires_at)<julianday(?)`, nowText,
	); err != nil {
		return fmt.Errorf("prune expired web sessions: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit web session merge: %w", err)
	}
	return nil
}

// WebSession returns the persisted state for one server-side session ID.
func (store *Store) WebSession(id string) (WebSession, bool, error) {
	if store == nil || store.db == nil {
		return WebSession{}, false, fmt.Errorf("store is closed")
	}
	if id == "" {
		return WebSession{}, false, fmt.Errorf("web session id is required")
	}
	var session WebSession
	err := store.db.QueryRow(`
		SELECT id, user_id, issued_at, expires_at, revoked_at
		FROM web_sessions WHERE id=?`, id,
	).Scan(&session.ID, &session.UserID, &session.IssuedAt, &session.ExpiresAt, &session.RevokedAt)
	if err == sql.ErrNoRows {
		return WebSession{}, false, nil
	}
	if err != nil {
		return WebSession{}, false, fmt.Errorf("query web session: %w", err)
	}
	return session, true, nil
}

// RevokeWebSession revokes one browser session. Logout uses this even when the
// client presents the token in the Authorization header rather than a cookie.
func (store *Store) RevokeWebSession(id string, now time.Time) error {
	if store == nil || store.db == nil {
		return fmt.Errorf("store is closed")
	}
	if id == "" {
		return fmt.Errorf("web session id is required")
	}
	if _, err := store.db.Exec(`
		UPDATE web_sessions SET revoked_at=? WHERE id=? AND revoked_at=''`,
		now.UTC().Format(time.RFC3339Nano), id,
	); err != nil {
		return fmt.Errorf("revoke web session: %w", err)
	}
	return nil
}

// RevokeUserWebSessions invalidates every active session for a user after a
// credential, role, blocking, or owner-reset change.
func (store *Store) RevokeUserWebSessions(userID string, now time.Time) error {
	if store == nil || store.db == nil {
		return fmt.Errorf("store is closed")
	}
	if userID == "" {
		return fmt.Errorf("user id is required")
	}
	if _, err := store.db.Exec(`
		UPDATE web_sessions SET revoked_at=? WHERE user_id=? AND revoked_at=''`,
		now.UTC().Format(time.RFC3339Nano), userID,
	); err != nil {
		return fmt.Errorf("revoke user web sessions: %w", err)
	}
	return nil
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
