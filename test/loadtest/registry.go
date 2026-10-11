package loadtest

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"hash/fnv"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/netp2p/netp2p/internal/model"
	_ "modernc.org/sqlite"
)

type RegistryPeer struct {
	Record           model.PeerRecord
	ManagerID        string
	SourceGroupID    string
	DestinationScope string
}

type ShardedRegistry struct {
	dbs   []*sql.DB
	root  string
	count int
}

const registrySchema = `
CREATE TABLE IF NOT EXISTS peers (
	peer_id TEXT PRIMARY KEY,
	overlay_ip TEXT NOT NULL,
	hostname TEXT NOT NULL,
	os TEXT NOT NULL,
	client_version TEXT NOT NULL,
	user_id TEXT NOT NULL,
	dns_label TEXT NOT NULL,
	manager_id TEXT NOT NULL,
	source_group_id TEXT NOT NULL,
	destination_scope TEXT NOT NULL,
	groups_json TEXT NOT NULL,
	addresses_json TEXT NOT NULL,
	posture_json TEXT NOT NULL,
	last_login TEXT NOT NULL,
	is_exit_node INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS peers_manager_idx ON peers(manager_id);
CREATE INDEX IF NOT EXISTS peers_source_group_idx ON peers(source_group_id);
CREATE INDEX IF NOT EXISTS peers_destination_scope_idx ON peers(destination_scope);
CREATE TABLE IF NOT EXISTS registry_meta (
	key TEXT PRIMARY KEY,
	value BLOB NOT NULL
);
`

func registryShard(peerID string, shardCount int) int {
	hash := fnv.New64a()
	_, _ = hash.Write([]byte(peerID))
	return int(hash.Sum64() % uint64(shardCount))
}

func openRegistryDatabase(path string) (*sql.DB, error) {
	dsn := "file:" + filepath.ToSlash(filepath.Clean(path)) +
		"?_pragma=journal_mode(WAL)&_pragma=synchronous(NORMAL)&_pragma=busy_timeout(5000)"
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("open registry shard %s: %w", path, err)
	}
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)
	if _, err := db.Exec(registrySchema); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("initialize registry shard %s: %w", path, err)
	}
	return db, nil
}

func CreateShardedRegistry(
	ctx context.Context,
	root string,
	shardCount int,
	count int,
	generate func(index int) RegistryPeer,
) (*ShardedRegistry, error) {
	if root == "" {
		return nil, errors.New("registry root is required")
	}
	if shardCount <= 0 {
		shardCount = 16
	}
	if count < 0 {
		return nil, errors.New("registry count cannot be negative")
	}
	if generate == nil {
		return nil, errors.New("registry generator is required")
	}
	if err := os.MkdirAll(root, 0o700); err != nil {
		return nil, fmt.Errorf("create registry root: %w", err)
	}
	registry := &ShardedRegistry{dbs: make([]*sql.DB, shardCount), root: root, count: count}
	for shard := 0; shard < shardCount; shard++ {
		path := filepath.Join(root, fmt.Sprintf("registry-%03d.db", shard))
		db, err := openRegistryDatabase(path)
		if err != nil {
			_ = registry.Close()
			return nil, err
		}
		registry.dbs[shard] = db
	}

	peerIDs := make([]string, 0, count)
	inserted := make([]int, shardCount)
	transactions := make([]*sql.Tx, shardCount)
	statements := make([]*sql.Stmt, shardCount)
	begin := func(shard int) error {
		tx, err := registry.dbs[shard].BeginTx(ctx, nil)
		if err != nil {
			return fmt.Errorf("begin shard %d: %w", shard, err)
		}
		statement, err := tx.PrepareContext(ctx, `
			INSERT INTO peers(
				peer_id, overlay_ip, hostname, os, client_version, user_id, dns_label,
				manager_id, source_group_id, destination_scope, groups_json,
				addresses_json, posture_json, last_login, is_exit_node
			) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`)
		if err != nil {
			_ = tx.Rollback()
			return fmt.Errorf("prepare shard %d: %w", shard, err)
		}
		transactions[shard] = tx
		statements[shard] = statement
		return nil
	}
	commit := func(shard int) error {
		if transactions[shard] == nil {
			return nil
		}
		if err := statements[shard].Close(); err != nil {
			return fmt.Errorf("close shard %d statement: %w", shard, err)
		}
		if err := transactions[shard].Commit(); err != nil {
			return fmt.Errorf("commit shard %d: %w", shard, err)
		}
		transactions[shard] = nil
		statements[shard] = nil
		return nil
	}
	defer func() {
		for shard := range transactions {
			if statements[shard] != nil {
				_ = statements[shard].Close()
			}
			if transactions[shard] != nil {
				_ = transactions[shard].Rollback()
			}
		}
	}()
	for shard := range registry.dbs {
		if err := begin(shard); err != nil {
			_ = registry.Close()
			return nil, err
		}
	}
	for index := 0; index < count; index++ {
		if err := ctx.Err(); err != nil {
			_ = registry.Close()
			return nil, err
		}
		peer := generate(index)
		shard := registryShard(peer.Record.PeerID, shardCount)
		groupsJSON, err := json.Marshal(peer.Record.Groups)
		if err != nil {
			_ = registry.Close()
			return nil, err
		}
		addressesJSON, err := json.Marshal(peer.Record.Addresses)
		if err != nil {
			_ = registry.Close()
			return nil, err
		}
		postureJSON, err := json.Marshal(peer.Record.Posture)
		if err != nil {
			_ = registry.Close()
			return nil, err
		}
		if _, err := statements[shard].ExecContext(ctx,
			peer.Record.PeerID, peer.Record.OverlayIP, peer.Record.Hostname, peer.Record.OS,
			peer.Record.ClientVersion, peer.Record.UserID, peer.Record.DNSLabel,
			peer.ManagerID, peer.SourceGroupID, peer.DestinationScope, string(groupsJSON),
			string(addressesJSON), string(postureJSON), peer.Record.LastLogin, peer.Record.IsExitNode,
		); err != nil {
			_ = registry.Close()
			return nil, fmt.Errorf("insert peer %d: %w", index, err)
		}
		peerIDs = append(peerIDs, peer.Record.PeerID)
		inserted[shard]++
		if inserted[shard]%10000 == 0 {
			if err := commit(shard); err != nil {
				_ = registry.Close()
				return nil, err
			}
			if err := begin(shard); err != nil {
				_ = registry.Close()
				return nil, err
			}
		}
	}
	for shard := range registry.dbs {
		if err := commit(shard); err != nil {
			_ = registry.Close()
			return nil, err
		}
	}
	rootHash := MerkleRoot(peerIDs)
	for shard := range registry.dbs {
		if _, err := registry.dbs[shard].ExecContext(ctx,
			`INSERT INTO registry_meta(key, value) VALUES ('merkle_root', ?)`, rootHash,
		); err != nil {
			_ = registry.Close()
			return nil, fmt.Errorf("store merkle root: %w", err)
		}
	}
	return registry, nil
}

func MerkleRoot(values []string) []byte {
	if len(values) == 0 {
		return make([]byte, sha256.Size)
	}
	sorted := append([]string(nil), values...)
	sort.Strings(sorted)
	level := make([][]byte, len(sorted))
	for index, value := range sorted {
		digest := sha256.Sum256([]byte(value))
		level[index] = digest[:]
	}
	for len(level) > 1 {
		if len(level)%2 == 1 {
			level = append(level, level[len(level)-1])
		}
		next := make([][]byte, 0, len(level)/2)
		for index := 0; index < len(level); index += 2 {
			digest := sha256.New()
			_, _ = digest.Write(level[index])
			_, _ = digest.Write(level[index+1])
			next = append(next, digest.Sum(nil))
		}
		level = next
	}
	return level[0]
}

func (registry *ShardedRegistry) Close() error {
	if registry == nil {
		return nil
	}
	var firstError error
	for _, db := range registry.dbs {
		if db == nil {
			continue
		}
		if _, err := db.Exec(`PRAGMA wal_checkpoint(TRUNCATE)`); err != nil && firstError == nil {
			firstError = err
		}
		if err := db.Close(); err != nil && firstError == nil {
			firstError = err
		}
	}
	registry.dbs = nil
	return firstError
}

func (registry *ShardedRegistry) Checkpoint() error {
	if registry == nil {
		return errors.New("registry is closed")
	}
	for _, db := range registry.dbs {
		if _, err := db.Exec(`PRAGMA wal_checkpoint(TRUNCATE)`); err != nil {
			return err
		}
	}
	return nil
}

func (registry *ShardedRegistry) Peer(ctx context.Context, peerID string) (model.PeerRecord, error) {
	if registry == nil || len(registry.dbs) == 0 {
		return model.PeerRecord{}, errors.New("registry is closed")
	}
	shard := registryShard(peerID, len(registry.dbs))
	var record model.PeerRecord
	var groupsJSON, addressesJSON, postureJSON string
	var isExitNode int
	err := registry.dbs[shard].QueryRowContext(ctx, `
		SELECT peer_id, overlay_ip, hostname, os, client_version, user_id, dns_label,
		       groups_json, addresses_json, posture_json, last_login, is_exit_node
		FROM peers WHERE peer_id = ?`, peerID,
	).Scan(&record.PeerID, &record.OverlayIP, &record.Hostname, &record.OS, &record.ClientVersion,
		&record.UserID, &record.DNSLabel, &groupsJSON, &addressesJSON, &postureJSON,
		&record.LastLogin, &isExitNode,
	)
	if err != nil {
		return model.PeerRecord{}, err
	}
	if err := json.Unmarshal([]byte(groupsJSON), &record.Groups); err != nil {
		return model.PeerRecord{}, err
	}
	if err := json.Unmarshal([]byte(addressesJSON), &record.Addresses); err != nil {
		return model.PeerRecord{}, err
	}
	if err := json.Unmarshal([]byte(postureJSON), &record.Posture); err != nil {
		return model.PeerRecord{}, err
	}
	record.IsExitNode = isExitNode != 0
	return record, nil
}

func (registry *ShardedRegistry) CountByManager(ctx context.Context, managerID string) (int, error) {
	if registry == nil || len(registry.dbs) == 0 {
		return 0, errors.New("registry is closed")
	}
	total := 0
	for _, db := range registry.dbs {
		var count int
		if err := db.QueryRowContext(ctx, `SELECT COUNT(*) FROM peers WHERE manager_id = ?`, managerID).Scan(&count); err != nil {
			return 0, err
		}
		total += count
	}
	return total, nil
}

func (registry *ShardedRegistry) Root() string {
	if registry == nil {
		return ""
	}
	return registry.root
}

func (registry *ShardedRegistry) MerkleRoot(ctx context.Context) ([]byte, error) {
	if registry == nil || len(registry.dbs) == 0 {
		return nil, errors.New("registry is closed")
	}
	var root []byte
	if err := registry.dbs[0].QueryRowContext(ctx,
		`SELECT value FROM registry_meta WHERE key = 'merkle_root'`,
	).Scan(&root); err != nil {
		return nil, err
	}
	return root, nil
}

func (registry *ShardedRegistry) ShardCount() int {
	if registry == nil {
		return 0
	}
	return len(registry.dbs)
}

func (registry *ShardedRegistry) DiskUsageBytes() (int64, error) {
	if registry == nil {
		return 0, errors.New("registry is closed")
	}
	var total int64
	err := filepath.Walk(registry.root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.Mode().IsRegular() && strings.HasSuffix(path, ".db") {
			total += info.Size()
		}
		return nil
	})
	return total, err
}
