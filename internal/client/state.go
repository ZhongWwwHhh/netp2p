package client

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/netp2p/netp2p/internal/bft"
	"github.com/netp2p/netp2p/internal/model"
)

// defaultPathTTL bounds how long a persisted path decision is trusted. The
// certified assignment is authoritative, so a stale hint is only useful for the
// first selection after a restart; an expired hint is discarded rather than
// risking a dead path.
const defaultPathTTL = 24 * time.Hour

// defaultPathFlushDebounce rate-limits disk writes. Selection happens per
// packet, so writing on every change would be wasteful; the file only has to be
// current enough to survive a restart.
const defaultPathFlushDebounce = time.Second

// persistedPaths is the on-disk shape. It stores only peer/path identifiers and
// admission conclusions, never payloads, so it is not sensitive.
type persistedPaths struct {
	Version      int                             `json:"version"`
	UpdatedAt    time.Time                       `json:"updatedAt,omitempty"`
	Destinations map[string]persistedDestination `json:"destinations,omitempty"`
	Admissions   map[string]persistedAdmission   `json:"admissions,omitempty"`
}

type persistedDestination struct {
	LastGoodPathID string    `json:"lastGoodPathId"`
	UpdatedAt      time.Time `json:"updatedAt"`
}

type persistedAdmission struct {
	OK        bool      `json:"ok"`
	ChangedAt time.Time `json:"changedAt"`
}

// ClientState is the persistence and manager-connectivity state exposed to
// operators. It is deliberately independent of packet-forwarding health.
type ClientState string

const (
	ClientStateReady      ClientState = "ready"
	ClientStateDegraded   ClientState = "degraded"
	ClientStateNeedsLogin ClientState = "needs-login"
	ClientStateFailed     ClientState = "failed"
)

// ClientManagerStatus describes the current manager endpoint and the last
// connectivity failure, if any.
type ClientManagerStatus struct {
	State           ClientState
	ActiveManager   peer.ID
	ManagerEndpoint string
	Managers        []string
	ActiveIndex     int
	LastError       string
	SnapshotHeight  uint64
	NextAction      string
}

// ClientPathDiagnostics summarizes the latest outbound path decision. Values
// identify peers and failure classes only; they never contain packet payloads
// or raw packet contents.
type ClientPathDiagnostics struct {
	LastState              string `json:"lastState,omitempty"`
	LastError              string `json:"lastError,omitempty"`
	LastOutboundDropReason string `json:"lastOutboundDropReason,omitempty"`
}

// persistedClientState is the local recovery record. The snapshot was fully
// validated before it was written, so a restart can use it read-only while
// manager connectivity is re-established.
type persistedClientState struct {
	Version          int                  `json:"version"`
	UpdatedAt        time.Time            `json:"updatedAt"`
	LocalPeerID      string               `json:"localPeerId"`
	ManagerEndpoints []string             `json:"managerEndpoints,omitempty"`
	ActiveManager    string               `json:"activeManager,omitempty"`
	Snapshot         model.SignedSnapshot `json:"snapshot"`
	Self             model.PeerRecord     `json:"self"`
}

// RecoveryBootstrap contains only the fields needed to configure a daemon
// restart before it can connect to a manager. The certified snapshot itself
// remains private to the client state store.
type RecoveryBootstrap struct {
	LocalPeerID      string
	NetworkID        string
	ManagerEndpoints []string
}

// LoadRecoveryBootstrap validates the persisted certified snapshot and returns
// its manager failover endpoints so an upgrade can retain a first-run profile
// while resuming the existing local identity.
func LoadRecoveryBootstrap(stateDir string) (RecoveryBootstrap, error) {
	store := loadClientStateStore(filepath.Join(stateDir, "state.json"))
	state := store.data
	if state.Version != 1 || state.LocalPeerID == "" {
		return RecoveryBootstrap{}, fmt.Errorf("client recovery state is absent or unsupported")
	}
	if err := bft.ValidateClientSnapshot(state.Snapshot); err != nil {
		return RecoveryBootstrap{}, fmt.Errorf("client recovery snapshot is invalid: %w", err)
	}
	endpoints := make([]string, 0, len(state.ManagerEndpoints))
	for _, endpoint := range state.ManagerEndpoints {
		if endpoint != "" {
			endpoints = append(endpoints, endpoint)
		}
	}
	if len(endpoints) == 0 {
		return RecoveryBootstrap{}, fmt.Errorf("client recovery state has no manager endpoints")
	}
	return RecoveryBootstrap{
		LocalPeerID:      state.LocalPeerID,
		NetworkID:        state.Snapshot.State.NetworkID,
		ManagerEndpoints: endpoints,
	}, nil
}

// pathStore persists the last-known-good path per destination and the local
// admission conclusion per path so a restart resumes from the same state
// instead of re-probing from scratch. It is safe for concurrent use.
type pathStore struct {
	path     string
	ttl      time.Duration
	debounce time.Duration
	now      func() time.Time

	mu        sync.Mutex
	data      persistedPaths
	dirty     bool
	lastWrite time.Time
	flusher   *time.Timer
	closed    bool
}

// loadPathStore reads a store from disk. A missing or corrupt file is treated
// as an empty cache: persistence is an optimization, never a source of truth.
func loadPathStore(path string, ttl time.Duration) *pathStore {
	store := &pathStore{
		path: path, ttl: ttl, debounce: defaultPathFlushDebounce, now: time.Now,
		data: persistedPaths{Version: 1, Destinations: map[string]persistedDestination{}, Admissions: map[string]persistedAdmission{}},
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return store
	}
	var loaded persistedPaths
	if err := json.Unmarshal(raw, &loaded); err != nil {
		return store
	}
	if loaded.Destinations != nil {
		store.data.Destinations = loaded.Destinations
	}
	if loaded.Admissions != nil {
		store.data.Admissions = loaded.Admissions
	}
	store.pruneExpired()
	return store
}

// pruneExpired drops entries older than the TTL so a long-idle client does not
// resume from a decision made days ago.
func (store *pathStore) pruneExpired() {
	cutoff := store.now().Add(-store.ttl)
	pruned := false
	for destination, entry := range store.data.Destinations {
		if entry.UpdatedAt.Before(cutoff) {
			delete(store.data.Destinations, destination)
			pruned = true
		}
	}
	for pathID, entry := range store.data.Admissions {
		if entry.ChangedAt.Before(cutoff) {
			delete(store.data.Admissions, pathID)
			pruned = true
		}
	}
	if pruned {
		store.dirty = true
	}
}

// lastGood returns the persisted path for a destination when it is still fresh.
func (store *pathStore) lastGood(destination string) (string, bool) {
	if store == nil || store.path == "" {
		return "", false
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	entry, ok := store.data.Destinations[destination]
	if !ok || entry.LastGoodPathID == "" {
		return "", false
	}
	if entry.UpdatedAt.Before(store.now().Add(-store.ttl)) {
		return "", false
	}
	return entry.LastGoodPathID, true
}

// admission returns the persisted usability conclusion for a path.
func (store *pathStore) admission(pathID string) (bool, bool) {
	if store == nil || store.path == "" {
		return false, false
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	entry, ok := store.data.Admissions[pathID]
	if !ok {
		return false, false
	}
	if entry.ChangedAt.Before(store.now().Add(-store.ttl)) {
		return false, false
	}
	return entry.OK, true
}

// setLastGood records the selected path for a destination.
func (store *pathStore) setLastGood(destination, pathID string) {
	if store == nil || store.path == "" || pathID == "" {
		return
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	if existing, ok := store.data.Destinations[destination]; ok && existing.LastGoodPathID == pathID {
		return
	}
	store.data.Destinations[destination] = persistedDestination{LastGoodPathID: pathID, UpdatedAt: store.now()}
	store.markDirtyLocked()
}

// recordAdmission persists an admission conclusion when it changes.
func (store *pathStore) recordAdmission(pathID string, ok bool) {
	if store == nil || store.path == "" || pathID == "" {
		return
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	if existing, found := store.data.Admissions[pathID]; found && existing.OK == ok {
		return
	}
	store.data.Admissions[pathID] = persistedAdmission{OK: ok, ChangedAt: store.now()}
	store.markDirtyLocked()
}

// markDirtyLocked schedules a flush, honoring the debounce window. The caller
// must hold the lock.
func (store *pathStore) markDirtyLocked() {
	if store.closed {
		return
	}
	store.dirty = true
	now := store.now()
	if now.Sub(store.lastWrite) >= store.debounce {
		store.writeLocked()
		return
	}
	if store.flusher != nil {
		return
	}
	remaining := store.debounce - now.Sub(store.lastWrite)
	store.flusher = time.AfterFunc(remaining, store.flush)
}

// flush writes pending changes. It is what the debounce timer invokes.
func (store *pathStore) flush() {
	if store == nil {
		return
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	store.flusher = nil
	if store.dirty && !store.closed {
		store.writeLocked()
	}
}

// writeLocked performs an atomic write (temp file + rename) so a crash cannot
// leave a half-written cache behind. The caller must hold the lock.
func (store *pathStore) writeLocked() {
	store.data.Version = 1
	store.data.UpdatedAt = store.now()
	encoded, err := json.Marshal(store.data)
	if err != nil {
		return
	}
	if err := atomicWrite(store.path, encoded); err != nil {
		return
	}
	store.dirty = false
	store.lastWrite = store.now()
}

// close stops the debounce timer and flushes any pending change.
func (store *pathStore) close() {
	if store == nil {
		return
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	store.closed = true
	if store.flusher != nil {
		store.flusher.Stop()
		store.flusher = nil
	}
	if store.dirty {
		store.writeLocked()
	}
}

// clientStateStore persists the last validated certified snapshot and the
// identity it belongs to. It is separate from the path cache because its
// lifetime and failure semantics are different.
type clientStateStore struct {
	path string
	mu   sync.Mutex
	data persistedClientState
}

func loadClientStateStore(path string) *clientStateStore {
	store := &clientStateStore{path: path}
	raw, err := os.ReadFile(path)
	if err != nil {
		return store
	}
	var loaded persistedClientState
	if err := json.Unmarshal(raw, &loaded); err != nil {
		return store
	}
	if loaded.Version != 1 {
		return store
	}
	store.data = loaded
	return store
}

func (store *clientStateStore) save(state persistedClientState) error {
	if store == nil || store.path == "" {
		return nil
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	state.Version = 1
	state.UpdatedAt = time.Now().UTC()
	encoded, err := json.Marshal(state)
	if err != nil {
		return fmt.Errorf("encode client state: %w", err)
	}
	if err := atomicWrite(store.path, encoded); err != nil {
		return fmt.Errorf("write client state: %w", err)
	}
	store.data = state
	return nil
}

// atomicWrite writes a complete file before replacing the destination and
// fsyncs the file before rename. Directory syncing is best effort because some
// platforms do not support it, but the file itself is always synced first.
func atomicWrite(path string, encoded []byte) error {
	directory := filepath.Dir(path)
	if err := os.MkdirAll(directory, 0o700); err != nil {
		return fmt.Errorf("create state directory: %w", err)
	}
	temp, err := os.CreateTemp(directory, ".state-*.tmp")
	if err != nil {
		return fmt.Errorf("create temporary state file: %w", err)
	}
	tempName := temp.Name()
	if _, err := temp.Write(encoded); err != nil {
		_ = temp.Close()
		_ = os.Remove(tempName)
		return fmt.Errorf("write temporary state file: %w", err)
	}
	if err := temp.Sync(); err != nil {
		_ = temp.Close()
		_ = os.Remove(tempName)
		return fmt.Errorf("sync temporary state file: %w", err)
	}
	if err := temp.Close(); err != nil {
		_ = os.Remove(tempName)
		return fmt.Errorf("close temporary state file: %w", err)
	}
	if err := os.Rename(tempName, path); err != nil {
		_ = os.Remove(tempName)
		return fmt.Errorf("replace state file: %w", err)
	}
	syncDirectory(directory)
	return nil
}

func syncDirectory(path string) {
	directory, err := os.Open(path)
	if err != nil {
		return
	}
	defer directory.Close()
	_ = directory.Sync()
}

// setManagers validates and deduplicates the configured manager endpoints.
func (client *Client) setManagers() error {
	addresses := make([]string, 0, len(client.managerAddresses))
	seen := make(map[string]struct{}, len(client.managerAddresses))
	for _, address := range client.managerAddresses {
		if address == "" {
			continue
		}
		if _, duplicate := seen[address]; duplicate {
			continue
		}
		seen[address] = struct{}{}
		addresses = append(addresses, address)
	}
	if len(addresses) == 0 {
		return fmt.Errorf("no manager endpoints configured")
	}
	managers := make([]peer.AddrInfo, 0, len(addresses))
	seenIDs := make(map[string]struct{}, len(addresses))
	for _, address := range addresses {
		info, err := peer.AddrInfoFromString(address)
		if err != nil {
			return fmt.Errorf("invalid manager address %q: %w", address, err)
		}
		key := info.ID.String()
		if _, duplicate := seenIDs[key]; duplicate {
			continue
		}
		seenIDs[key] = struct{}{}
		managers = append(managers, *info)
	}
	if len(managers) == 0 {
		return fmt.Errorf("no distinct manager endpoints configured")
	}
	client.managers = managers
	client.manager = managers[0]
	client.activeManager = 0
	return nil
}

// restorePersistedState applies the last validated snapshot only when it
// belongs to the current local identity. A mismatch is discarded rather than
// mixing one peer's certified state with another peer's private identity.
func (client *Client) restorePersistedState() {
	if client.stateStore == nil {
		client.connectionState = ClientStateNeedsLogin
		return
	}
	state := client.stateStore.data
	localPeerID := client.node.Host.ID().String()
	if state.LocalPeerID == "" || state.LocalPeerID != localPeerID {
		client.connectionState = ClientStateNeedsLogin
		return
	}
	if err := bft.ValidateClientSnapshot(state.Snapshot); err != nil {
		client.connectionState = ClientStateNeedsLogin
		return
	}
	client.mu.Lock()
	for index, manager := range client.managers {
		if manager.ID.String() == state.ActiveManager {
			client.manager = manager
			client.activeManager = index
			break
		}
	}
	client.snapshot = state.Snapshot
	if state.Self.PeerID != "" {
		client.self = state.Self
	}
	client.connectionState = ClientStateDegraded
	client.mu.Unlock()
}

func (client *Client) persistSnapshot(snapshot model.SignedSnapshot, self model.PeerRecord) {
	if client.stateStore == nil {
		return
	}
	client.mu.RLock()
	activeManager := client.manager.ID.String()
	client.mu.RUnlock()
	state := persistedClientState{
		LocalPeerID: client.node.Host.ID().String(), ManagerEndpoints: client.managerAddresses,
		ActiveManager: activeManager, Snapshot: snapshot, Self: self,
	}
	if err := client.stateStore.save(state); err != nil {
		log.Printf("persist client state: %v", err)
	}
}

// State returns the client's persistence and manager-connectivity state.
func (client *Client) State() ClientState {
	client.mu.RLock()
	defer client.mu.RUnlock()
	if client.connectionState == "" {
		return ClientStateNeedsLogin
	}
	return client.connectionState
}

func (client *Client) activeManagerIndexLocked() int {
	if len(client.manager.ID) == 0 {
		return -1
	}
	for index, address := range client.managerAddresses {
		info, err := peer.AddrInfoFromString(address)
		if err == nil && info.ID == client.manager.ID {
			return index
		}
	}
	return -1
}

// ManagerStatus returns the operator-facing manager failover view.
func (client *Client) ManagerStatus() ClientManagerStatus {
	client.mu.RLock()
	defer client.mu.RUnlock()
	return ClientManagerStatus{
		State: client.connectionState, ActiveManager: client.manager.ID,
		ManagerEndpoint: client.managerAddress(), Managers: append([]string(nil), client.managerAddresses...), ActiveIndex: client.activeManagerIndexLocked(), LastError: client.lastManagerError,
		SnapshotHeight: client.snapshot.Height, NextAction: client.nextActionLocked(),
	}
}

// PathDiagnostics returns the latest certified-path decision and outbound drop
// reason. It is safe for concurrent use with the packet read loop.
func (client *Client) PathDiagnostics() ClientPathDiagnostics {
	client.mu.RLock()
	defer client.mu.RUnlock()
	return ClientPathDiagnostics{
		LastState: string(client.pathState), LastError: client.pathError,
		LastOutboundDropReason: client.outboundDrop,
	}
}

func (client *Client) recordPathSelection(destination peer.ID, status PathSelectionStatus) {
	client.mu.Lock()
	defer client.mu.Unlock()
	client.pathState = status.State
	if status.OK {
		client.pathError = ""
		return
	}
	message := "path selection failed"
	if status.Err != nil {
		message = status.Err.Error()
	}
	client.pathError = fmt.Sprintf("to %s: %s", destination, message)
}

func (client *Client) markOutboundDrop(reason string) {
	client.mu.Lock()
	defer client.mu.Unlock()
	client.outboundDrop = reason
}

func (client *Client) clearOutboundDrop() {
	client.mu.Lock()
	defer client.mu.Unlock()
	client.outboundDrop = ""
}

// NextAction gives diagnostics and the doctor a concrete operator-facing next
// step instead of leaving them to infer one from a warning list.
func (client *Client) NextAction() string {
	client.mu.RLock()
	defer client.mu.RUnlock()
	return client.nextActionLocked()
}

func (client *Client) nextActionLocked() string {
	if client.outboundDrop != "" {
		return fmt.Sprintf(
			"Last data-plane drop: %s. Run netp2p doctor to check assignment state, routes, and manager connectivity.",
			client.outboundDrop,
		)
	}
	switch client.connectionState {
	case ClientStateReady:
		return "No action required."
	case ClientStateDegraded:
		return "Run netp2p doctor and restore manager connectivity; the persisted certified state remains usable."
	case ClientStateNeedsLogin:
		return "Run netp2p login with a valid setup key or SSO account."
	case ClientStateFailed:
		return "Run netp2p doctor, fix the reported manager or local failure, then retry login."
	default:
		return "Run netp2p doctor to identify the client state."
	}
}

func (client *Client) managerAddress() string {
	if client.manager.ID == "" || len(client.manager.Addrs) == 0 {
		return ""
	}
	return client.manager.Addrs[0].String()
}

func (client *Client) setClientState(state ClientState) {
	client.mu.Lock()
	client.connectionState = state
	client.mu.Unlock()
}

func (client *Client) markManagerRequestFailure(err error) {
	message := "manager request failed"
	if err != nil {
		message = err.Error()
	}
	client.mu.Lock()
	client.lastManagerError = message
	if client.snapshot.Height > 0 {
		client.connectionState = ClientStateDegraded
	} else {
		client.connectionState = ClientStateFailed
	}
	client.mu.Unlock()
}

func (client *Client) markSyncError(err *SyncError) {
	message := "sync failed"
	if err != nil && err.Error() != "" {
		message = err.Error()
	}
	state := ClientStateFailed
	if client.SnapshotHeight() > 0 {
		state = ClientStateDegraded
	}
	if err != nil && (err.Code == "peer_removed" || err.Code == "network_mismatch") {
		state = ClientStateNeedsLogin
	}
	client.mu.Lock()
	client.lastManagerError = message
	client.connectionState = state
	client.mu.Unlock()
}

func (client *Client) persistedStateForClose() persistedClientState {
	client.mu.RLock()
	defer client.mu.RUnlock()
	return persistedClientState{
		LocalPeerID: client.node.Host.ID().String(), ManagerEndpoints: client.managerAddresses,
		ActiveManager: client.manager.ID.String(), Snapshot: client.snapshot, Self: client.self,
	}
}
