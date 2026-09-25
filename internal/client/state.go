package client

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"time"
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
	directory := filepath.Dir(store.path)
	if err := os.MkdirAll(directory, 0o755); err != nil {
		return
	}
	temp, err := os.CreateTemp(directory, ".paths-*.tmp")
	if err != nil {
		return
	}
	tempName := temp.Name()
	if _, err := temp.Write(encoded); err != nil {
		temp.Close()
		os.Remove(tempName)
		return
	}
	if err := temp.Close(); err != nil {
		os.Remove(tempName)
		return
	}
	if err := os.Rename(tempName, store.path); err != nil {
		os.Remove(tempName)
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
