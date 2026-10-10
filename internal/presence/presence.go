// Package presence tracks which peers are currently reachable, as observed
// locally by each manager. Presence is deliberately NOT part of BFT state:
// clients sync with whichever manager they dialed, so different managers can
// legitimately disagree, and broadcasting every heartbeat through consensus
// would grow the decision log without bound.
package presence

import (
	"sort"
	"sync"
	"time"
)

// StaleAfter is how long an observation stays "online" without refresh. The
// client sync stream long-polls for 30s, so 90s tolerates two missed polls.
const StaleAfter = 90 * time.Second

// Observation is one manager's view of a peer at a point in time.
type Observation struct {
	PeerID     string    `json:"peerId"`
	Online     bool      `json:"online"`
	LastSeen   time.Time `json:"lastSeen"`
	RemoteAddr string    `json:"remoteAddr,omitempty"`
	Observer   string    `json:"observer"`
	UpdatedAt  time.Time `json:"updatedAt"`
}

// Table is a last-write-wins merge of observations from several managers. It is
// safe for concurrent use.
type Table struct {
	mu      sync.RWMutex
	entries map[string]Observation
}

func NewTable() *Table {
	return &Table{entries: make(map[string]Observation)}
}

// Observe records that a peer was seen by the local manager right now.
func (table *Table) Observe(peerID, remoteAddr, observer string) Observation {
	return table.Record(Observation{
		PeerID:     peerID,
		Online:     true,
		LastSeen:   time.Now().UTC(),
		RemoteAddr: remoteAddr,
		Observer:   observer,
		UpdatedAt:  time.Now().UTC(),
	})
}

// Disconnect records a peer dropping its connection to the local manager. The
// last seen time is preserved so the UI can show how long ago it was seen.
func (table *Table) Disconnect(peerID, remoteAddr, observer string) Observation {
	table.mu.RLock()
	previous, ok := table.entries[peerID]
	table.mu.RUnlock()
	lastSeen := time.Now().UTC()
	updatedAt := time.Now().UTC()
	if ok && !previous.LastSeen.IsZero() {
		lastSeen = previous.LastSeen
	}
	if ok && !updatedAt.After(previous.UpdatedAt) {
		updatedAt = previous.UpdatedAt.Add(time.Nanosecond)
	}
	return table.Record(Observation{
		PeerID:     peerID,
		Online:     false,
		LastSeen:   lastSeen,
		RemoteAddr: remoteAddr,
		Observer:   observer,
		UpdatedAt:  updatedAt,
	})
}

// Record merges one observation using last-write-wins. Ties on UpdatedAt are
// broken by observer id so every manager converges on the same entry.
func (table *Table) Record(observation Observation) Observation {
	if observation.UpdatedAt.IsZero() {
		observation.UpdatedAt = time.Now().UTC()
	}
	table.mu.Lock()
	defer table.mu.Unlock()
	if current, ok := table.entries[observation.PeerID]; ok && !newer(observation, current) {
		return current
	}
	table.entries[observation.PeerID] = observation
	return observation
}

// newer reports whether candidate supersedes current under LWW.
func newer(candidate, current Observation) bool {
	if candidate.UpdatedAt.After(current.UpdatedAt) {
		return true
	}
	if candidate.UpdatedAt.Before(current.UpdatedAt) {
		return false
	}
	return candidate.Observer > current.Observer
}

// Snapshot returns every observation with freshness applied, sorted by peer id.
func (table *Table) Snapshot() []Observation {
	return table.SnapshotAt(time.Now().UTC())
}

// SnapshotAt is Snapshot with an explicit clock, which keeps staleness
// deterministic in tests.
func (table *Table) SnapshotAt(now time.Time) []Observation {
	table.mu.RLock()
	defer table.mu.RUnlock()
	result := make([]Observation, 0, len(table.entries))
	for _, observation := range table.entries {
		observation.Online = observation.Online && now.Sub(observation.LastSeen) < StaleAfter
		result = append(result, observation)
	}
	sort.Slice(result, func(i, j int) bool { return result[i].PeerID < result[j].PeerID })
	return result
}

// Merge folds remote observations into the table and returns how many changed.
func (table *Table) Merge(observations []Observation) int {
	changed := 0
	for _, observation := range observations {
		if observation.PeerID == "" {
			continue
		}
		table.mu.RLock()
		current, ok := table.entries[observation.PeerID]
		table.mu.RUnlock()
		if ok && !newer(observation, current) {
			continue
		}
		table.mu.Lock()
		table.entries[observation.PeerID] = observation
		table.mu.Unlock()
		changed++
	}
	return changed
}
