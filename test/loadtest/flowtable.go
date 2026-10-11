package loadtest

import (
	"errors"
	"hash/fnv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/netp2p/netp2p/internal/packet"
)

const DefaultFlowTableCapacity = 1 << 20

type FlowEntry struct {
	Key            packet.Flow
	DestinationID  string
	Domain         RoutingDomainKey
	FlowClass      FlowClass
	PathID         string
	Bytes          uint64
	CreatedAt      time.Time
	LastUsedAt     time.Time
	LastMigration  time.Time
	MigrationCount uint32
}

type flowShard struct {
	mu      sync.RWMutex
	entries map[packet.Flow]*FlowEntry
}

type FlowTable struct {
	shards   []*flowShard
	capacity int
	length   atomic.Int64
}

func NewFlowTable(shards, capacity int) *FlowTable {
	if shards <= 0 {
		shards = 64
	}
	if capacity <= 0 {
		capacity = DefaultFlowTableCapacity
	}
	table := &FlowTable{shards: make([]*flowShard, shards), capacity: capacity}
	for index := range table.shards {
		table.shards[index] = &flowShard{entries: make(map[packet.Flow]*FlowEntry)}
	}
	return table
}

func flowShardIndex(flow packet.Flow, shardCount int) int {
	hash := fnv.New64a()
	var buffer [18]byte
	buffer[0] = flow.Protocol
	buffer[1] = byte(flow.SourcePort >> 8)
	buffer[2] = byte(flow.SourcePort)
	buffer[3] = byte(flow.DestinationPort >> 8)
	buffer[4] = byte(flow.DestinationPort)
	if flow.Source.Is4() {
		source := flow.Source.As4()
		copy(buffer[5:9], source[:])
	}
	if flow.Destination.Is4() {
		destination := flow.Destination.As4()
		copy(buffer[9:13], destination[:])
	}
	_, _ = hash.Write(buffer[:])
	return int(hash.Sum64() % uint64(shardCount))
}

func (table *FlowTable) Observe(entry FlowEntry) {
	shard := table.shards[flowShardIndex(entry.Key, len(table.shards))]
	now := entry.LastUsedAt
	if now.IsZero() {
		now = time.Now()
	}
	shard.mu.Lock()
	defer shard.mu.Unlock()
	if existing, exists := shard.entries[entry.Key]; exists {
		existing.Bytes += entry.Bytes
		existing.LastUsedAt = now
		if existing.PathID != entry.PathID {
			existing.PathID = entry.PathID
			existing.LastMigration = now
			existing.MigrationCount++
		}
		return
	}
	if table.length.Load() >= int64(table.capacity) {
		table.evictLocked(shard, now)
	}
	copyEntry := entry
	copyEntry.CreatedAt = now
	copyEntry.LastUsedAt = now
	shard.entries[entry.Key] = &copyEntry
	table.length.Add(1)
}

func (table *FlowTable) evictLocked(shard *flowShard, now time.Time) {
	var oldestKey packet.Flow
	var oldest time.Time
	found := false
	for key, entry := range shard.entries {
		if !found || entry.LastUsedAt.Before(oldest) {
			oldestKey = key
			oldest = entry.LastUsedAt
			found = true
		}
	}
	if found {
		delete(shard.entries, oldestKey)
		table.length.Add(-1)
		return
	}
	for key := range shard.entries {
		delete(shard.entries, key)
		table.length.Add(-1)
		return
	}
	_ = now
}

func (table *FlowTable) Lookup(flow packet.Flow) (FlowEntry, bool) {
	shard := table.shards[flowShardIndex(flow, len(table.shards))]
	shard.mu.RLock()
	entry, exists := shard.entries[flow]
	shard.mu.RUnlock()
	if !exists {
		return FlowEntry{}, false
	}
	return *entry, true
}

func (table *FlowTable) Len() int {
	return int(table.length.Load())
}

var ErrNoEligiblePath = errors.New("no eligible path")

// SelectPath uses weighted rendezvous hashing. Existing flows remain pinned
// unless their path hard-fails, loses almost all weight, or violates a
// realtime SLA. Ordinary metric jitter does not remap a realtime flow.
func SelectPath(
	flow packet.Flow,
	weights []PathWeight,
	currentPathID string,
	realtime bool,
	hardFailed func(string) bool,
) (string, error) {
	if len(weights) == 0 {
		return "", ErrNoEligiblePath
	}
	currentWeight := 0.0
	currentEligible := false
	for _, weight := range weights {
		if weight.Weight <= 0 || (hardFailed != nil && hardFailed(weight.PathID)) {
			continue
		}
		if weight.PathID == currentPathID {
			currentWeight = weight.Weight
			currentEligible = true
		}
	}
	if currentEligible {
		threshold := 0.02
		if realtime {
			threshold = 0.005
		}
		if currentWeight >= threshold {
			return currentPathID, nil
		}
	}

	bestPath := ""
	bestScore := -1.0
	for _, weight := range weights {
		if weight.Weight <= 0 || (hardFailed != nil && hardFailed(weight.PathID)) {
			continue
		}
		hash := fnv.New64a()
		_, _ = hash.Write([]byte(weight.PathID))
		var flowBytes [8]byte
		flowValue := FlowHash(flow)
		for index := 0; index < 8; index++ {
			flowBytes[index] = byte(flowValue >> (8 * index))
		}
		_, _ = hash.Write(flowBytes[:])
		score := weight.Weight / float64(hash.Sum64()|1)
		if score > bestScore {
			bestScore = score
			bestPath = weight.PathID
		}
	}
	if bestPath == "" {
		return "", ErrNoEligiblePath
	}
	return bestPath, nil
}
