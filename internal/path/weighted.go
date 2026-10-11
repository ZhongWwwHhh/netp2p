package path

import (
	"crypto/sha256"
	"encoding/binary"
	"math"
	"sort"
	"sync"
	"sync/atomic"
	"time"
)

// PathWeight is the runtime fraction of traffic that may use a path family.
// Weights come from a RoutingEpoch and are never authoritative by themselves:
// a path must also pass the certified hard constraints in Constraints.
type PathWeight struct {
	PathID string
	Weight float64
}

// NormalizeWeights returns a deterministic, normalized copy. Zero and negative
// weights are discarded rather than being treated as ineligible paths.
func NormalizeWeights(weights []PathWeight) []PathWeight {
	result := make([]PathWeight, 0, len(weights))
	total := 0.0
	for _, weight := range weights {
		if weight.PathID == "" || weight.Weight <= 0 {
			continue
		}
		result = append(result, weight)
		total += weight.Weight
	}
	if total == 0 {
		return result
	}
	for index := range result {
		result[index].Weight /= total
	}
	sort.Slice(result, func(i, j int) bool { return result[i].PathID < result[j].PathID })
	return result
}

// WeightedRendezvous maps one stable flow identity to one path. It uses the
// standard weight / -ln(uniform) score, which preserves weights much better
// than dividing a hash directly by the weight.
func WeightedRendezvous(weights []PathWeight, flowKey []byte) (string, bool) {
	weights = NormalizeWeights(weights)
	if len(weights) == 0 {
		return "", false
	}
	bestScore := math.Inf(1)
	bestPath := ""
	for _, candidate := range weights {
		digest := pathFlowDigest(flowKey, candidate.PathID)
		uniform := float64(binary.BigEndian.Uint64(digest[:8])) / 18446744073709551616.0
		if uniform <= 0 {
			uniform = math.SmallestNonzeroFloat64
		}
		score := -math.Log(uniform) / candidate.Weight
		if score < bestScore || (score == bestScore && candidate.PathID < bestPath) {
			bestScore = score
			bestPath = candidate.PathID
		}
	}
	return bestPath, bestPath != ""
}

func pathFlowDigest(flowKey []byte, pathID string) [sha256.Size]byte {
	digest := sha256.New()
	_, _ = digest.Write(flowKey)
	_, _ = digest.Write([]byte{0})
	_, _ = digest.Write([]byte(pathID))
	var result [sha256.Size]byte
	digest.Sum(result[:0])
	return result
}

// WeightedSelection keeps an existing healthy flow pinned, then uses weighted
// rendezvous for new flows. Hard failure is resolved locally without waiting
// for the next global epoch.
func WeightedSelection(candidates []LinkProfile, weights []PathWeight, constraints Constraints, flowKey []byte, currentPathID string, hardFailed func(string) bool) Decision {
	byID := make(map[string]LinkProfile, len(candidates))
	eligible := make([]LinkProfile, 0, len(candidates))
	for _, candidate := range candidates {
		if Score(candidate, constraints) == 0 {
			continue
		}
		byID[candidate.PathID] = candidate
		eligible = append(eligible, candidate)
	}
	if len(eligible) == 0 {
		return Decision{}
	}
	if current, ok := byID[currentPathID]; ok && (hardFailed == nil || !hardFailed(currentPathID)) {
		return Decision{Path: current, Score: Score(current, constraints)}
	}
	normalized := make([]PathWeight, 0, len(eligible))
	weightByID := make(map[string]float64, len(weights))
	for _, weight := range weights {
		if weight.Weight > 0 {
			weightByID[weight.PathID] = weight.Weight
		}
	}
	for _, candidate := range eligible {
		if hardFailed != nil && hardFailed(candidate.PathID) {
			continue
		}
		weight := weightByID[candidate.PathID]
		if weight <= 0 {
			weight = 1
		}
		normalized = append(normalized, PathWeight{PathID: candidate.PathID, Weight: weight})
	}
	selected, ok := WeightedRendezvous(normalized, flowKey)
	if !ok {
		return Decision{}
	}
	candidate := byID[selected]
	return Decision{Path: candidate, Score: Score(candidate, constraints)}
}

type FlowIdentity struct {
	Protocol        string
	Source          string
	Destination     string
	SourcePort      uint16
	DestinationPort uint16
}

func (identity FlowIdentity) String() string {
	return identity.Protocol + "\\x00" + identity.Source + "\\x00" + identity.Destination +
		"\\x00" + string([]byte{byte(identity.SourcePort >> 8), byte(identity.SourcePort)}) +
		"\\x00" + string([]byte{byte(identity.DestinationPort >> 8), byte(identity.DestinationPort)})
}

type FlowEntry struct {
	Key            FlowIdentity
	DomainID       string
	FlowClass      FlowClass
	PathID         string
	Bytes          uint64
	Packets        uint64
	CreatedAt      time.Time
	LastUsedAt     time.Time
	LastMigration  time.Time
	MigrationCount uint32
}

type demandKey struct {
	domainID  string
	flowClass FlowClass
}

type flowShard struct {
	mu      sync.Mutex
	entries map[string]*FlowEntry
	demand  map[demandKey]uint64
}

// FlowTable is a bounded, sharded client-side flow table. Per-flow entries are
// cache state; demand counters survive entry eviction so the planner still
// observes traffic from idle or evicted flows.
type FlowTable struct {
	shards   []*flowShard
	capacity int
	ttl      time.Duration
	count    atomic.Int64
}

func NewFlowTable(capacity, shardCount int, ttl time.Duration) *FlowTable {
	if capacity <= 0 {
		capacity = 1048576
	}
	if shardCount <= 0 {
		shardCount = 64
	}
	if shardCount > capacity {
		shardCount = capacity
	}
	if ttl <= 0 {
		ttl = 5 * time.Minute
	}
	shards := make([]*flowShard, shardCount)
	for index := range shards {
		shards[index] = &flowShard{entries: make(map[string]*FlowEntry), demand: make(map[demandKey]uint64)}
	}
	return &FlowTable{shards: shards, capacity: capacity, ttl: ttl}
}

func (table *FlowTable) shardFor(key string) *flowShard {
	digest := sha256.Sum256([]byte(key))
	return table.shards[binary.BigEndian.Uint16(digest[:2])%uint16(len(table.shards))]
}

// Record creates or updates a flow entry. When the hard capacity is reached
// the shard evicts its least valuable entry (idle and low-byte first), never
// silently growing beyond the configured memory ceiling.
func (table *FlowTable) Record(identity FlowIdentity, domainID string, flowClass FlowClass, pathID string, bytes, packets uint64, now time.Time) (FlowEntry, bool) {
	key := identity.String()
	shard := table.shardFor(key)
	shard.mu.Lock()
	defer shard.mu.Unlock()
	if entry, ok := shard.entries[key]; ok {
		entry.Bytes += bytes
		entry.Packets += packets
		entry.LastUsedAt = now
		if entry.PathID != pathID {
			entry.PathID = pathID
			entry.LastMigration = now
			entry.MigrationCount++
		}
		shard.demand[demandKey{domainID, flowClass}] += bytes
		return *entry, true
	}
	for {
		current := table.count.Load()
		if current < int64(table.capacity) {
			if table.count.CompareAndSwap(current, current+1) {
				break
			}
			continue
		}
		if !shard.evictLocked(now, table.ttl) {
			return FlowEntry{}, false
		}
		table.count.Add(-1)
		break
	}
	entry := &FlowEntry{
		Key: identity, DomainID: domainID, FlowClass: flowClass, PathID: pathID,
		Bytes: bytes, Packets: packets, CreatedAt: now, LastUsedAt: now,
	}
	shard.entries[key] = entry
	shard.demand[demandKey{domainID, flowClass}] += bytes
	return *entry, true
}

func (shard *flowShard) evictLocked(now time.Time, ttl time.Duration) bool {
	var victim string
	var victimScore uint64
	victimIsIdle := false
	for key, entry := range shard.entries {
		idle := now.Sub(entry.LastUsedAt) > ttl
		score := entry.Bytes
		if idle {
			score = 0
		}
		if victim == "" || (idle && !victimIsIdle) || (idle == victimIsIdle && score < victimScore) {
			victim = key
			victimScore = score
			victimIsIdle = idle
		}
	}
	if victim == "" {
		return false
	}
	delete(shard.entries, victim)
	return true
}

func (table *FlowTable) Get(identity FlowIdentity) (FlowEntry, bool) {
	shard := table.shardFor(identity.String())
	shard.mu.Lock()
	defer shard.mu.Unlock()
	entry, ok := shard.entries[identity.String()]
	if !ok {
		return FlowEntry{}, false
	}
	return *entry, true
}

func (table *FlowTable) Len() int { return int(table.count.Load()) }

type DomainDemand struct {
	DomainID  string
	FlowClass FlowClass
	Bytes     uint64
}

func (table *FlowTable) Demand() []DomainDemand {
	aggregate := make(map[demandKey]uint64)
	for _, shard := range table.shards {
		shard.mu.Lock()
		for key, bytes := range shard.demand {
			aggregate[key] += bytes
		}
		shard.mu.Unlock()
	}
	result := make([]DomainDemand, 0, len(aggregate))
	for key, bytes := range aggregate {
		result = append(result, DomainDemand{DomainID: key.domainID, FlowClass: key.flowClass, Bytes: bytes})
	}
	sort.Slice(result, func(i, j int) bool {
		if result[i].DomainID != result[j].DomainID {
			return result[i].DomainID < result[j].DomainID
		}
		return result[i].FlowClass < result[j].FlowClass
	})
	return result
}

func (table *FlowTable) EvictIdle(now time.Time) int {
	removed := 0
	for _, shard := range table.shards {
		shard.mu.Lock()
		for key, entry := range shard.entries {
			if now.Sub(entry.LastUsedAt) > table.ttl {
				delete(shard.entries, key)
				removed++
				table.count.Add(-1)
			}
		}
		shard.mu.Unlock()
	}
	return removed
}
