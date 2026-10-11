package client

import (
	"container/heap"
	"sync"
	"sync/atomic"
	"time"

	"github.com/netp2p/netp2p/internal/conntrack"
	"github.com/netp2p/netp2p/internal/packet"
)

const (
	defaultFlowTableCapacity = 1_000_000
	defaultFlowShardCount    = 250
)

// FlowClass is the client-side runtime traffic class. It deliberately supports
// realtime even while older certified-state validators only know the original
// four classes; an explicit policy or route class always wins over heuristics.
type FlowClass string

const (
	FlowClassLatency     FlowClass = "latency"
	FlowClassThroughput  FlowClass = "throughput"
	FlowClassCost        FlowClass = "cost"
	FlowClassReliability FlowClass = "reliability"
	FlowClassRealtime    FlowClass = "realtime"
)

// ParseFlowClass returns the canonical class and whether value was explicit.
func ParseFlowClass(value string) (FlowClass, bool) {
	switch FlowClass(value) {
	case FlowClassLatency, FlowClassThroughput, FlowClassCost, FlowClassReliability, FlowClassRealtime:
		return FlowClass(value), true
	default:
		return FlowClassLatency, false
	}
}

func normalizeFlowClass(value, fallback string) FlowClass {
	if class, explicit := ParseFlowClass(value); explicit {
		return class
	}
	if class, explicit := ParseFlowClass(fallback); explicit {
		return class
	}
	return FlowClassLatency
}

// classifyFlow resolves the five-class identity. Explicit certified policy or
// route configuration takes precedence; only unclassified traffic uses protocol
// and destination-port heuristics.
func classifyFlow(protocol string, port uint16, explicit, fallback string) FlowClass {
	if class, ok := ParseFlowClass(explicit); ok {
		return class
	}
	if class, ok := ParseFlowClass(fallback); ok {
		return class
	}
	switch protocol {
	case "udp":
		if isRealtimeUDPPort(port) {
			return FlowClassRealtime
		}
		if port == 53 || port == 123 {
			return FlowClassLatency
		}
	case "tcp":
		switch port {
		case 22, 3389, 5900:
			return FlowClassLatency
		case 20, 21, 80, 443, 3306, 5432:
			return FlowClassThroughput
		}
	}
	return normalizeFlowClass("", fallback)
}

func isRealtimeUDPPort(port uint16) bool {
	switch port {
	case 3478, 3479, 5060, 5061, 19302, 19303, 19304, 19305, 19306, 19307, 19308, 19309:
		return true
	}
	return port >= 20000 && port <= 20100
}

type flowEntry struct {
	key              conntrack.Key
	pathID           string
	class            FlowClass
	expiresAt        int64
	bytes            uint64
	packets          uint32
	migrations       uint16
	touched          bool
	heapIndex        int
	generation       uint64
	classifiedHeight uint64
}

type flowShard struct {
	mu      sync.Mutex
	entries map[conntrack.Key]*flowEntry
	expiry  flowExpiryHeap
}

type flowTable struct {
	shards         []flowShard
	now            func() time.Time
	capacity       int
	admitMu        sync.Mutex
	evictionQueue  []evictionQueueItem
	evictionHead   int
	evictionTail   int
	evictionCount  int
	nextGeneration uint64
	active         atomic.Int64
	evictions      atomic.Uint64
	migrations     atomic.Uint64
	bytes          atomic.Uint64
	packets        atomic.Uint64
}

type flowTableStats struct {
	Active     int
	Capacity   int
	Evictions  uint64
	Migrations uint64
	Bytes      uint64
	Packets    uint64
}

type evictionQueueItem struct {
	key        conntrack.Key
	generation uint64
}

func newFlowTable(capacity int) *flowTable {
	if capacity <= 0 {
		capacity = defaultFlowTableCapacity
	}
	shardCount := defaultFlowShardCount
	if capacity < shardCount {
		shardCount = capacity
	}
	table := &flowTable{
		shards: make([]flowShard, shardCount), now: time.Now, capacity: capacity,
		evictionQueue: make([]evictionQueueItem, capacity+1),
	}
	for index := range table.shards {
		table.shards[index].entries = make(map[conntrack.Key]*flowEntry)
	}
	return table
}

// canonicalFlowKey makes both directions of a transport flow choose the same
// path. Without this, a SYN and SYN-ACK could use unrelated overlay paths.
func canonicalFlowKey(key conntrack.Key) conntrack.Key {
	sourceDestination := key.Source.Compare(key.Destination)
	if sourceDestination < 0 || (sourceDestination == 0 && key.SourcePort <= key.DestinationPort) {
		return key
	}
	return key.Reverse()
}

func (table *flowTable) shardFor(key conntrack.Key) *flowShard {
	return &table.shards[flowShardIndex(key, uint32(len(table.shards)))]
}

func flowShardIndex(key conntrack.Key, shardCount uint32) uint32 {
	if shardCount <= 1 {
		return 0
	}
	return uint32(flowHash(key, "")) % shardCount
}

func (table *flowTable) get(key conntrack.Key) (flowEntry, bool) {
	normalized := canonicalFlowKey(key)
	shard := table.shardFor(normalized)
	shard.mu.Lock()
	defer shard.mu.Unlock()
	entry, exists := shard.entries[normalized]
	if !exists {
		return flowEntry{}, false
	}
	now := table.now()
	if now.UnixNano() >= entry.expiresAt {
		table.removeLocked(shard, normalized, entry)
		table.evictions.Add(1)
		return flowEntry{}, false
	}
	return *entry, true
}

func (table *flowTable) observe(key conntrack.Key, pathID string, class FlowClass, size int, migrated bool) flowEntry {
	return table.observeAt(key, pathID, class, size, migrated, 0)
}

func (table *flowTable) observeAt(key conntrack.Key, pathID string, class FlowClass, size int, migrated bool, classifiedHeight uint64) flowEntry {
	normalized := canonicalFlowKey(key)
	shard := table.shardFor(normalized)
	now := table.now()

	shard.mu.Lock()
	entry, exists := shard.entries[normalized]
	if exists {
		table.updateFlowEntryLocked(entry, &shard.expiry, normalized.Protocol, pathID, class, size, migrated, classifiedHeight, now)
		shard.mu.Unlock()
		return *entry
	}
	shard.mu.Unlock()

	// New-flow admission is globally bounded while updates remain shard-local.
	table.admitMu.Lock()
	if table.active.Load() >= int64(table.capacity) {
		table.evictOneForCapacityLocked()
	}
	shard.mu.Lock()
	entry, exists = shard.entries[normalized]
	if !exists {
		table.nextGeneration++
		entry = &flowEntry{key: normalized, heapIndex: -1, generation: table.nextGeneration}
		shard.entries[normalized] = entry
		heap.Push(&shard.expiry, entry)
		table.active.Add(1)
		table.pushEvictionLocked(normalized, entry.generation)
	}
	table.updateFlowEntryLocked(entry, &shard.expiry, normalized.Protocol, pathID, class, size, migrated, classifiedHeight, now)
	shard.mu.Unlock()
	table.admitMu.Unlock()
	return *entry
}

func (table *flowTable) updateFlowEntryLocked(entry *flowEntry, expiry *flowExpiryHeap, protocol uint8, pathID string, class FlowClass, size int, migrated bool, classifiedHeight uint64, now time.Time) {
	entry.pathID = pathID
	entry.class = class
	entry.classifiedHeight = classifiedHeight
	entry.expiresAt = now.Add(flowTimeoutFor(protocol)).UnixNano()
	entry.bytes += uint64(size)
	entry.packets++
	entry.touched = true
	if migrated {
		entry.migrations++
		table.migrations.Add(1)
	}
	if entry.heapIndex >= 0 {
		heap.Fix(expiry, entry.heapIndex)
	}
	table.bytes.Add(uint64(size))
	table.packets.Add(1)
}

func (table *flowTable) removeLocked(shard *flowShard, key conntrack.Key, entry *flowEntry) {
	delete(shard.entries, key)
	if entry.heapIndex >= 0 {
		heap.Remove(&shard.expiry, entry.heapIndex)
	}
	table.active.Add(-1)
}

func (table *flowTable) evictOneForCapacityLocked() {
	for table.evictionCount > 0 {
		item := table.popEvictionLocked()
		shard := table.shardFor(item.key)
		shard.mu.Lock()
		entry, exists := shard.entries[item.key]
		if !exists || entry.generation != item.generation {
			shard.mu.Unlock()
			continue
		}
		if entry.touched {
			entry.touched = false
			table.pushEvictionLocked(item.key, item.generation)
			shard.mu.Unlock()
			continue
		}
		table.removeLocked(shard, item.key, entry)
		table.evictions.Add(1)
		shard.mu.Unlock()
		return
	}
}

func (table *flowTable) pushEvictionLocked(key conntrack.Key, generation uint64) {
	if table.evictionCount == len(table.evictionQueue) {
		table.drainStaleEvictionsLocked()
	}
	table.offerEvictionLocked(key, generation)
}

func (table *flowTable) offerEvictionLocked(key conntrack.Key, generation uint64) {
	if table.evictionCount == len(table.evictionQueue) {
		return
	}
	table.evictionQueue[table.evictionTail] = evictionQueueItem{key: key, generation: generation}
	table.evictionTail = (table.evictionTail + 1) % len(table.evictionQueue)
	table.evictionCount++
}

func (table *flowTable) popEvictionLocked() evictionQueueItem {
	item := table.evictionQueue[table.evictionHead]
	table.evictionQueue[table.evictionHead] = evictionQueueItem{}
	table.evictionHead = (table.evictionHead + 1) % len(table.evictionQueue)
	table.evictionCount--
	return item
}

func (table *flowTable) drainStaleEvictionsLocked() {
	originalCount := table.evictionCount
	for scanned := 0; scanned < originalCount && table.evictionCount > 0; scanned++ {
		item := table.popEvictionLocked()
		shard := table.shardFor(item.key)
		shard.mu.Lock()
		entry, exists := shard.entries[item.key]
		if exists && entry.generation == item.generation {
			entry.touched = false
			shard.mu.Unlock()
			table.offerEvictionLocked(item.key, item.generation)
			continue
		}
		shard.mu.Unlock()
	}
}

func (table *flowTable) len() int {
	now := table.now()
	for index := range table.shards {
		shard := &table.shards[index]
		shard.mu.Lock()
		table.pruneShardLocked(shard, now)
		shard.mu.Unlock()
	}
	return int(table.active.Load())
}

func (table *flowTable) stats() flowTableStats {
	result := flowTableStats{Capacity: table.capacity}
	now := table.now()
	for index := range table.shards {
		shard := &table.shards[index]
		shard.mu.Lock()
		table.pruneShardLocked(shard, now)
		shard.mu.Unlock()
	}
	result.Active = int(table.active.Load())
	result.Evictions = table.evictions.Load()
	result.Migrations = table.migrations.Load()
	result.Bytes = table.bytes.Load()
	result.Packets = table.packets.Load()
	return result
}

func (table *flowTable) pruneShardLocked(shard *flowShard, now time.Time) {
	for len(shard.expiry) > 0 {
		entry := shard.expiry[0]
		if entry.heapIndex < 0 {
			heap.Pop(&shard.expiry)
			continue
		}
		if entry.expiresAt > now.UnixNano() {
			return
		}
		table.removeLocked(shard, entry.key, entry)
		table.evictions.Add(1)
	}
}

func flowTimeoutFor(protocol uint8) time.Duration {
	switch protocol {
	case packet.ProtocolTCP:
		return 5 * time.Minute
	case packet.ProtocolUDP:
		return 60 * time.Second
	case packet.ProtocolICMP:
		return 30 * time.Second
	default:
		return 60 * time.Second
	}
}

type flowExpiryHeap []*flowEntry

func (entries flowExpiryHeap) Len() int { return len(entries) }

func (entries flowExpiryHeap) Less(left, right int) bool {
	return entries[left].expiresAt < entries[right].expiresAt
}

func (entries flowExpiryHeap) Swap(left, right int) {
	entries[left], entries[right] = entries[right], entries[left]
	entries[left].heapIndex = left
	entries[right].heapIndex = right
}

func (entries *flowExpiryHeap) Push(value any) {
	entry := value.(*flowEntry)
	entry.heapIndex = len(*entries)
	*entries = append(*entries, entry)
}

func (entries *flowExpiryHeap) Pop() any {
	old := *entries
	last := len(old) - 1
	entry := old[last]
	old[last] = nil
	entry.heapIndex = -1
	*entries = old[:last]
	return entry
}

// flowHash is allocation-free and deterministic within a process. It is used
// both for shard placement and weighted rendezvous selection.
func flowHash(key conntrack.Key, pathID string) uint64 {
	const prime = 1099511628211
	hash := uint64(14695981039346656037)
	mix := func(value uint64) {
		hash ^= value
		hash *= prime
	}
	mix(uint64(key.Protocol))
	mix(uint64(key.SourcePort)<<32 | uint64(key.DestinationPort))
	mix(addressHash(key.Source))
	mix(addressHash(key.Destination))
	for index := 0; index < len(pathID); index++ {
		mix(uint64(pathID[index]))
	}
	return mix64(hash)
}

func addressHash(address comparableAddress) uint64 {
	if address.Is4() {
		value := address.As4()
		return uint64(value[0])<<56 | uint64(value[1])<<48 | uint64(value[2])<<40 | uint64(value[3])<<32
	}
	value := address.As16()
	var result uint64
	for index := 0; index < len(value); index += 8 {
		var part uint64
		for offset := 0; offset < 8; offset++ {
			part = part<<8 | uint64(value[index+offset])
		}
		result ^= part
	}
	if result == 0 {
		return 1
	}
	return result
}

func mix64(value uint64) uint64 {
	value += 0x9e3779b97f4a7c15
	value = (value ^ (value >> 30)) * 0xbf58476d1ce4e5b9
	value = (value ^ (value >> 27)) * 0x94d049bb133111eb
	return value ^ (value >> 31)
}

type comparableAddress interface {
	Is4() bool
	As4() [4]byte
	As16() [16]byte
}
