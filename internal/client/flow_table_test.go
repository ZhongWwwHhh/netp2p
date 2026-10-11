package client

import (
	"net/netip"
	"runtime"
	"testing"
	"time"

	"github.com/netp2p/netp2p/internal/conntrack"
)

func TestFlowTableUsesOneCanonicalIdentityForBothDirections(t *testing.T) {
	table := newFlowTable(16)
	key := conntrack.Key{
		Protocol: 6, Source: netip.MustParseAddr("198.51.100.1"),
		Destination: netip.MustParseAddr("198.51.100.2"), SourcePort: 51000, DestinationPort: 443,
	}
	table.observe(key, "path-a", FlowClassThroughput, 100, false)

	forward, ok := table.get(key)
	if !ok || forward.pathID != "path-a" {
		t.Fatalf("forward lookup = %+v ok=%v", forward, ok)
	}
	reverse, ok := table.get(key.Reverse())
	if !ok || reverse.pathID != "path-a" {
		t.Fatalf("reverse lookup = %+v ok=%v", reverse, ok)
	}
	if table.len() != 1 {
		t.Fatalf("flow count = %d, want 1", table.len())
	}
}

func TestFlowHashSeparatesPathFamilies(t *testing.T) {
	counts := map[string]int{}
	for index := 0; index < 10000; index++ {
		key := testFlowKey(index)
		if flowHash(key, "via-a") > flowHash(key, "via-b") {
			counts["via-a"]++
		} else {
			counts["via-b"]++
		}
	}
	if counts["via-a"] < 4300 || counts["via-a"] > 5700 {
		t.Fatalf("path-family hash distribution = %v", counts)
	}
}

func TestFlowTableRefreshedFlowSurvivesCapacityPressure(t *testing.T) {
	table := newFlowTable(32)
	table.now = func() time.Time { return time.Unix(0, 0) }
	key := testFlowKey(0)
	table.observe(key, "path-a", FlowClassLatency, 10, false)

	// Refresh the first flow after the initial population so its expiry is
	// later than every newly created flow.
	for index := 1; index < 128; index++ {
		if index >= 64 {
			table.now = func() time.Time { return time.Unix(0, int64(time.Second)) }
			table.observe(key, "path-a", FlowClassLatency, 10, false)
			table.now = func() time.Time { return time.Unix(0, 0) }
		}
		table.observe(testFlowKey(index), "path-b", FlowClassLatency, 10, false)
	}
	if got := table.len(); got > 32 {
		t.Fatalf("flow count = %d, want <= 32", got)
	}
	if _, ok := table.get(key); !ok {
		t.Fatal("refreshed flow was evicted by capacity pressure")
	}
	if table.stats().Evictions == 0 {
		t.Fatal("capacity pressure did not evict any stale flow")
	}
}

func TestFlowTableHoldsOneMillionActiveFlows(t *testing.T) {
	if testing.Short() {
		t.Skip("one-million-flow capacity test is skipped in short mode")
	}
	var before runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)

	table := newFlowTable(defaultFlowTableCapacity)
	started := time.Now()
	for index := 0; index < defaultFlowTableCapacity; index++ {
		table.observe(testFlowKey(index), "path-a", FlowClassThroughput, 1400, false)
	}
	stats := table.stats()
	if stats.Active != defaultFlowTableCapacity {
		t.Fatalf("active flows = %d, want %d", stats.Active, defaultFlowTableCapacity)
	}
	if stats.Capacity != defaultFlowTableCapacity {
		t.Fatalf("capacity = %d, want %d", stats.Capacity, defaultFlowTableCapacity)
	}
	mapped := 0
	for index := range table.shards {
		mapped += len(table.shards[index].entries)
	}
	if mapped != defaultFlowTableCapacity {
		t.Fatalf("mapped flow entries = %d, want %d", mapped, defaultFlowTableCapacity)
	}
	if stats.Packets != defaultFlowTableCapacity || stats.Bytes != defaultFlowTableCapacity*1400 {
		t.Fatalf("packet/byte counters = %d/%d", stats.Packets, stats.Bytes)
	}

	runtime.GC()
	var after runtime.MemStats
	runtime.ReadMemStats(&after)
	runtime.KeepAlive(table)
	used := int64(after.HeapAlloc) - int64(before.HeapAlloc)
	if used < 0 {
		used = int64(after.HeapAlloc)
	}
	if used > 512<<20 {
		t.Fatalf("flow table heap delta = %d bytes, want <= %d", used, 512<<20)
	}
	t.Logf("1,000,000 flows: %d bytes, %s", used, time.Since(started).Round(time.Millisecond))
}

func testFlowKey(index int) conntrack.Key {
	source := netip.AddrFrom4([4]byte{198, 18, byte(index >> 16), 1})
	destination := netip.MustParseAddr("198.19.0.1")
	return conntrack.Key{
		Protocol: 6, Source: source, Destination: destination,
		SourcePort: uint16(index & 0xffff), DestinationPort: 443,
	}
}
