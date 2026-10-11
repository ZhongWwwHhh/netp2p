package path

import (
	"fmt"
	"runtime"
	"testing"
	"time"
)

func TestWeightedRendezvousPreservesWeights(t *testing.T) {
	weights := []PathWeight{{PathID: "a", Weight: 0.7}, {PathID: "b", Weight: 0.3}}
	counts := map[string]int{}
	const samples = 20000
	for index := 0; index < samples; index++ {
		selected, ok := WeightedRendezvous(weights, []byte(fmt.Sprintf("flow-%d", index)))
		if !ok {
			t.Fatal("selection failed")
		}
		counts[selected]++
	}
	if len(counts) != 2 {
		t.Fatalf("selected paths = %v", counts)
	}
	if delta := absFloat(float64(counts["a"])/samples - 0.7); delta > 0.03 {
		t.Fatalf("a share = %.4f, delta %.4f", float64(counts["a"])/samples, delta)
	}
	if delta := absFloat(float64(counts["b"])/samples - 0.3); delta > 0.03 {
		t.Fatalf("b share = %.4f, delta %.4f", float64(counts["b"])/samples, delta)
	}
}

func TestWeightedSelectionPinsCurrentFlowUntilHardFailure(t *testing.T) {
	direct := LinkProfile{PathID: "direct", Type: PathDirect, RTTMilliseconds: 10, BandwidthMbps: 100, Stability: 1}
	via := LinkProfile{PathID: "via", Type: PathViaManager, RTTMilliseconds: 20, BandwidthMbps: 100, Stability: 1}
	constraints := Constraints{FlowClass: FlowLatency}
	weights := []PathWeight{{PathID: "direct", Weight: 1}, {PathID: "via", Weight: 0.01}}

	decision := WeightedSelection([]LinkProfile{direct, via}, weights, constraints, []byte("tcp-flow"), "via", nil)
	if decision.Path.PathID != "via" {
		t.Fatalf("ordinary weight change migrated flow to %q", decision.Path.PathID)
	}
	decision = WeightedSelection([]LinkProfile{direct, via}, weights, constraints, []byte("tcp-flow"), "via", func(pathID string) bool {
		return pathID == "via"
	})
	if decision.Path.PathID != "direct" {
		t.Fatalf("hard failure did not fall back to direct, got %q", decision.Path.PathID)
	}
}

func TestRealtimeHardSLARejectsJitter(t *testing.T) {
	candidate := LinkProfile{PathID: "realtime", Type: PathViaManager, RTTMilliseconds: 20, JitterMilliseconds: 11, BandwidthMbps: 100, Stability: 1}
	if score := Score(candidate, Constraints{FlowClass: FlowRealtime, MaxJitterMilliseconds: 10}); score != 0 {
		t.Fatalf("realtime score = %f, want hard reject", score)
	}
}

func TestFlowTableIsBoundedAndRetainsDemand(t *testing.T) {
	table := NewFlowTable(10, 2, time.Minute)
	now := time.Now().UTC()
	for index := 0; index < 11; index++ {
		identity := FlowIdentity{Protocol: "tcp", Source: fmt.Sprintf("10.0.0.%d", index), Destination: "10.0.1.1", SourcePort: uint16(1000 + index), DestinationPort: 443}
		if _, ok := table.Record(identity, "domain", FlowThroughput, "path-a", 1, 1, now); !ok {
			t.Fatalf("record %d failed", index)
		}
	}
	if table.Len() > 10 {
		t.Fatalf("flow table grew to %d entries beyond cap 10", table.Len())
	}
	var total uint64
	for _, demand := range table.Demand() {
		total += demand.Bytes
	}
	if total != 11 {
		t.Fatalf("demand bytes = %d, want 11 after eviction", total)
	}
}

func TestFlowTableOneMillionEntriesMemoryBudget(t *testing.T) {
	if testing.Short() {
		t.Skip("short mode skips the one-million-entry memory budget")
	}
	runtime.GC()
	var before runtime.MemStats
	runtime.ReadMemStats(&before)
	table := NewFlowTable(1048576, 64, time.Minute)
	defer runtime.KeepAlive(table)
	now := time.Now().UTC()
	for index := 0; index < 1048576; index++ {
		identity := FlowIdentity{
			Protocol: "tcp", Source: fmt.Sprintf("10.%d.%d.%d", byte(index>>16), byte(index>>8), byte(index)), Destination: "10.0.1.1",
			SourcePort: uint16(index), DestinationPort: 443,
		}
		if _, ok := table.Record(identity, fmt.Sprintf("domain-%d", index%100), FlowThroughput, "path-a", 1200, 1, now); !ok {
			t.Fatalf("record %d failed", index)
		}
	}
	if table.Len() != 1048576 {
		t.Fatalf("entries = %d, want 1048576", table.Len())
	}
	runtime.GC()
	var after runtime.MemStats
	runtime.ReadMemStats(&after)
	used := int64(after.HeapAlloc) - int64(before.HeapAlloc)
	if used > 512<<20 {
		t.Fatalf("one million flow entries used %d bytes, budget %d", used, 512<<20)
	}
	t.Logf("one million flow entries used %d bytes", used)
}

func BenchmarkWeightedRendezvous(b *testing.B) {
	weights := []PathWeight{{PathID: "a", Weight: 0.7}, {PathID: "b", Weight: 0.3}}
	b.ResetTimer()
	for index := 0; index < b.N; index++ {
		if _, ok := WeightedRendezvous(weights, []byte{byte(index), byte(index >> 8), byte(index >> 16)}); !ok {
			b.Fatal("selection failed")
		}
	}
}

func BenchmarkFlowTableRecord(b *testing.B) {
	table := NewFlowTable(1048576, 64, time.Minute)
	now := time.Now().UTC()
	b.ResetTimer()
	for index := 0; index < b.N; index++ {
		identity := FlowIdentity{
			Protocol: "tcp", Source: "10.0.0.1", Destination: "10.0.1.1",
			SourcePort: uint16(index), DestinationPort: 443,
		}
		if _, ok := table.Record(identity, "domain", FlowThroughput, "path-a", 1200, 1, now); !ok {
			b.Fatal("record failed")
		}
	}
}

func absFloat(value float64) float64 {
	if value < 0 {
		return -value
	}
	return value
}
