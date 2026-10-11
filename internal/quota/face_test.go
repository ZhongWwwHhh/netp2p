package quota

import (
	"testing"
	"time"

	"github.com/netp2p/netp2p/internal/path"
)

func TestFaceBudgetReservesRealtimeShare(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	set, err := NewFaceBudgetSet([]FaceConfig{{
		FaceID: "manager-a", CapacityBytesPerSecond: 1000,
		ReserveFraction: 0.1, RealtimeShare: 0.5, QueueLow: 0.3, QueueHigh: 0.5,
	}})
	if err != nil {
		t.Fatal(err)
	}
	realtime := set.Admit("manager-a", path.FlowRealtime, 50, now)
	if !realtime.Allowed {
		t.Fatalf("realtime priority admission failed: %+v", realtime)
	}
	latency := set.Admit("manager-a", path.FlowLatency, 50, now)
	if latency.Allowed {
		t.Fatalf("bulk traffic exceeded its non-priority token share: %+v", latency)
	}
}

func TestFaceBudgetRejectsUnknownClass(t *testing.T) {
	set, err := NewFaceBudgetSet([]FaceConfig{{FaceID: "face", CapacityBytesPerSecond: 1000}})
	if err != nil {
		t.Fatal(err)
	}
	decision := set.Admit("face", path.FlowClass("unknown"), 1, time.Now())
	if decision.Allowed {
		t.Fatalf("unknown flow class admitted: %+v", decision)
	}
}

func TestQueuePressureReducesAdmissionRate(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	set, err := NewFaceBudgetSet([]FaceConfig{{
		FaceID: "manager-a", CapacityBytesPerSecond: 1000,
		ReserveFraction: 0.1, RealtimeShare: 0.2, QueueLow: 0.3, QueueHigh: 0.5,
	}})
	if err != nil {
		t.Fatal(err)
	}
	before, err := set.Feedback("manager-a")
	if err != nil {
		t.Fatal(err)
	}
	feedback, err := set.ObserveQueue("manager-a", 900, 1000, now)
	if err != nil {
		t.Fatal(err)
	}
	if !feedback.Congested || feedback.Backoff >= before.Backoff || feedback.RateBytesPerSecond >= before.RateBytesPerSecond {
		t.Fatalf("queue pressure did not reduce admission: before=%+v after=%+v", before, feedback)
	}
}

func BenchmarkFaceBudgetAdmit(b *testing.B) {
	set, err := NewFaceBudgetSet([]FaceConfig{{FaceID: "manager-a", CapacityBytesPerSecond: 1 << 30}})
	if err != nil {
		b.Fatal(err)
	}
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	b.ResetTimer()
	for index := 0; index < b.N; index++ {
		set.Admit("manager-a", path.FlowLatency, 1200, now.Add(time.Duration(index)*time.Microsecond))
	}
}
