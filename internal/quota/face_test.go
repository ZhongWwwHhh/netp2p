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
	realtime := set.Admit("manager-a", path.FlowRealtime, 40, now)
	if !realtime.Allowed {
		t.Fatalf("realtime priority admission failed: %+v", realtime)
	}
	latency := set.Admit("manager-a", path.FlowLatency, 40, now)
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

func TestFaceBudgetDelayedRejectionsDoNotConsumeTokens(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	set, err := NewFaceBudgetSet([]FaceConfig{{
		FaceID: "manager-a", CapacityBytesPerSecond: 5000,
		ReserveFraction: 0.1, RealtimeShare: 0.2,
	}})
	if err != nil {
		t.Fatal(err)
	}

	if first := set.Admit("manager-a", path.FlowLatency, 80, now); !first.Allowed {
		t.Fatalf("initial burst frame was not admitted: %+v", first)
	}
	for attempt := 0; attempt < 10; attempt++ {
		decision := set.Admit("manager-a", path.FlowLatency, 80, now)
		if decision.Allowed || decision.Delay <= 0 {
			t.Fatalf("delayed frame must be rejected without immediate admission: %+v", decision)
		}
	}
	// The latency class has a 90-byte burst and a 900-byte/s rate. After the
	// first admitted frame, 100ms of refill covers another 80-byte frame only
	// if rejected frames did not drive the bucket negative.
	recovered := set.Admit("manager-a", path.FlowLatency, 80, now.Add(100*time.Millisecond))
	if !recovered.Allowed || recovered.Delay != 0 {
		t.Fatalf("rejected frames consumed tokens: %+v", recovered)
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
