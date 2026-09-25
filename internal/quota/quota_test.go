package quota

import (
	"testing"
	"time"

	"github.com/netp2p/netp2p/internal/model"
)

func TestAdmitDailyBudget(t *testing.T) {
	now := time.Date(2026, 9, 19, 10, 0, 0, 0, time.UTC)
	tracker := NewTracker([]model.TrafficBudget{{ID: "b", DailyBytes: 100, OnExhausted: "block"}})
	tracker.Now = func() time.Time { return now }
	if decision := tracker.Admit("b", 60); !decision.Allowed {
		t.Fatalf("first admission rejected: %+v", decision)
	}
	decision := tracker.Admit("b", 60)
	if decision.Allowed || decision.Action != ActionBlock || decision.Remaining != 40 {
		t.Fatalf("unexpected over-budget decision: %+v", decision)
	}
	if decision.LimitReset != time.Date(2026, 9, 20, 0, 0, 0, 0, time.UTC) {
		t.Fatalf("unexpected reset time: %s", decision.LimitReset)
	}
}

func TestResolvePriorityRouteThenGroupThenPeer(t *testing.T) {
	enforcer := NewEnforcer([]model.TrafficBudget{
		{ID: "peer-budget", SubjectType: "peer", SubjectID: "peer-a", DailyBytes: 10},
		{ID: "group-budget", SubjectType: "group", SubjectID: "clients", DailyBytes: 20},
		{ID: "route-budget", SubjectType: "route", SubjectID: "route-1", DailyBytes: 30},
	})
	budget, ok := enforcer.Resolve("peer-a", []string{"clients"}, "route-1")
	if !ok || budget.ID != "route-budget" {
		t.Fatalf("route budget should win: %+v", budget)
	}
	budget, ok = enforcer.Resolve("peer-a", []string{"clients"}, "")
	if !ok || budget.ID != "group-budget" {
		t.Fatalf("group budget should win: %+v", budget)
	}
	budget, ok = enforcer.Resolve("peer-a", nil, "")
	if !ok || budget.ID != "peer-budget" {
		t.Fatalf("peer budget should be the fallback: %+v", budget)
	}
	if _, ok := enforcer.Resolve("peer-z", nil, ""); ok {
		t.Fatal("unmatched peer should have no budget")
	}
}

func TestEnforcerBlocksAtCap(t *testing.T) {
	now := time.Date(2026, 9, 25, 10, 0, 0, 0, time.UTC)
	enforcer := NewEnforcer([]model.TrafficBudget{{
		ID: "b", SubjectType: "peer", SubjectID: "peer-a", DailyBytes: 100, OnExhausted: "block",
	}})
	enforcer.now = func() time.Time { return now }
	if decision := enforcer.Check("peer-a", nil, "", 60); !decision.Allowed {
		t.Fatalf("first check rejected: %+v", decision)
	}
	decision := enforcer.Check("peer-a", nil, "", 60)
	if decision.Allowed || decision.Action != ActionBlock {
		t.Fatalf("over-cap check accepted: %+v", decision)
	}
	if decision.BudgetID != "b" {
		t.Fatalf("unexpected budget id: %+v", decision)
	}
}

func TestEnforcerThrottleDelaysWithinBounds(t *testing.T) {
	now := time.Date(2026, 9, 25, 10, 0, 0, 0, time.UTC)
	enforcer := NewEnforcer([]model.TrafficBudget{{
		ID: "b", SubjectType: "peer", SubjectID: "peer-a",
		DailyBytes: 1 << 30, MonthlyBytes: 1 << 30,
		PeakBPS: 1000, PeakBurstBytes: 1000, OnExhausted: "throttle",
	}})
	current := now
	enforcer.now = func() time.Time { return current }

	decision := enforcer.Check("peer-a", nil, "", 1000)
	if !decision.Allowed || decision.Delay != 0 {
		t.Fatalf("first burst should be immediate: %+v", decision)
	}
	// The bucket is empty; a 500 byte packet needs half a second, which exceeds
	// the 250ms cap and must be dropped rather than queued.
	decision = enforcer.Check("peer-a", nil, "", 500)
	if decision.Allowed {
		t.Fatalf("excess burst should not be admitted immediately: %+v", decision)
	}
	if decision.Delay <= enforcer.MaxThrottleDelay {
		t.Fatalf("expected a delay beyond the throttle cap, got %s", decision.Delay)
	}

	// After a short sleep the bucket refills enough for a small packet.
	current = now.Add(100 * time.Millisecond)
	decision = enforcer.Check("peer-a", nil, "", 50)
	if !decision.Allowed {
		t.Fatalf("refilled bucket should admit: %+v", decision)
	}
}

func TestDrainDeltasReportsUsage(t *testing.T) {
	now := time.Date(2026, 9, 25, 10, 0, 0, 0, time.UTC)
	enforcer := NewEnforcer([]model.TrafficBudget{{
		ID: "b", SubjectType: "peer", SubjectID: "peer-a", DailyBytes: 1000, MonthlyBytes: 1000,
	}})
	enforcer.now = func() time.Time { return now }
	enforcer.Check("peer-a", nil, "", 100)
	enforcer.Check("peer-a", nil, "", 200)
	deltas := enforcer.DrainDeltas()
	if deltas["b"] != 300 {
		t.Fatalf("unexpected delta: %v", deltas)
	}
	if len(enforcer.DrainDeltas()) != 0 {
		t.Fatal("deltas should be cleared after draining")
	}
}

func TestThrottleBucket(t *testing.T) {
	now := time.Date(2026, 9, 25, 10, 0, 0, 0, time.UTC)
	bucket := NewTokenBucket(1000, 1000, now)
	if allowed, _ := bucket.Allow(1000, now, time.Second); !allowed {
		t.Fatal("initial burst should be allowed")
	}
	if allowed, delay := bucket.Allow(1000, now, time.Second); !allowed || delay != time.Second {
		t.Fatalf("expected a refill delay: allowed=%v delay=%s", allowed, delay)
	}
}
