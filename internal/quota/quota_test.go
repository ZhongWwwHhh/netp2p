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
