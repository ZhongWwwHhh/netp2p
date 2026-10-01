package bft

import (
	"testing"

	"github.com/netp2p/netp2p/internal/model"
)

// TestBudgetUsageHistory keeps the decision log as the source of truth for
// usage history: every settlement is retained in commit order.
func TestBudgetUsageHistory(t *testing.T) {
	committee, keys := testCommittee()
	state := testState()
	state.Budgets = []model.TrafficBudget{{ID: "b1", DailyBytes: 1000, MonthlyBytes: 10000}}
	engines := make([]*Engine, CommitteeSize)
	for index, key := range keys {
		engine, err := NewEngine(state, committee, committee[index].ID, key)
		if err != nil {
			t.Fatal(err)
		}
		engines[index] = engine
	}
	advance(t, keys, engines, model.StateTransition{
		Type:        TransitionUpdateBudgetUse,
		BudgetUsage: &model.BudgetUsage{BudgetID: "b1", DailyBytes: 10, MonthlyBytes: 10, PeriodDay: "2026-10-01", PeriodMonth: "2026-10"},
	})
	advance(t, keys, engines, model.StateTransition{
		Type:        TransitionUpdateBudgetUse,
		BudgetUsage: &model.BudgetUsage{BudgetID: "b1", DailyBytes: 25, MonthlyBytes: 35, PeriodDay: "2026-10-01", PeriodMonth: "2026-10"},
	})
	history := engines[0].BudgetUsageHistory()
	if len(history) != 2 {
		t.Fatalf("history = %+v, want 2 settlements", history)
	}
	if history[0].DailyBytes != 10 || history[1].DailyBytes != 25 {
		t.Fatalf("history out of order: %+v", history)
	}
}
