package manager

import (
	"testing"

	"github.com/netp2p/netp2p/internal/model"
)

func TestAggregateQuotaHistoryDaily(t *testing.T) {
	usage := []model.BudgetUsage{
		{BudgetID: "b1", DailyBytes: 10, MonthlyBytes: 10, PeriodDay: "2026-10-01", PeriodMonth: "2026-10"},
		{BudgetID: "b1", DailyBytes: 40, MonthlyBytes: 40, PeriodDay: "2026-10-01", PeriodMonth: "2026-10"},
		{BudgetID: "b1", DailyBytes: 5, MonthlyBytes: 45, PeriodDay: "2026-10-02", PeriodMonth: "2026-10"},
		{BudgetID: "b2", DailyBytes: 7, MonthlyBytes: 7, PeriodDay: "2026-10-01", PeriodMonth: "2026-10"},
	}
	entries := aggregateQuotaHistory(usage, "daily")
	if len(entries) != 3 {
		t.Fatalf("entries = %+v, want 3", entries)
	}
	// Sorted by period then budget; the latest settlement in a period wins.
	if entries[0] != (QuotaHistoryEntry{BudgetID: "b1", Period: "2026-10-01", Bytes: 40}) {
		t.Fatalf("first entry = %+v", entries[0])
	}
	if entries[1] != (QuotaHistoryEntry{BudgetID: "b2", Period: "2026-10-01", Bytes: 7}) {
		t.Fatalf("second entry = %+v", entries[1])
	}
	if entries[2] != (QuotaHistoryEntry{BudgetID: "b1", Period: "2026-10-02", Bytes: 5}) {
		t.Fatalf("third entry = %+v", entries[2])
	}

	monthly := aggregateQuotaHistory(usage, "monthly")
	if len(monthly) != 2 || monthly[0].Period != "2026-10" || monthly[0].Bytes != 45 {
		t.Fatalf("monthly = %+v", monthly)
	}
}
