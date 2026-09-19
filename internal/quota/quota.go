// Package quota tracks aggregate byte usage and runtime enforcement actions.
package quota

import (
	"time"

	"github.com/netp2p/netp2p/internal/model"
)

type Action string

const (
	ActionBlock      Action = "block"
	ActionThrottle   Action = "throttle"
	ActionDegrade    Action = "degrade"
	ActionSwitchPath Action = "switch_path"
	ActionAllow      Action = "allow"
)

type Decision struct {
	Allowed    bool      `json:"allowed"`
	Action     Action    `json:"action"`
	Remaining  uint64    `json:"remaining"`
	LimitReset time.Time `json:"limitReset"`
}

// Tracker is a local enforcement cache. It does not replace committee state.
type Tracker struct {
	Budgets map[string]model.TrafficBudget
	Now     func() time.Time
}

func NewTracker(budgets []model.TrafficBudget) *Tracker {
	tracker := &Tracker{Budgets: make(map[string]model.TrafficBudget), Now: time.Now}
	for _, budget := range budgets {
		tracker.Budgets[budget.ID] = budget
	}
	return tracker
}

func dailyExpiry(now time.Time) time.Time {
	next := now.AddDate(0, 0, 1)
	return time.Date(next.Year(), next.Month(), next.Day(), 0, 0, 0, 0, now.Location())
}

func monthlyExpiry(now time.Time) time.Time {
	next := now.AddDate(0, 1, 0)
	return time.Date(next.Year(), next.Month(), 1, 0, 0, 0, 0, now.Location())
}

// Admit checks and reserves bytes. Failed admission does not mutate usage.
func (tracker *Tracker) Admit(budgetID string, bytes uint64) Decision {
	budget, ok := tracker.Budgets[budgetID]
	if !ok {
		return Decision{Allowed: true, Action: ActionAllow}
	}
	now := tracker.Now()
	remaining := budget.DailyBytes - budget.UsedDailyBytes
	reset := dailyExpiry(now)
	if budget.MonthlyBytes > 0 && budget.MonthlyBytes-budget.UsedMonthlyBytes < remaining {
		remaining = budget.MonthlyBytes - budget.UsedMonthlyBytes
		reset = monthlyExpiry(now)
	}
	if remaining < bytes {
		action := ActionThrottle
		if budget.OnExhausted != "" {
			action = Action(budget.OnExhausted)
		}
		if action == ActionBlock {
			return Decision{Allowed: false, Action: action, Remaining: max64(0, remaining), LimitReset: reset}
		}
		return Decision{Allowed: false, Action: action, Remaining: max64(0, remaining), LimitReset: reset}
	}
	budget.UsedDailyBytes += bytes
	budget.UsedMonthlyBytes += bytes
	budget.UpdatedAt = now
	tracker.Budgets[budgetID] = budget
	return Decision{Allowed: true, Action: ActionAllow, Remaining: remaining - bytes, LimitReset: reset}
}

func max64(a, b uint64) uint64 {
	if a > b {
		return a
	}
	return b
}
