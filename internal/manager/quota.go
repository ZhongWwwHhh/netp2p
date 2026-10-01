package manager

import (
	"context"
	"log"
	"sort"
	"time"

	"github.com/libp2p/go-libp2p/core/network"
	"github.com/netp2p/netp2p/internal/bft"
	"github.com/netp2p/netp2p/internal/model"
	"github.com/netp2p/netp2p/internal/p2p"
	"github.com/netp2p/netp2p/internal/version"
	"github.com/netp2p/netp2p/internal/wire"
	"github.com/netp2p/netp2p/internal/wire/pb"
	"google.golang.org/protobuf/proto"
)

// quotaSettlementInterval is the hard floor between two usage-settlement
// transitions. Aggregating client reports for this long prevents per-packet
// accounting from churning consensus.
const quotaSettlementInterval = 60 * time.Second

// handleQuotaReport aggregates a client's usage increments. Reports are
// non-certified input: the manager only turns them into a transition, which the
// committee still has to certify.
func (manager *Manager) handleQuotaReport(stream network.Stream) {
	defer stream.Close()
	envelope, err := p2p.DecodeEnvelope(stream)
	if err != nil {
		return
	}
	var message pb.QuotaReport
	if err := proto.Unmarshal(envelope.Payload, &message); err != nil {
		return
	}
	report := wire.QuotaReportFromProto(&message)
	if report.PeerID != stream.Conn().RemotePeer().String() {
		return
	}
	if report.ProtocolVersion != version.ProtocolVersion {
		return
	}
	manager.mu.Lock()
	if manager.quotaPending == nil {
		manager.quotaPending = make(map[string]uint64)
	}
	for _, increment := range report.Increments {
		if increment.BudgetID == "" || increment.Bytes == 0 {
			continue
		}
		manager.quotaPending[increment.BudgetID] += increment.Bytes
	}
	manager.mu.Unlock()
}

// RunQuotaSettlement periodically settles aggregated usage into certified state.
func (manager *Manager) RunQuotaSettlement(ctx context.Context) {
	ticker := time.NewTicker(quotaSettlementInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			manager.SettleQuota(time.Now().UTC())
		}
	}
}

// SettleQuota submits at most one settlement per configured interval. It is
// exported so tests can drive settlement deterministically.
func (manager *Manager) SettleQuota(now time.Time) {
	manager.mu.Lock()
	if !manager.quotaSettledAt.IsZero() && now.Sub(manager.quotaSettledAt) < quotaSettlementInterval {
		manager.mu.Unlock()
		return
	}
	pending := manager.quotaPending
	if len(pending) == 0 {
		manager.mu.Unlock()
		return
	}
	manager.quotaPending = make(map[string]uint64)
	manager.quotaSettledAt = now
	manager.mu.Unlock()

	state := manager.engine.CurrentState()
	ids := make([]string, 0, len(pending))
	for id := range pending {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		budget, ok := findBudget(state, id)
		if !ok {
			continue
		}
		daily := budget.UsedDailyBytes
		monthly := budget.UsedMonthlyBytes
		if !sameUTCDay(budget.UpdatedAt, now) {
			daily = 0
		}
		if !sameUTCMonth(budget.UpdatedAt, now) {
			monthly = 0
		}
		daily += pending[id]
		monthly += pending[id]
		transition := model.StateTransition{
			Type: bft.TransitionUpdateBudgetUse,
			BudgetUsage: &model.BudgetUsage{
				BudgetID:     id,
				DailyBytes:   daily,
				MonthlyBytes: monthly,
				PeriodDay:    now.Format("2006-01-02"),
				PeriodMonth:  now.Format("2006-01"),
			},
		}
		if _, err := manager.SubmitAs(transition, systemActor("quota")); err != nil {
			log.Printf("quota settlement for %s failed: %v", id, err)
		}
	}
}

// SettleQuotaNow bypasses the interval, for the admin console and tests.
func (manager *Manager) SettleQuotaNow(now time.Time) {
	manager.mu.Lock()
	manager.quotaSettledAt = time.Time{}
	manager.mu.Unlock()
	manager.SettleQuota(now)
}

// QuotaUsage returns the certified budgets with the locally pending increments
// folded in, so the console can show an up-to-date picture before settlement.
func (manager *Manager) QuotaUsage() []model.TrafficBudget {
	state := manager.engine.CurrentState()
	manager.mu.RLock()
	pending := manager.quotaPending
	manager.mu.RUnlock()
	result := make([]model.TrafficBudget, 0, len(state.Budgets))
	for _, budget := range state.Budgets {
		budget.UsedDailyBytes += pending[budget.ID]
		budget.UsedMonthlyBytes += pending[budget.ID]
		result = append(result, budget)
	}
	return result
}

func findBudget(state model.NetworkState, id string) (model.TrafficBudget, bool) {
	for _, budget := range state.Budgets {
		if budget.ID == id {
			return budget, true
		}
	}
	return model.TrafficBudget{}, false
}

func sameUTCDay(a, b time.Time) bool {
	ay, am, ad := a.UTC().Date()
	by, bm, bd := b.UTC().Date()
	return ay == by && am == bm && ad == bd
}

func sameUTCMonth(a, b time.Time) bool {
	ay, am, _ := a.UTC().Date()
	by, bm, _ := b.UTC().Date()
	return ay == by && am == bm
}

// QuotaHistoryEntry is one budget's usage in one period, rebuilt from the
// decision log. Usage settlements carry absolute counters, so the latest
// settlement in a period wins.
type QuotaHistoryEntry struct {
	BudgetID string `json:"budgetId"`
	Period   string `json:"period"`
	Bytes    uint64 `json:"bytes"`
}

// QuotaHistory rebuilds per-period usage from committed update_budget_usage
// transitions. period is "daily" or "monthly".
func (manager *Manager) QuotaHistory(period string) []QuotaHistoryEntry {
	return aggregateQuotaHistory(manager.engine.BudgetUsageHistory(), period)
}

// aggregateQuotaHistory folds absolute usage settlements into one entry per
// (period, budget), keeping the latest value seen in the decision log.
func aggregateQuotaHistory(usage []model.BudgetUsage, period string) []QuotaHistoryEntry {
	monthly := period == "monthly"
	latest := make(map[string]map[string]uint64)
	for _, item := range usage {
		key := item.PeriodDay
		bytes := item.DailyBytes
		if monthly {
			key = item.PeriodMonth
			bytes = item.MonthlyBytes
		}
		if key == "" {
			continue
		}
		if latest[key] == nil {
			latest[key] = make(map[string]uint64)
		}
		latest[key][item.BudgetID] = bytes
	}
	keys := make([]string, 0, len(latest))
	for key := range latest {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	result := make([]QuotaHistoryEntry, 0)
	for _, key := range keys {
		budgetIDs := make([]string, 0, len(latest[key]))
		for budgetID := range latest[key] {
			budgetIDs = append(budgetIDs, budgetID)
		}
		sort.Strings(budgetIDs)
		for _, budgetID := range budgetIDs {
			result = append(result, QuotaHistoryEntry{BudgetID: budgetID, Period: key, Bytes: latest[key][budgetID]})
		}
	}
	return result
}
