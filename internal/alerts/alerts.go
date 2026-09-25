// Package alerts evaluates local operational rules on a manager and reports
// state transitions to one or more sinks. Alerts are manager-local and never
// enter certified state: two managers may disagree about a transient condition,
// and that disagreement must not become consensus.
package alerts

import (
	"context"
	"fmt"
	"sort"
	"sync"
	"time"

	"github.com/netp2p/netp2p/internal/model"
)

// Severity ranks how urgently an operator should react.
type Severity string

const (
	SeverityInfo     Severity = "info"
	SeverityWarning  Severity = "warning"
	SeverityCritical Severity = "critical"
)

// Stable rule identifiers. They are part of the alert identity and the wire
// payload, so they must not change once shipped.
const (
	RuleQuorumDegraded = "quorum_degraded"
	RuleForwardDrops   = "forward_drops"
	RuleQuotaExceeded  = "quota_exceeded"
	RuleProbeFailed    = "probe_failed"
)

// Alert is one active condition.
type Alert struct {
	ID       string    `json:"id"`
	Rule     string    `json:"rule"`
	Severity Severity  `json:"severity"`
	Summary  string    `json:"summary"`
	FiredAt  time.Time `json:"firedAt"`
}

// Event is a state change: firing when an alert becomes active, resolved when
// it clears. The manager and height are attached for context.
type Event struct {
	Status  string    `json:"status"`
	Alert   Alert     `json:"alert"`
	Manager string    `json:"manager,omitempty"`
	Height  uint64    `json:"height,omitempty"`
	Time    time.Time `json:"time"`
}

// Sink delivers alert events. Implementations must be safe for concurrent use
// and must not block evaluation indefinitely.
type Sink interface {
	Send(ctx context.Context, event Event) error
}

// Input is the manager observation an evaluation pass reasons about. It is
// deliberately a flat value so rules stay deterministic and testable.
type Input struct {
	Manager           string
	Height            uint64
	QuorumSize        int
	CommitteeSize     int
	DisconnectedPeers []string
	PeerCount         int
	LinkSegments      int
	MinLinkConfidence float64
	Forwarded         uint64
	Dropped           uint64
	Budgets           []model.TrafficBudget
	Now               time.Time
}

// Thresholds are the tunable rule parameters. Zero values mean "use the
// default", so a partially-filled config is still usable.
type Thresholds struct {
	// DropCount is the forwarded-frame drop delta that fires forward_drops.
	DropCount uint64
	// DropRatePercent fires forward_drops when the drop delta is at least this
	// share of the forwarded delta. It only applies once traffic is observed.
	DropRatePercent float64
}

// Config configures an Alerter.
type Config struct {
	Interval   time.Duration
	Thresholds Thresholds
}

func (config Config) withDefaults() Config {
	if config.Interval <= 0 {
		config.Interval = 15 * time.Second
	}
	if config.Thresholds.DropCount == 0 {
		config.Thresholds.DropCount = 100
	}
	if config.Thresholds.DropRatePercent == 0 {
		config.Thresholds.DropRatePercent = 5
	}
	return config
}

// Alerter tracks which alerts are active and delivers only transitions. It is
// safe for concurrent use.
type Alerter struct {
	config Config
	sinks  []Sink
	now    func() time.Time

	mu     sync.Mutex
	active map[string]Alert
	// lastDrop tracks the previous drop/forward counters so rates are computed
	// over an interval rather than over process lifetime.
	lastDropped   uint64
	lastForwarded uint64
	lastSample    time.Time
}

// New builds an Alerter. With no sinks it still tracks state, which keeps
// callers simple when alerting is disabled.
func New(config Config, sinks ...Sink) *Alerter {
	return &Alerter{
		config: config.withDefaults(),
		sinks:  sinks,
		now:    time.Now,
		active: make(map[string]Alert),
	}
}

// Interval is the recommended evaluation period.
func (alerter *Alerter) Interval() time.Duration {
	return alerter.config.Interval
}

// Evaluate reconciles the desired alert set against the active set and delivers
// the difference. It returns the events it delivered, which makes assertions
// easy in tests.
func (alerter *Alerter) Evaluate(ctx context.Context, input Input) []Event {
	if input.Now.IsZero() {
		input.Now = alerter.now()
	}
	desired := alerter.evaluateRules(input)

	alerter.mu.Lock()
	events := make([]Event, 0)
	for id, alert := range desired {
		if _, exists := alerter.active[id]; exists {
			continue
		}
		alert.FiredAt = input.Now
		alerter.active[id] = alert
		events = append(events, Event{
			Status: "firing", Alert: alert, Manager: input.Manager, Height: input.Height, Time: input.Now,
		})
	}
	for id, alert := range alerter.active {
		if _, exists := desired[id]; exists {
			continue
		}
		delete(alerter.active, id)
		events = append(events, Event{
			Status: "resolved", Alert: alert, Manager: input.Manager, Height: input.Height, Time: input.Now,
		})
	}
	// Update the drop baseline after comparing, so the next pass measures the
	// delta since this one.
	alerter.lastDropped = input.Dropped
	alerter.lastForwarded = input.Forwarded
	alerter.lastSample = input.Now
	alerter.mu.Unlock()

	sort.Slice(events, func(i, j int) bool { return events[i].Alert.ID < events[j].Alert.ID })
	alerter.deliver(ctx, events)
	return events
}

// Active returns the current alert set, sorted by id.
func (alerter *Alerter) Active() []Alert {
	alerter.mu.Lock()
	defer alerter.mu.Unlock()
	result := make([]Alert, 0, len(alerter.active))
	for _, alert := range alerter.active {
		result = append(result, alert)
	}
	sort.Slice(result, func(i, j int) bool { return result[i].ID < result[j].ID })
	return result
}

// evaluateRules produces the desired alert set for the input. It does not
// mutate state.
func (alerter *Alerter) evaluateRules(input Input) map[string]Alert {
	desired := make(map[string]Alert)
	if len(input.DisconnectedPeers) > 0 {
		desired[RuleQuorumDegraded] = Alert{
			ID: RuleQuorumDegraded, Rule: RuleQuorumDegraded, Severity: SeverityWarning,
			Summary: fmt.Sprintf("%d committee member(s) not connected: %v", len(input.DisconnectedPeers), input.DisconnectedPeers),
		}
	}
	for _, alert := range alerter.forwardDropAlerts(input) {
		desired[alert.ID] = alert
	}
	for _, budget := range input.Budgets {
		if alert, ok := quotaAlert(budget); ok {
			desired[alert.ID] = alert
		}
	}
	if alert, ok := probeAlert(input); ok {
		desired[alert.ID] = alert
	}
	return desired
}

// forwardDropAlerts compares the current drop counters against the previous
// sample. The first pass only establishes a baseline.
func (alerter *Alerter) forwardDropAlerts(input Input) []Alert {
	alerter.mu.Lock()
	previousDropped := alerter.lastDropped
	previousForwarded := alerter.lastForwarded
	hasBaseline := !alerter.lastSample.IsZero()
	alerter.mu.Unlock()
	if !hasBaseline {
		return nil
	}
	dropDelta := input.Dropped - previousDropped
	forwardDelta := input.Forwarded - previousForwarded
	if dropDelta < alerter.config.Thresholds.DropCount {
		rate := 0.0
		if total := dropDelta + forwardDelta; total > 0 {
			rate = float64(dropDelta) / float64(total) * 100
		}
		if rate < alerter.config.Thresholds.DropRatePercent {
			return nil
		}
	}
	return []Alert{{
		ID: RuleForwardDrops, Rule: RuleForwardDrops, Severity: SeverityWarning,
		Summary: fmt.Sprintf("%d forwarded frame(s) dropped since the last evaluation", dropDelta),
	}}
}

// quotaAlert fires when a budget with a limit has reached it.
func quotaAlert(budget model.TrafficBudget) (Alert, bool) {
	exhausted := (budget.DailyBytes > 0 && budget.UsedDailyBytes >= budget.DailyBytes) ||
		(budget.MonthlyBytes > 0 && budget.UsedMonthlyBytes >= budget.MonthlyBytes)
	if !exhausted {
		return Alert{}, false
	}
	summary := fmt.Sprintf("budget %s reached its limit", budget.ID)
	if budget.OnExhausted != "" {
		summary = fmt.Sprintf("%s (action: %s)", summary, budget.OnExhausted)
	}
	return Alert{ID: RuleQuotaExceeded + ":" + budget.ID, Rule: RuleQuotaExceeded, Severity: SeverityWarning, Summary: summary}, true
}

// probeAlert fires when peers exist but no usable link measurement does.
func probeAlert(input Input) (Alert, bool) {
	if input.PeerCount == 0 {
		return Alert{}, false
	}
	if input.LinkSegments > 0 && input.MinLinkConfidence > 0 {
		return Alert{}, false
	}
	return Alert{
		ID: RuleProbeFailed, Rule: RuleProbeFailed, Severity: SeverityWarning,
		Summary: fmt.Sprintf("no confident link measurement for %d peer(s); path scoring is running on stale data", input.PeerCount),
	}, true
}

// deliver fans events out to every sink. A failing sink never blocks the
// others and never propagates into the evaluation caller.
func (alerter *Alerter) deliver(ctx context.Context, events []Event) {
	for _, event := range events {
		for _, sink := range alerter.sinks {
			if sink == nil {
				continue
			}
			_ = sink.Send(ctx, event)
		}
	}
}
