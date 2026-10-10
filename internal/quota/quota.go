// Package quota tracks aggregate byte usage and runtime enforcement actions.
package quota

import (
	"sort"
	"sync"
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
	// BudgetID is the budget that produced the decision, empty when no budget
	// matched the traffic.
	BudgetID string `json:"budgetId,omitempty"`
	// Delay is how long a throttled packet must wait before it may be sent.
	Delay time.Duration `json:"delay,omitempty"`
}

// defaultMaxThrottleDelay bounds how long a throttled packet may be delayed
// before it is dropped instead of queued.
const defaultMaxThrottleDelay = 250 * time.Millisecond

// TokenBucket is a classic leaky-bucket rate limiter used for throttle-mode
// budgets. rate is bytes per second and burst is the maximum bucket depth.
type TokenBucket struct {
	rate   float64
	burst  float64
	tokens float64
	last   time.Time
	ready  bool
}

// NewTokenBucket builds a full bucket. A zero rate disables the bucket.
func NewTokenBucket(rateBytesPerSecond, burstBytes uint64, now time.Time) *TokenBucket {
	return &TokenBucket{rate: float64(rateBytesPerSecond), burst: float64(burstBytes), tokens: float64(burstBytes), last: now, ready: true}
}

func (bucket *TokenBucket) refill(now time.Time) {
	if !bucket.ready {
		bucket.last = now
		bucket.ready = true
		return
	}
	elapsed := now.Sub(bucket.last).Seconds()
	if elapsed <= 0 {
		return
	}
	bucket.last = now
	bucket.tokens += elapsed * bucket.rate
	if bucket.tokens > bucket.burst {
		bucket.tokens = bucket.burst
	}
}

// Allow reports whether a burst of bytes may be sent now. When it cannot be
// sent immediately the caller learns how long to wait; a wait longer than
// maxDelay means the packet should be dropped.
func (bucket *TokenBucket) Allow(bytes uint64, now time.Time, maxDelay time.Duration) (bool, time.Duration) {
	if bucket.rate <= 0 {
		return true, 0
	}
	bucket.refill(now)
	needed := float64(bytes)
	if bucket.tokens >= needed {
		bucket.tokens -= needed
		return true, 0
	}
	if bucket.rate <= 0 {
		return false, 0
	}
	shortfall := needed - bucket.tokens
	wait := time.Duration(shortfall / bucket.rate * float64(time.Second))
	if wait > maxDelay {
		return false, wait
	}
	// Reserve the tokens that will arrive after the wait so concurrent packets
	// do not all pass on the same window.
	bucket.tokens -= needed
	return true, wait
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

// Enforcer combines the aggregate byte budget with the token-bucket rate
// limiter. It is the single admission point for both the client's outbound
// path and the manager's forwarding path.
type Enforcer struct {
	mu      sync.Mutex
	budgets map[string]model.TrafficBudget
	order   []string
	buckets map[string]*TokenBucket
	deltas  map[string]uint64
	now     func() time.Time
	// MaxThrottleDelay bounds throttle-mode queuing.
	MaxThrottleDelay time.Duration
}

// NewEnforcer builds an enforcer from the certified budgets.
func NewEnforcer(budgets []model.TrafficBudget) *Enforcer {
	enforcer := &Enforcer{
		budgets:          make(map[string]model.TrafficBudget),
		buckets:          make(map[string]*TokenBucket),
		deltas:           make(map[string]uint64),
		now:              time.Now,
		MaxThrottleDelay: defaultMaxThrottleDelay,
	}
	enforcer.Replace(budgets)
	return enforcer
}

// Replace updates the budget set as certified state changes. Usage counters are
// preserved so the reset is driven by the manager, not by a local heuristic.
func (enforcer *Enforcer) Replace(budgets []model.TrafficBudget) {
	enforcer.mu.Lock()
	defer enforcer.mu.Unlock()

	now := enforcer.now()
	pending := make(map[string]uint64, len(enforcer.deltas))
	for id, bytes := range enforcer.deltas {
		pending[id] = bytes
	}
	known := make(map[string]struct{}, len(budgets))
	for _, budget := range budgets {
		known[budget.ID] = struct{}{}
		// Keep locally admitted but not yet settled bytes. A snapshot refresh
		// must never turn an exhausted budget into an empty one.
		if bytes := pending[budget.ID]; bytes > 0 {
			budget.UsedDailyBytes += bytes
			budget.UsedMonthlyBytes += bytes
		}
		enforcer.budgets[budget.ID] = budget
		if existing, ok := enforcer.buckets[budget.ID]; !ok || !existing.ready {
			burst := budget.PeakBurstBytes
			if burst == 0 {
				burst = budget.PeakBPS
			}
			if burst == 0 {
				burst = 1 << 16
			}
			enforcer.buckets[budget.ID] = NewTokenBucket(budget.PeakBPS, burst, now)
		}
	}
	for id := range enforcer.budgets {
		if _, ok := known[id]; !ok {
			delete(enforcer.budgets, id)
			delete(enforcer.buckets, id)
			delete(enforcer.deltas, id)
		}
	}
	order := make([]string, 0, len(enforcer.budgets))
	for id := range enforcer.budgets {
		order = append(order, id)
	}
	sort.Strings(order)
	enforcer.order = order
}

// Resolve picks the most specific budget for a flow. Priority is fixed at
// route → group → peer so a narrow route budget always wins over a broad peer
// budget.
func (enforcer *Enforcer) Resolve(peerID string, groups []string, routeID string) (model.TrafficBudget, bool) {
	enforcer.mu.Lock()
	defer enforcer.mu.Unlock()
	return enforcer.resolveLocked(peerID, groups, routeID)
}

func (enforcer *Enforcer) resolveLocked(peerID string, groups []string, routeID string) (model.TrafficBudget, bool) {
	group := make(map[string]struct{}, len(groups))
	for _, id := range groups {
		group[id] = struct{}{}
	}
	for _, kind := range []string{"route", "group", "peer"} {
		for _, id := range enforcer.order {
			budget := enforcer.budgets[id]
			if budget.SubjectType != kind {
				continue
			}
			switch kind {
			case "route":
				if routeID != "" && budget.SubjectID == routeID {
					return budget, true
				}
			case "group":
				if _, ok := group[budget.SubjectID]; ok {
					return budget, true
				}
			case "peer":
				if peerID != "" && budget.SubjectID == peerID {
					return budget, true
				}
			}
		}
	}
	return model.TrafficBudget{}, false
}

// Check admits bytes against the matching budget and records the usage delta
// for later settlement. A nil budget (no match) always allows.
func (enforcer *Enforcer) Check(peerID string, groups []string, routeID string, bytes uint64) Decision {
	enforcer.mu.Lock()
	defer enforcer.mu.Unlock()
	budget, ok := enforcer.resolveLocked(peerID, groups, routeID)
	if !ok {
		return Decision{Allowed: true, Action: ActionAllow}
	}
	now := enforcer.now()
	remaining := budget.DailyBytes - min64(budget.UsedDailyBytes, budget.DailyBytes)
	reset := dailyExpiry(now)
	if budget.MonthlyBytes > 0 {
		monthly := budget.MonthlyBytes - min64(budget.UsedMonthlyBytes, budget.MonthlyBytes)
		if monthly < remaining {
			remaining = monthly
			reset = monthlyExpiry(now)
		}
	}
	if remaining < bytes {
		action := Action(budget.OnExhausted)
		if action == "" {
			action = ActionBlock
		}
		return Decision{Allowed: false, Action: action, Remaining: remaining, LimitReset: reset, BudgetID: budget.ID}
	}
	// A block-mode budget never rate limits; it only stops at the cap.
	if budget.OnExhausted == string(ActionThrottle) && budget.PeakBPS > 0 {
		if bucket := enforcer.buckets[budget.ID]; bucket != nil {
			allowed, delay := bucket.Allow(bytes, now, enforcer.MaxThrottleDelay)
			if !allowed {
				return Decision{Allowed: false, Action: ActionThrottle, Remaining: remaining, LimitReset: reset, BudgetID: budget.ID, Delay: delay}
			}
			if delay > 0 {
				enforcer.record(budget.ID, bytes)
				return Decision{Allowed: true, Action: ActionThrottle, Remaining: remaining - bytes, LimitReset: reset, BudgetID: budget.ID, Delay: delay}
			}
		}
	}
	enforcer.record(budget.ID, bytes)
	return Decision{Allowed: true, Action: ActionAllow, Remaining: remaining - bytes, LimitReset: reset, BudgetID: budget.ID}
}

func (enforcer *Enforcer) record(budgetID string, bytes uint64) {
	budget := enforcer.budgets[budgetID]
	budget.UsedDailyBytes += bytes
	budget.UsedMonthlyBytes += bytes
	enforcer.budgets[budgetID] = budget
	enforcer.deltas[budgetID] += bytes
}

// DrainDeltas returns and clears the accumulated per-budget byte deltas since
// the last drain, for reporting to the manager.
func (enforcer *Enforcer) DrainDeltas() map[string]uint64 {
	enforcer.mu.Lock()
	defer enforcer.mu.Unlock()
	result := make(map[string]uint64, len(enforcer.deltas))
	for id, bytes := range enforcer.deltas {
		if bytes == 0 {
			continue
		}
		result[id] = bytes
		delete(enforcer.deltas, id)
	}
	return result
}

// Usage returns a copy of the locally tracked usage, for the console.
func (enforcer *Enforcer) Usage() map[string]model.TrafficBudget {
	enforcer.mu.Lock()
	defer enforcer.mu.Unlock()
	result := make(map[string]model.TrafficBudget, len(enforcer.budgets))
	for id, budget := range enforcer.budgets {
		result[id] = budget
	}
	return result
}

// RestoreDelta puts a drained delta back after a failed report so it is not
// lost. The tracked usage is not re-applied; only the outbound increment.
func (enforcer *Enforcer) RestoreDelta(budgetID string, bytes uint64) {
	if bytes == 0 {
		return
	}
	enforcer.mu.Lock()
	defer enforcer.mu.Unlock()
	enforcer.deltas[budgetID] += bytes
}

func min64(a, b uint64) uint64 {
	if a < b {
		return a
	}
	return b
}
