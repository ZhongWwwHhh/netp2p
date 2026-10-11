package link

import (
	"context"
	"math"
	"sync"
	"time"

	"github.com/netp2p/netp2p/internal/bft"
	"github.com/netp2p/netp2p/internal/model"
	"github.com/netp2p/netp2p/internal/policy"
	"github.com/netp2p/netp2p/internal/protocol"
)

const (
	replanCooldown          = 30 * time.Second
	assignmentStabilization = 2 * time.Minute
	submitRetryBackoff      = 30 * time.Second
)

type Submitter interface {
	Submit(transition model.StateTransition) (model.SignedSnapshot, error)
}

// AllowedFn returns the service list permitted from source to destination.
// The scheduler uses it to create assignments only for policy-allowed pairs.
type AllowedFn func(source, destination string) ([]model.Service, bool)

// Scheduler converts mesh LinkViews into BFT-certified RouteAssignments. It
// deliberately only observes changes every interval and keeps a cooldown, so
// probe noise cannot turn into consensus churn.
type Scheduler struct {
	manager       Submitter
	committee     []model.CommitteeMember
	view          func() LinkView
	admissions    func() map[string]map[string]protocol.AdmissionReport
	allowed       AllowedFn
	leader        func() bool
	interval      time.Duration
	threshold     float64
	cooldown      time.Duration
	stabilization time.Duration

	mu         sync.Mutex
	lastReplan time.Time
	retryUntil map[string]time.Time
	now        func() time.Time
}

func NewScheduler(manager Submitter, committee []model.CommitteeMember, view func() LinkView) *Scheduler {
	return &Scheduler{
		manager: manager, committee: committee, view: view,
		interval: 15 * time.Second, threshold: 10, cooldown: replanCooldown,
		stabilization: assignmentStabilization,
		retryUntil:    make(map[string]time.Time),
		now:           time.Now,
	}
}

// SetAutomaticLeader installs the predicate used only by Run. Automatic ticks
// are no-ops until the deterministic next-height leader is known; explicit
// Reconcile calls remain available to admin tooling and tests.
func (scheduler *Scheduler) SetAutomaticLeader(leader func() bool) {
	scheduler.leader = leader
}

// SetCooldown adjusts the minimum time between two submitted assignments. A
// zero cooldown lets deterministic callers reconcile back to back.
func (scheduler *Scheduler) SetCooldown(cooldown time.Duration) {
	scheduler.cooldown = cooldown
}

// SetAdmissions supplies client path observations. They are evidence, not
// certified state: the planner uses them to remove a direct path that failed
// admission and to prefer one that succeeded.
func (scheduler *Scheduler) SetAdmissions(admissions func() map[string]map[string]protocol.AdmissionReport) {
	scheduler.admissions = admissions
}

// SetStabilization adjusts how long a newly certified assignment is protected
// from metric-only rewrites. The boundary is the certified UpdatedAt, so it
// follows the assignment across BFT leadership rotations. Topology changes are
// never held by this window.
func (scheduler *Scheduler) SetStabilization(stabilization time.Duration) {
	scheduler.stabilization = stabilization
}

func (scheduler *Scheduler) Run(ctx context.Context, state func() model.NetworkState) {
	ticker := time.NewTicker(scheduler.interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			_ = scheduler.ReconcileAutomatic(state())
		}
	}
}

// ReconcileAutomatic applies the leadership backpressure before planning.
func (scheduler *Scheduler) ReconcileAutomatic(state model.NetworkState) error {
	if scheduler.leader != nil && !scheduler.leader() {
		return nil
	}
	return scheduler.Reconcile(state)
}

func (scheduler *Scheduler) Reconcile(state model.NetworkState) error {
	now := scheduler.clock()
	if scheduler.cooldown > 0 && now.Sub(scheduler.lastReplanTime()) < scheduler.cooldown {
		return nil
	}
	view := scheduler.view()
	allowed := scheduler.allowed
	if allowed == nil {
		allowed = func(source, destination string) ([]model.Service, bool) {
			return policy.AllowedServices(policy.State{
				NetworkID: state.NetworkID, Groups: state.Groups, Policies: state.Policies,
				Routes: state.Routes, Budgets: state.Budgets,
			}, source, destination)
		}
	}
	// One sweep reconciles every policy-allowed pair and submits all changed
	// assignments together. Submitting a single assignment per cooldown meant a
	// network with many peers took minutes to converge; the change-detection
	// below (sameAssignment) is what actually bounds consensus writes, so a
	// full sweep is both correct and fast.
	submitted := false
	for _, source := range state.Peers {
		for _, destination := range state.Peers {
			if source.PeerID == destination.PeerID {
				continue
			}
			if _, permitted := allowed(source.PeerID, destination.PeerID); !permitted {
				continue
			}
			existing, found := findAssignment(state, source.PeerID, destination.PeerID)
			var admissions map[string]map[string]protocol.AdmissionReport
			if scheduler.admissions != nil {
				admissions = scheduler.admissions()
			}
			next, ok := AssignmentFor(AssignmentInput{
				State: state, Committee: scheduler.committee, View: view, Admissions: admissions,
			}, source.PeerID, destination.PeerID, scheduler.threshold)
			if !ok {
				continue
			}
			if found && sameAssignment(existing, next) {
				continue
			}
			key := transitionKey(source.PeerID, destination.PeerID)
			if scheduler.backedOff(key, now) {
				continue
			}
			if found && scheduler.stabilized(existing.UpdatedAt, now) && sameTopology(existing, next) {
				// The certified UpdatedAt lets every subsequent leader observe the
				// same protection window. Different managers still observe slightly
				// different probe metrics, so metric-only drift cannot race through
				// BFT merely because leadership changed.
				continue
			}
			if _, err := scheduler.manager.Submit(model.StateTransition{Type: bft.TransitionUpdateAssignment, Assignment: &next}); err != nil {
				scheduler.setBackoff(key, now, submitRetryBackoff)
				return err
			}
			submitted = true
		}
	}
	if submitted {
		scheduler.mu.Lock()
		scheduler.lastReplan = now
		scheduler.mu.Unlock()
	}
	return nil
}

func transitionKey(source, destination string) string {
	return source + "\x00" + destination
}

func (scheduler *Scheduler) clock() time.Time {
	scheduler.mu.Lock()
	defer scheduler.mu.Unlock()
	if scheduler.now != nil {
		return scheduler.now()
	}
	return time.Now()
}

func (scheduler *Scheduler) lastReplanTime() time.Time {
	scheduler.mu.Lock()
	defer scheduler.mu.Unlock()
	return scheduler.lastReplan
}

func (scheduler *Scheduler) backedOff(key string, now time.Time) bool {
	scheduler.mu.Lock()
	defer scheduler.mu.Unlock()
	return now.Before(scheduler.retryUntil[key])
}

// stabilized treats a future timestamp as protected as well, so bounded clock
// skew cannot immediately expire another leader's stabilization window.
func (scheduler *Scheduler) stabilized(certifiedAt, now time.Time) bool {
	if certifiedAt.IsZero() {
		return false
	}
	return now.Before(certifiedAt.Add(scheduler.stabilization))
}

func (scheduler *Scheduler) setBackoff(key string, now time.Time, interval time.Duration) {
	if interval <= 0 {
		return
	}
	scheduler.mu.Lock()
	defer scheduler.mu.Unlock()
	if scheduler.retryUntil == nil {
		scheduler.retryUntil = make(map[string]time.Time)
	}
	until := now.Add(interval)
	if until.After(scheduler.retryUntil[key]) {
		scheduler.retryUntil[key] = until
	}
}

func findAssignment(state model.NetworkState, source, destination string) (model.RouteAssignment, bool) {
	for _, assignment := range state.Assignments {
		if assignment.SourcePeerID == source && assignment.DestinationPeerID == destination {
			return assignment, true
		}
	}
	return model.RouteAssignment{}, false
}

func sameAssignment(current, next model.RouteAssignment) bool {
	if !samePath(current.Primary, next.Primary) {
		return false
	}
	if len(current.Fallbacks) != len(next.Fallbacks) {
		return false
	}
	for index := range current.Fallbacks {
		if !samePath(current.Fallbacks[index], next.Fallbacks[index]) {
			return false
		}
	}
	return true
}

// samePath compares the stable identity of a path (kind and manager hops) and
// treats small metric fluctuations as unchanged. Without this, ordinary probe
// jitter would submit a new BFT transition on every reconcile tick.
func samePath(current, next model.PathSpec) bool {
	if current.Kind != next.Kind || len(current.ManagerHops) != len(next.ManagerHops) {
		return false
	}
	for index := range current.ManagerHops {
		if current.ManagerHops[index] != next.ManagerHops[index] {
			return false
		}
	}
	return within(current.RTTMilliseconds, next.RTTMilliseconds, 5, 0.2) &&
		math.Abs(current.LossPercent-next.LossPercent) <= 2 &&
		within(current.BandwidthMbps, next.BandwidthMbps, 5, 0.2) &&
		math.Abs(current.Confidence-next.Confidence) <= 0.15
}

// sameTopology compares only routing identity. It deliberately ignores every
// measured metric, letting stabilization distinguish a real path change from
// observations that merely disagree at the edges of their tolerance windows.
func sameTopology(current, next model.RouteAssignment) bool {
	if !samePathIdentity(current.Primary, next.Primary) ||
		len(current.Fallbacks) != len(next.Fallbacks) {
		return false
	}
	for index := range current.Fallbacks {
		if !samePathIdentity(current.Fallbacks[index], next.Fallbacks[index]) {
			return false
		}
	}
	return true
}

func samePathIdentity(current, next model.PathSpec) bool {
	if current.Kind != next.Kind || len(current.ManagerHops) != len(next.ManagerHops) {
		return false
	}
	for index := range current.ManagerHops {
		if current.ManagerHops[index] != next.ManagerHops[index] {
			return false
		}
	}
	return true
}

// within reports whether two metrics are close enough to be considered equal:
// either within an absolute margin or a relative fraction of the larger value.
func within(current, next, absolute, relative float64) bool {
	delta := math.Abs(current - next)
	if delta <= absolute {
		return true
	}
	largest := math.Max(math.Abs(current), math.Abs(next))
	return largest > 0 && delta <= largest*relative
}
