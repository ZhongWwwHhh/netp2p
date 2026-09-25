package link

import (
	"context"
	"math"
	"time"

	"github.com/netp2p/netp2p/internal/bft"
	"github.com/netp2p/netp2p/internal/model"
	"github.com/netp2p/netp2p/internal/policy"
)

const replanCooldown = 30 * time.Second

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
	manager   Submitter
	committee []model.CommitteeMember
	view      func() LinkView
	allowed   AllowedFn
	interval  time.Duration
	threshold float64
	cooldown  time.Duration

	lastReplan time.Time
}

func NewScheduler(manager Submitter, committee []model.CommitteeMember, view func() LinkView) *Scheduler {
	return &Scheduler{
		manager: manager, committee: committee, view: view,
		interval: 15 * time.Second, threshold: 10, cooldown: replanCooldown,
	}
}

// SetCooldown adjusts the minimum time between two submitted assignments. A
// zero cooldown lets deterministic callers reconcile back to back.
func (scheduler *Scheduler) SetCooldown(cooldown time.Duration) {
	scheduler.cooldown = cooldown
}

func (scheduler *Scheduler) Run(ctx context.Context, state func() model.NetworkState) {
	ticker := time.NewTicker(scheduler.interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			_ = scheduler.Reconcile(state())
		}
	}
}

func (scheduler *Scheduler) Reconcile(state model.NetworkState) error {
	if scheduler.cooldown > 0 && time.Since(scheduler.lastReplan) < scheduler.cooldown {
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
	for _, source := range state.Peers {
		for _, destination := range state.Peers {
			if source.PeerID == destination.PeerID {
				continue
			}
			if _, permitted := allowed(source.PeerID, destination.PeerID); !permitted {
				continue
			}
			existing, found := findAssignment(state, source.PeerID, destination.PeerID)
			next, ok := AssignmentFor(AssignmentInput{State: state, Committee: scheduler.committee, View: view}, source.PeerID, destination.PeerID, scheduler.threshold)
			if !ok {
				continue
			}
			if found && sameAssignment(existing, next) {
				continue
			}
			if _, err := scheduler.manager.Submit(model.StateTransition{Type: bft.TransitionUpdateAssignment, Assignment: &next}); err != nil {
				return err
			}
			scheduler.lastReplan = time.Now()
			return nil
		}
	}
	return nil
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
