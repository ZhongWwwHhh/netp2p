package link

import (
	"context"
	"reflect"
	"time"

	"github.com/netp2p/netp2p/internal/bft"
	"github.com/netp2p/netp2p/internal/model"
)

const replanCooldown = 30 * time.Second

type Submitter interface {
	Submit(transition model.StateTransition) (model.SignedSnapshot, error)
}

// Scheduler converts mesh LinkViews into BFT-certified RouteAssignments. It
// deliberately only observes changes every interval and keeps a cooldown, so
// probe noise cannot turn into consensus churn.
type Scheduler struct {
	manager   Submitter
	committee []model.CommitteeMember
	view      func() LinkView
	interval  time.Duration
	threshold float64

	lastReplan time.Time
}

func NewScheduler(manager Submitter, committee []model.CommitteeMember, view func() LinkView) *Scheduler {
	return &Scheduler{
		manager: manager, committee: committee, view: view,
		interval: 15 * time.Second, threshold: 10,
	}
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
	if time.Since(scheduler.lastReplan) < replanCooldown {
		return nil
	}
	view := scheduler.view()
	input := AssignmentInput{State: state, Committee: scheduler.committee, View: view, Allowed: policyAllowed(state)}
	for _, assignment := range state.Assignments {
		next, ok := AssignmentFor(input, assignment.SourcePeerID, assignment.DestinationPeerID, scheduler.threshold)
		if !ok {
			continue
		}
		if sameAssignment(assignment, next) {
			continue
		}
		if _, err := scheduler.manager.Submit(model.StateTransition{Type: bft.TransitionUpdateAssignment, Assignment: &next}); err != nil {
			return err
		}
		scheduler.lastReplan = time.Now()
		return nil
	}
	return nil
}

func policyAllowed(state model.NetworkState) map[string]map[string][]model.Service {
	return nil
}

func sameAssignment(current, next model.RouteAssignment) bool {
	if !reflect.DeepEqual(current.Primary, next.Primary) {
		return false
	}
	if len(current.Fallbacks) != len(next.Fallbacks) {
		return false
	}
	for index := range current.Fallbacks {
		if !reflect.DeepEqual(current.Fallbacks[index], next.Fallbacks[index]) {
			return false
		}
	}
	return true
}
