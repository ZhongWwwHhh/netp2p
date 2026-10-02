package link

import (
	"testing"
	"time"

	"github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/netp2p/netp2p/internal/bft"
	"github.com/netp2p/netp2p/internal/model"
)

type stubSchedulerManager struct {
	transitions []model.StateTransition
}

func (stub *stubSchedulerManager) Submit(transition model.StateTransition) (model.SignedSnapshot, error) {
	stub.transitions = append(stub.transitions, transition)
	return model.SignedSnapshot{}, nil
}

func testCommitteePeerID(t *testing.T, seed int64) string {
	t.Helper()
	privateKey := bft.SeededPrivateKey(seed)
	libp2pKey, _, err := crypto.KeyPairFromStdKey(&privateKey)
	if err != nil {
		t.Fatal(err)
	}
	peerID, err := peer.IDFromPrivateKey(libp2pKey)
	if err != nil {
		t.Fatal(err)
	}
	return peerID.String()
}

func TestSchedulerCreatesAndUpdatesAssignments(t *testing.T) {
	state := model.NetworkState{
		NetworkID: "net",
		Settings: model.NetworkSettings{
			ViaManagerEnabled: true, DirectPathEnabled: true, MaxManagerHops: 2,
		},
		Peers: []model.PeerRecord{{PeerID: "client-a"}, {PeerID: "client-b"}},
	}
	committee := []model.CommitteeMember{{
		ID: "manager-a", PeerID: testCommitteePeerID(t, 301), ForwardingEnabled: true,
	}}
	hop := committee[0].PeerID
	now := time.Now().UTC()
	view := Aggregate([]Observation{
		{ObserverID: "client-a", SubjectID: hop, Scope: ScopeManagerMesh, RTTMilliseconds: 10, LossPercent: 0, BandwidthMbps: 100, Samples: 1, MeasuredAt: now},
		{ObserverID: hop, SubjectID: "client-b", Scope: ScopeManagerMesh, RTTMilliseconds: 10, LossPercent: 0, BandwidthMbps: 100, Samples: 1, MeasuredAt: now},
	}, now, time.Minute, 100)
	manager := &stubSchedulerManager{}
	scheduler := NewScheduler(manager, committee, func() LinkView { return view })
	scheduler.allowed = func(source, destination string) ([]model.Service, bool) {
		if source == "client-a" && destination == "client-b" {
			return []model.Service{{Protocol: "icmp"}}, true
		}
		return nil, false
	}
	if err := scheduler.Reconcile(state); err != nil {
		t.Fatal(err)
	}
	if len(manager.transitions) != 1 || manager.transitions[0].Assignment == nil {
		t.Fatalf("expected one assignment transition, got %+v", manager.transitions)
	}
	assignment := *manager.transitions[0].Assignment
	if assignment.Primary.Kind != model.PathKindDirect {
		t.Fatalf("primary path = %s, want direct", assignment.Primary.Kind)
	}
	foundViaManager := false
	for _, path := range assignment.Fallbacks {
		if path.Kind == model.PathKindViaManager && len(path.ManagerHops) == 1 && path.ManagerHops[0] == hop {
			foundViaManager = true
		}
	}
	if !foundViaManager {
		t.Fatalf("via-manager fallback missing: %+v", assignment)
	}
}

// Probe jitter must not turn into a consensus write on every reconcile tick.
func TestSchedulerIgnoresMetricNoise(t *testing.T) {
	state := model.NetworkState{
		NetworkID: "net",
		Settings: model.NetworkSettings{
			ViaManagerEnabled: true, DirectPathEnabled: true, MaxManagerHops: 2,
		},
		Peers: []model.PeerRecord{{PeerID: "client-a"}, {PeerID: "client-b"}},
	}
	committee := []model.CommitteeMember{{
		ID: "manager-a", PeerID: testCommitteePeerID(t, 302), ForwardingEnabled: true,
	}}
	hop := committee[0].PeerID
	now := time.Now().UTC()
	observations := func(rtt float64, bandwidth float64) []Observation {
		return []Observation{
			{ObserverID: hop, SubjectID: "client-a", Scope: ScopeAccess, RTTMilliseconds: rtt, LossPercent: 0, BandwidthMbps: bandwidth, Samples: 5, MeasuredAt: now},
			{ObserverID: hop, SubjectID: "client-b", Scope: ScopeAccess, RTTMilliseconds: rtt, LossPercent: 0, BandwidthMbps: bandwidth, Samples: 5, MeasuredAt: now},
		}
	}
	manager := &stubSchedulerManager{}
	scheduler := NewScheduler(manager, committee, func() LinkView {
		return Aggregate(observations(10, 100), now, time.Minute, 100)
	})
	scheduler.allowed = func(source, destination string) ([]model.Service, bool) {
		if source == "client-a" && destination == "client-b" {
			return []model.Service{{Protocol: "icmp"}}, true
		}
		return nil, false
	}
	if err := scheduler.Reconcile(state); err != nil {
		t.Fatal(err)
	}
	if len(manager.transitions) != 1 || manager.transitions[0].Assignment == nil {
		t.Fatalf("expected one assignment transition, got %+v", manager.transitions)
	}
	state.Assignments = []model.RouteAssignment{*manager.transitions[0].Assignment}
	scheduler.view = func() LinkView {
		return Aggregate(observations(11, 104), now, time.Minute, 100)
	}
	scheduler.lastReplan = time.Now().Add(-time.Minute)
	if err := scheduler.Reconcile(state); err != nil {
		t.Fatal(err)
	}
	if len(manager.transitions) != 1 {
		t.Fatalf("scheduler churned on metric noise: %d transitions", len(manager.transitions))
	}
}

// A single reconcile sweep must reconcile every allowed pair, so a network
// with several peers does not need one cooldown window per assignment.
func TestSchedulerReconcilesEveryPairInOneSweep(t *testing.T) {
	state := model.NetworkState{
		NetworkID: "net",
		Settings: model.NetworkSettings{
			ViaManagerEnabled: true, DirectPathEnabled: true, MaxManagerHops: 2,
		},
		Peers: []model.PeerRecord{
			{PeerID: "client-a"}, {PeerID: "client-b"}, {PeerID: "client-c"},
		},
	}
	committee := []model.CommitteeMember{{
		ID: "manager-a", PeerID: testCommitteePeerID(t, 303), ForwardingEnabled: true,
	}}
	hop := committee[0].PeerID
	now := time.Now().UTC()
	view := Aggregate([]Observation{
		{ObserverID: hop, SubjectID: "client-a", Scope: ScopeAccess, RTTMilliseconds: 10, BandwidthMbps: 100, Samples: 5, MeasuredAt: now},
		{ObserverID: hop, SubjectID: "client-b", Scope: ScopeAccess, RTTMilliseconds: 10, BandwidthMbps: 100, Samples: 5, MeasuredAt: now},
		{ObserverID: hop, SubjectID: "client-c", Scope: ScopeAccess, RTTMilliseconds: 10, BandwidthMbps: 100, Samples: 5, MeasuredAt: now},
	}, now, time.Minute, 100)
	allowed := func(source, destination string) ([]model.Service, bool) {
		if source == "client-a" && (destination == "client-b" || destination == "client-c") {
			return []model.Service{{Protocol: "icmp"}}, true
		}
		return nil, false
	}
	manager := &stubSchedulerManager{}
	scheduler := NewScheduler(manager, committee, func() LinkView { return view })
	scheduler.allowed = allowed
	if err := scheduler.Reconcile(state); err != nil {
		t.Fatal(err)
	}
	if len(manager.transitions) != 2 {
		t.Fatalf("expected both allowed pairs in one sweep, got %d transitions", len(manager.transitions))
	}
	destinations := make(map[string]bool)
	for _, transition := range manager.transitions {
		destinations[transition.Assignment.DestinationPeerID] = true
	}
	if !destinations["client-b"] || !destinations["client-c"] {
		t.Fatalf("missing assignment in sweep: %v", destinations)
	}

	// A second sweep with unchanged inputs must not write anything.
	state.Assignments = []model.RouteAssignment{
		*manager.transitions[0].Assignment,
		*manager.transitions[1].Assignment,
	}
	scheduler.lastReplan = time.Now().Add(-time.Minute)
	if err := scheduler.Reconcile(state); err != nil {
		t.Fatal(err)
	}
	if len(manager.transitions) != 2 {
		t.Fatalf("unchanged sweep churned: %d transitions", len(manager.transitions))
	}
}
