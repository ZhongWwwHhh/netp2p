package link

import (
	"errors"
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

func TestSchedulerFollowerAutomaticTickIsNoOp(t *testing.T) {
	state := model.NetworkState{
		NetworkID: "net",
		Settings: model.NetworkSettings{
			ViaManagerEnabled: true, DirectPathEnabled: false, MaxManagerHops: 2,
		},
		Peers: []model.PeerRecord{{PeerID: "client-a"}, {PeerID: "client-b"}},
	}
	committee := []model.CommitteeMember{{
		ID: "manager-a", PeerID: testCommitteePeerID(t, 304), ForwardingEnabled: true,
	}}
	now := time.Now().UTC()
	view := Aggregate([]Observation{
		{ObserverID: "client-a", SubjectID: committee[0].PeerID, Scope: ScopeAccess, RTTMilliseconds: 10, BandwidthMbps: 100, Samples: 5, MeasuredAt: now},
		{ObserverID: "client-a", SubjectID: "client-b", Scope: ScopeManagerMesh, RTTMilliseconds: 10, BandwidthMbps: 100, Samples: 5, MeasuredAt: now},
		{ObserverID: committee[0].PeerID, SubjectID: "client-b", Scope: ScopeAccess, RTTMilliseconds: 10, BandwidthMbps: 100, Samples: 5, MeasuredAt: now},
	}, now, time.Minute, 100)
	manager := &stubSchedulerManager{}
	scheduler := NewScheduler(manager, committee, func() LinkView { return view })
	scheduler.SetCooldown(0)
	scheduler.SetAutomaticLeader(func() bool { return false })
	scheduler.allowed = func(source, destination string) ([]model.Service, bool) {
		if source == "client-a" && destination == "client-b" {
			return []model.Service{{Protocol: "icmp"}}, true
		}
		return nil, false
	}
	if err := scheduler.ReconcileAutomatic(state); err != nil {
		t.Fatal(err)
	}
	if len(manager.transitions) != 0 {
		t.Fatalf("follower submitted %d transitions", len(manager.transitions))
	}
	scheduler.SetAutomaticLeader(func() bool { return true })
	if err := scheduler.ReconcileAutomatic(state); err != nil {
		t.Fatal(err)
	}
	if len(manager.transitions) != 1 {
		t.Fatalf("leader did not converge: %d transitions", len(manager.transitions))
	}
}

func TestSchedulerStabilizesMetricOnlyChanges(t *testing.T) {
	state := model.NetworkState{
		NetworkID: "net",
		Settings: model.NetworkSettings{
			ViaManagerEnabled: true, DirectPathEnabled: false, MaxManagerHops: 2,
		},
		Peers: []model.PeerRecord{{PeerID: "client-a"}, {PeerID: "client-b"}},
	}
	committee := []model.CommitteeMember{{
		ID: "manager-a", PeerID: testCommitteePeerID(t, 305), ForwardingEnabled: true,
	}}
	hop := committee[0].PeerID
	observations := func(rtt, bandwidth float64) []Observation {
		measured := time.Unix(1000, 0).UTC()
		return []Observation{
			{ObserverID: "client-a", SubjectID: hop, Scope: ScopeAccess, RTTMilliseconds: rtt, BandwidthMbps: bandwidth, Samples: 5, MeasuredAt: measured},
			{ObserverID: "client-a", SubjectID: "client-b", Scope: ScopeManagerMesh, RTTMilliseconds: rtt, BandwidthMbps: bandwidth, Samples: 5, MeasuredAt: measured},
			{ObserverID: hop, SubjectID: "client-b", Scope: ScopeAccess, RTTMilliseconds: rtt, BandwidthMbps: bandwidth, Samples: 5, MeasuredAt: measured},
		}
	}
	manager := &stubSchedulerManager{}
	current := time.Unix(1000, 0).UTC()
	scheduler := NewScheduler(manager, committee, func() LinkView {
		return Aggregate(observations(10, 100), current, time.Minute, 100)
	})
	scheduler.SetCooldown(0)
	scheduler.now = func() time.Time { return current }
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
		t.Fatalf("expected initial assignment, got %+v", manager.transitions)
	}
	if got := manager.transitions[0].Assignment.Primary.Kind; got != model.PathKindViaManager {
		t.Fatalf("initial primary = %s, want %s", got, model.PathKindViaManager)
	}
	state.Assignments = []model.RouteAssignment{*manager.transitions[0].Assignment}

	// A materially different metric set must not rewrite the just-certified
	// topology, even though it would no longer compare equal after stabilization.
	scheduler.view = func() LinkView {
		return Aggregate(observations(30, 150), current, time.Minute, 100)
	}
	if err := scheduler.Reconcile(state); err != nil {
		t.Fatal(err)
	}
	if len(manager.transitions) != 1 {
		t.Fatalf("stabilization allowed metric churn: %d transitions", len(manager.transitions))
	}

	// The next height has a different deterministic leader. Stabilization must
	// come from certified assignment state, not the first scheduler's memory.
	successor := &stubSchedulerManager{}
	nextLeader := NewScheduler(successor, committee, func() LinkView {
		return Aggregate(observations(30, 150), current, time.Minute, 100)
	})
	nextLeader.SetCooldown(0)
	nextLeader.SetAutomaticLeader(func() bool { return true })
	nextLeader.now = scheduler.now
	nextLeader.allowed = scheduler.allowed
	if err := nextLeader.ReconcileAutomatic(state); err != nil {
		t.Fatal(err)
	}
	if len(successor.transitions) != 0 {
		t.Fatalf("successor leader churned metric-only state: %d transitions", len(successor.transitions))
	}

	// A different path topology is a real user-visible change and bypasses the
	// stabilization window immediately.
	state.Settings.DirectPathEnabled = true
	if err := nextLeader.ReconcileAutomatic(state); err != nil {
		t.Fatal(err)
	}
	if len(successor.transitions) != 1 || successor.transitions[0].Assignment == nil {
		t.Fatalf("topology change did not converge: %+v", successor.transitions)
	}
	if got := successor.transitions[0].Assignment.Primary.Kind; got != model.PathKindDirect {
		t.Fatalf("new primary = %s, want %s", got, model.PathKindDirect)
	}
}

type failingSchedulerManager struct {
	stubSchedulerManager
	failFirst bool
}

func (stub *failingSchedulerManager) Submit(transition model.StateTransition) (model.SignedSnapshot, error) {
	if stub.failFirst {
		stub.failFirst = false
		return model.SignedSnapshot{}, errors.New("committee unavailable")
	}
	return stub.stubSchedulerManager.Submit(transition)
}

func TestSchedulerBacksOffFailedTransition(t *testing.T) {
	state := model.NetworkState{
		NetworkID: "net",
		Settings: model.NetworkSettings{
			ViaManagerEnabled: true, DirectPathEnabled: false, MaxManagerHops: 2,
		},
		Peers: []model.PeerRecord{{PeerID: "client-a"}, {PeerID: "client-b"}},
	}
	committee := []model.CommitteeMember{{
		ID: "manager-a", PeerID: testCommitteePeerID(t, 306), ForwardingEnabled: true,
	}}
	now := time.Now().UTC()
	view := Aggregate([]Observation{
		{ObserverID: "client-a", SubjectID: committee[0].PeerID, Scope: ScopeAccess, RTTMilliseconds: 10, BandwidthMbps: 100, Samples: 5, MeasuredAt: now},
		{ObserverID: "client-a", SubjectID: "client-b", Scope: ScopeManagerMesh, RTTMilliseconds: 10, BandwidthMbps: 100, Samples: 5, MeasuredAt: now},
		{ObserverID: committee[0].PeerID, SubjectID: "client-b", Scope: ScopeAccess, RTTMilliseconds: 10, BandwidthMbps: 100, Samples: 5, MeasuredAt: now},
	}, now, time.Minute, 100)
	manager := &failingSchedulerManager{failFirst: true}
	scheduler := NewScheduler(manager, committee, func() LinkView { return view })
	scheduler.SetCooldown(0)
	scheduler.SetAutomaticLeader(func() bool { return true })
	scheduler.allowed = func(source, destination string) ([]model.Service, bool) {
		if source == "client-a" && destination == "client-b" {
			return []model.Service{{Protocol: "icmp"}}, true
		}
		return nil, false
	}
	if err := scheduler.ReconcileAutomatic(state); err == nil {
		t.Fatal("expected submit failure")
	}
	if err := scheduler.ReconcileAutomatic(state); err != nil {
		t.Fatal(err)
	}
	if len(manager.transitions) != 0 {
		t.Fatalf("failed transition retried before backoff: %d submissions", len(manager.transitions))
	}
	manager.failFirst = false
	current := time.Now().Add(submitRetryBackoff + time.Second)
	scheduler.now = func() time.Time { return current }
	if err := scheduler.ReconcileAutomatic(state); err != nil {
		t.Fatal(err)
	}
	if len(manager.transitions) != 1 {
		t.Fatalf("backoff did not clear: %d submissions", len(manager.transitions))
	}
}
