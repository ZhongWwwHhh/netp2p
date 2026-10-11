package link

import (
	"testing"
	"time"

	"github.com/netp2p/netp2p/internal/model"
	"github.com/netp2p/netp2p/internal/protocol"
)

func TestPlannerGeneratesDirectAndManagerFallback(t *testing.T) {
	state := model.NetworkState{
		NetworkID: "net",
		Peers: []model.PeerRecord{
			{PeerID: "client-a", OverlayIP: "100.64.0.2"},
			{PeerID: "client-b", OverlayIP: "100.64.0.3"},
		},
		Settings: model.NetworkSettings{
			DirectPathEnabled: true, ViaManagerEnabled: true, MaxManagerHops: 2,
			LinkMinBandwidthMbps: 10,
		},
	}
	committee := []model.CommitteeMember{
		{ID: "manager-a", PeerID: testCommitteePeerID(t, 401), ForwardingEnabled: true},
		{ID: "manager-b", PeerID: testCommitteePeerID(t, 402), ForwardingEnabled: true},
	}
	hopA := committee[0].PeerID
	hopB := committee[1].PeerID
	now := time.Now().UTC()
	view := Aggregate([]Observation{
		{ObserverID: hopA, SubjectID: hopB, Scope: ScopeManagerMesh, RTTMilliseconds: 20, LossPercent: 0, BandwidthMbps: 100, Samples: 5, MeasuredAt: now},
		{ObserverID: "client-a", SubjectID: hopA, Scope: ScopeManagerMesh, RTTMilliseconds: 10, LossPercent: 0, BandwidthMbps: 100, Samples: 5, MeasuredAt: now},
		{ObserverID: hopB, SubjectID: "client-b", Scope: ScopeManagerMesh, RTTMilliseconds: 10, LossPercent: 0, BandwidthMbps: 100, Samples: 5, MeasuredAt: now},
	}, now, time.Minute, 100)

	assignment, ok := AssignmentFor(AssignmentInput{State: state, Committee: committee, View: view}, "client-a", "client-b", 5)
	if !ok {
		t.Fatal("assignment not generated")
	}
	if assignment.Primary.Kind != model.PathKindDirect {
		t.Fatalf("primary kind = %q, want direct", assignment.Primary.Kind)
	}
	t.Logf("candidates assignment=%+v view=%+v", assignment, view)
	foundManagerFallback := false
	for _, fallback := range assignment.Fallbacks {
		if (fallback.Kind != model.PathKindViaManager && fallback.Kind != model.PathKindMultiHop) || len(fallback.ManagerHops) == 0 {
			continue
		}
		// Hops must be libp2p PeerIDs so the data plane can dial them and BFT
		// can verify them against the committee.
		for _, hop := range fallback.ManagerHops {
			if hop != hopA && hop != hopB {
				t.Fatalf("hop %q is not a committee PeerID", hop)
			}
		}
		foundManagerFallback = true
	}
	if !foundManagerFallback {
		t.Fatalf("manager fallback missing: %+v", assignment)
	}
}

func TestPlannerRejectsUnknownHopsAndDisabledViaManager(t *testing.T) {
	state := model.NetworkState{
		NetworkID: "net",
		Peers: []model.PeerRecord{
			{PeerID: "client-a"}, {PeerID: "client-b"},
		},
		Settings: model.NetworkSettings{DirectPathEnabled: true, ViaManagerEnabled: false},
	}
	committee := []model.CommitteeMember{{ID: "manager-a", ForwardingEnabled: false}}
	assignment, ok := AssignmentFor(AssignmentInput{State: state, Committee: committee}, "client-a", "client-b", 5)
	if !ok || assignment.Primary.Kind != model.PathKindDirect || len(assignment.Fallbacks) != 0 {
		t.Fatalf("unexpected assignment %+v ok=%v", assignment, ok)
	}
}

func TestPlannerDropsDirectPathAfterFailedAdmission(t *testing.T) {
	state, committee, view := twoManagerRouteFixture(t, nil)
	directPath := AssignmentID("client-a", "client-b") + "-direct"
	admissions := map[string]map[string]protocol.AdmissionReport{
		"client-a": {
			directPath: {AssignmentID: AssignmentID("client-a", "client-b"), PathID: directPath, OK: false, ObservedAt: time.Now().UTC()},
		},
	}

	assignment, ok := AssignmentFor(AssignmentInput{
		State: state, Committee: committee, View: view, Admissions: admissions,
	}, "client-a", "client-b", 5)
	if !ok {
		t.Fatal("assignment not generated")
	}
	if assignment.Primary.Kind == model.PathKindDirect {
		t.Fatalf("failed direct admission remained primary: %+v", assignment.Primary)
	}
	if assignment.Primary.Kind != model.PathKindViaManager || len(assignment.Primary.ManagerHops) == 0 {
		t.Fatalf("planner did not fail over to a manager path: %+v", assignment.Primary)
	}
	for _, path := range assignment.Paths() {
		if path.ID == directPath {
			t.Fatalf("failed direct path remained a candidate: %+v", path)
		}
	}
}

func TestPlannerConfirmsDirectPathAfterSuccessfulAdmission(t *testing.T) {
	state, committee, view := twoManagerRouteFixture(t, nil)
	assignmentID := AssignmentID("client-a", "client-b")
	directPath := assignmentID + "-direct"
	admissions := map[string]map[string]protocol.AdmissionReport{
		"client-a": {
			directPath: {AssignmentID: assignmentID, PathID: directPath, OK: true, RTTMs: 2, ObservedAt: time.Now().UTC()},
		},
	}

	assignment, ok := AssignmentFor(AssignmentInput{
		State: state, Committee: committee, View: view, Admissions: admissions,
	}, "client-a", "client-b", 5)
	if !ok {
		t.Fatal("assignment not generated")
	}
	if assignment.Primary.ID != directPath || assignment.Primary.Confidence != 1 {
		t.Fatalf("confirmed direct primary = %+v", assignment.Primary)
	}
}

// A via-manager path needs every hop measured, including the access links on
// both ends. Until then the planner must not invent it.
func TestPlannerOmitsViaManagerWhenSegmentsMissing(t *testing.T) {
	state := model.NetworkState{
		NetworkID: "net",
		Peers:     []model.PeerRecord{{PeerID: "client-a"}, {PeerID: "client-b"}},
		Settings:  model.NetworkSettings{DirectPathEnabled: true, ViaManagerEnabled: true, MaxManagerHops: 2},
	}
	committee := []model.CommitteeMember{{ID: "manager-a", PeerID: testCommitteePeerID(t, 411), ForwardingEnabled: true}}
	now := time.Now().UTC()
	view := Aggregate([]Observation{
		{ObserverID: committee[0].PeerID, SubjectID: "client-a", Scope: ScopeAccess, RTTMilliseconds: 10, LossPercent: 0, BandwidthMbps: 100, Samples: 5, MeasuredAt: now},
	}, now, time.Minute, 100)
	assignment, ok := AssignmentFor(AssignmentInput{State: state, Committee: committee, View: view}, "client-a", "client-b", 5)
	if !ok {
		t.Fatal("assignment not generated")
	}
	for _, fallback := range assignment.Fallbacks {
		if fallback.Kind == model.PathKindViaManager {
			t.Fatalf("via-manager path planned without a measured access segment: %+v", fallback)
		}
	}
}

// Unknown bandwidth must not disqualify a via-manager path.
func TestPlannerAcceptsViaManagerWithUnknownBandwidth(t *testing.T) {
	state := model.NetworkState{
		NetworkID: "net",
		Peers:     []model.PeerRecord{{PeerID: "client-a"}, {PeerID: "client-b"}},
		Settings:  model.NetworkSettings{DirectPathEnabled: true, ViaManagerEnabled: true, MaxManagerHops: 2, LinkMinBandwidthMbps: 10},
	}
	committee := []model.CommitteeMember{{ID: "manager-a", PeerID: testCommitteePeerID(t, 412), ForwardingEnabled: true}}
	hop := committee[0].PeerID
	now := time.Now().UTC()
	view := Aggregate([]Observation{
		{ObserverID: hop, SubjectID: "client-a", Scope: ScopeAccess, RTTMilliseconds: 10, LossPercent: 0, Samples: 5, MeasuredAt: now},
		{ObserverID: hop, SubjectID: "client-b", Scope: ScopeAccess, RTTMilliseconds: 12, LossPercent: 0, Samples: 5, MeasuredAt: now},
	}, now, time.Minute, 100)
	assignment, ok := AssignmentFor(AssignmentInput{State: state, Committee: committee, View: view}, "client-a", "client-b", 5)
	if !ok {
		t.Fatal("assignment not generated")
	}
	found := false
	for _, fallback := range assignment.Fallbacks {
		if fallback.Kind == model.PathKindViaManager {
			found = true
			if fallback.BandwidthMbps != 0 {
				t.Fatalf("bandwidth = %f, want 0 (unmeasured)", fallback.BandwidthMbps)
			}
		}
	}
	if !found {
		t.Fatalf("via-manager fallback missing for unknown-bandwidth view: %+v", assignment)
	}
}

// twoManagerRouteFixture builds a state with two forwarding managers and a
// bidirectional measurement set that makes both one-hop and two-hop paths
// viable. The optional route scopes the peer pair.
func twoManagerRouteFixture(t *testing.T, route *model.Route) (model.NetworkState, []model.CommitteeMember, LinkView) {
	t.Helper()
	state := model.NetworkState{
		NetworkID: "net",
		Peers: []model.PeerRecord{
			{PeerID: "client-a", OverlayIP: "100.64.0.2", Groups: []string{"clients"}},
			{PeerID: "client-b", OverlayIP: "100.64.0.3", Groups: []string{"servers"}},
		},
		Groups: []model.Group{
			{ID: "clients", PeerIDs: []string{"client-a"}},
			{ID: "servers", PeerIDs: []string{"client-b"}},
			{ID: "gateways", PeerIDs: []string{"manager-a"}},
		},
		Settings: model.NetworkSettings{DirectPathEnabled: true, ViaManagerEnabled: true, MaxManagerHops: 2, LinkMinBandwidthMbps: 10},
	}
	if route != nil {
		state.Routes = []model.Route{*route}
	}
	committee := []model.CommitteeMember{
		{ID: "manager-a", PeerID: testCommitteePeerID(t, 421), ForwardingEnabled: true},
		{ID: "manager-b", PeerID: testCommitteePeerID(t, 422), ForwardingEnabled: true},
	}
	hopA := committee[0].PeerID
	hopB := committee[1].PeerID
	now := time.Now().UTC()
	view := Aggregate([]Observation{
		{ObserverID: "client-a", SubjectID: hopA, Scope: ScopeManagerMesh, RTTMilliseconds: 10, LossPercent: 0, BandwidthMbps: 100, Samples: 5, MeasuredAt: now},
		{ObserverID: hopA, SubjectID: "client-b", Scope: ScopeManagerMesh, RTTMilliseconds: 10, LossPercent: 0, BandwidthMbps: 100, Samples: 5, MeasuredAt: now},
		{ObserverID: "client-a", SubjectID: hopB, Scope: ScopeManagerMesh, RTTMilliseconds: 30, LossPercent: 0, BandwidthMbps: 100, Samples: 5, MeasuredAt: now},
		{ObserverID: hopB, SubjectID: "client-b", Scope: ScopeManagerMesh, RTTMilliseconds: 30, LossPercent: 0, BandwidthMbps: 100, Samples: 5, MeasuredAt: now},
		{ObserverID: hopA, SubjectID: hopB, Scope: ScopeManagerMesh, RTTMilliseconds: 20, LossPercent: 0, BandwidthMbps: 100, Samples: 5, MeasuredAt: now},
	}, now, time.Minute, 100)
	return state, committee, view
}

// A route that allows only direct paths must suppress every manager path.
func TestPlannerHonoursRouteAllowedPathTypes(t *testing.T) {
	route := &model.Route{
		ID: "pair", Destination: "100.64.0.3/32", RoutingGroup: "gateways",
		DistributionGroup: []string{"clients"}, Metric: 10, AllowedPathTypes: []string{"direct"},
	}
	state, committee, view := twoManagerRouteFixture(t, route)
	assignment, ok := AssignmentFor(AssignmentInput{State: state, Committee: committee, View: view}, "client-a", "client-b", 5)
	if !ok {
		t.Fatal("assignment not generated")
	}
	for _, path := range assignment.Paths() {
		if path.Kind != model.PathKindDirect {
			t.Fatalf("route restricted to direct planned %q", path.Kind)
		}
	}
}

// A route's MaxHops must override the network default.
func TestPlannerHonoursRouteMaxHops(t *testing.T) {
	route := &model.Route{
		ID: "pair", Destination: "100.64.0.3/32", RoutingGroup: "gateways",
		DistributionGroup: []string{"clients"}, Metric: 10, MaxHops: 1,
	}
	state, committee, view := twoManagerRouteFixture(t, route)
	assignment, ok := AssignmentFor(AssignmentInput{State: state, Committee: committee, View: view}, "client-a", "client-b", 5)
	if !ok {
		t.Fatal("assignment not generated")
	}
	for _, path := range assignment.Paths() {
		if len(path.ManagerHops) > 1 {
			t.Fatalf("route max hops 1 planned %d hops", len(path.ManagerHops))
		}
	}
}

// A route budget whose forwarding-cost limit is below a path's hop count must
// hard-exclude that path.
func TestPlannerHonoursRouteBudgetCostLimit(t *testing.T) {
	route := &model.Route{
		ID: "pair", Destination: "100.64.0.3/32", RoutingGroup: "gateways",
		DistributionGroup: []string{"clients"}, Metric: 10, BudgetIDs: []string{"cheap"},
	}
	state, committee, view := twoManagerRouteFixture(t, route)
	state.Budgets = []model.TrafficBudget{{ID: "cheap", ForwardingCostLimit: 1}}
	assignment, ok := AssignmentFor(AssignmentInput{State: state, Committee: committee, View: view}, "client-a", "client-b", 5)
	if !ok {
		t.Fatal("assignment not generated")
	}
	for _, path := range assignment.Paths() {
		if len(path.ManagerHops) > 1 {
			t.Fatalf("budget cost limit 1 allowed a %d-hop path", len(path.ManagerHops))
		}
	}
}
