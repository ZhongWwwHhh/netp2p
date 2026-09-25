package link

import (
	"testing"
	"time"

	"github.com/netp2p/netp2p/internal/model"
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
		if fallback.Kind != model.PathKindViaManager || len(fallback.ManagerHops) == 0 {
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
