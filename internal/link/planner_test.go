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
		{ID: "manager-a", ForwardingEnabled: true},
		{ID: "manager-b", ForwardingEnabled: true},
	}
	now := time.Now().UTC()
	view := Aggregate([]Observation{
		{ObserverID: "manager-a", SubjectID: "manager-b", Scope: ScopeManagerMesh, RTTMilliseconds: 20, LossPercent: 0, BandwidthMbps: 100, Samples: 5, MeasuredAt: now},
		{ObserverID: "client-a", SubjectID: "manager-a", Scope: ScopeManagerMesh, RTTMilliseconds: 10, LossPercent: 0, BandwidthMbps: 100, Samples: 5, MeasuredAt: now},
		{ObserverID: "manager-b", SubjectID: "client-b", Scope: ScopeManagerMesh, RTTMilliseconds: 10, LossPercent: 0, BandwidthMbps: 100, Samples: 5, MeasuredAt: now},
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
		if fallback.Kind == model.PathKindViaManager && len(fallback.ManagerHops) > 0 {
			foundManagerFallback = true
		}
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
