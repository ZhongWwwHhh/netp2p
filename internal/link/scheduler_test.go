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
