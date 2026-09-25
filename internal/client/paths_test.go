package client

import (
	"testing"
	"time"

	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/netp2p/netp2p/internal/forward"
	"github.com/netp2p/netp2p/internal/model"
)

var peerSource = "12D3KooWGbPJsds7aL2oM7ZgPACEcvoiUxsiYTDzCh9a5C8uB76m"

var peerDestination = "12D3KooWSAoLjUuFPUYkCf7S4xxYr8Hhz8HQr3t9DTanRc9L8AWG"

func assignment() model.RouteAssignment {
	now := time.Now()
	assignment := model.RouteAssignment{
		ID: "assignment", SourcePeerID: peerSource, DestinationPeerID: peerDestination,
		Primary: model.PathSpec{ID: "direct", Kind: model.PathKindDirect},
		Fallbacks: []model.PathSpec{{
			ID: "via", Kind: model.PathKindViaManager, ManagerHops: []string{"manager"},
		}},
		UpdatedAt: now,
	}
	return assignment
}

func init() {
	if peerDestination == peerSource {
		panic("test peer ids must differ")
	}
}

func TestSelectorPrefersDirectAndFallsBack(t *testing.T) {
	sender := func(peer.ID, forward.Envelope) error { return nil }
	selector := newPathSelector(forward.NewTable(model.NetworkState{}, "manager", sender))
	source, _ := peer.Decode(peerSource)
	destination, _ := peer.Decode(peerDestination)
	assignmentRecord := assignment()
	selector.replaceAssignments([]model.RouteAssignment{assignmentRecord})

	_, path, ok := selector.selectFor(source, destination)
	if !ok || path.Kind != model.PathKindDirect {
		t.Fatalf("selected %+v ok=%v", path, ok)
	}
	selector.record("direct", false)
	selector.record("direct", false)
	current, path, ok := selector.selectFor(source, destination)
	if !ok || current.ID != "assignment" || path.ID != "via" {
		t.Fatalf("fallback failed %+v ok=%v", path, ok)
	}
	selector.record("direct", true)
	if _, path, _ := selector.selectFor(source, destination); path.ID != "via" {
		t.Fatalf("switched before recovery threshold: %s", path.ID)
	}
	selector.record("direct", true)
	if _, path, _ := selector.selectFor(source, destination); path.ID != "direct" {
		t.Fatalf("did not recover direct: %s", path.ID)
	}
}

// TestSelectorHonorsCertifiedPrimaryOrder confirms the client never reorders a
// certified assignment: a via-manager primary wins even when a direct fallback
// exists, and the direct fallback is only used once the primary is unusable.
func TestSelectorHonorsCertifiedPrimaryOrder(t *testing.T) {
	selector := newPathSelector(forward.NewTable(model.NetworkState{}, "manager", func(peer.ID, forward.Envelope) error { return nil }))
	source, _ := peer.Decode(peerSource)
	destination, _ := peer.Decode(peerDestination)
	assignmentRecord := assignment()
	assignmentRecord.Primary = model.PathSpec{ID: "via", Kind: model.PathKindViaManager, ManagerHops: []string{"manager"}}
	assignmentRecord.Fallbacks = []model.PathSpec{{ID: "direct", Kind: model.PathKindDirect}}
	selector.replaceAssignments([]model.RouteAssignment{assignmentRecord})

	_, path, ok := selector.selectFor(source, destination)
	if !ok || path.ID != "via" {
		t.Fatalf("certified primary ignored: selected %+v ok=%v", path, ok)
	}
	selector.record("via", false)
	selector.record("via", false)
	if _, path, _ := selector.selectFor(source, destination); path.ID != "direct" {
		t.Fatalf("fallback not used after primary failed: %s", path.ID)
	}
	selector.record("via", true)
	selector.record("via", true)
	if _, path, _ := selector.selectFor(source, destination); path.ID != "via" {
		t.Fatalf("did not recover certified primary: %s", path.ID)
	}
}

// TestSelectorDoesNotFabricateAdmission confirms selection alone never marks a
// path healthy: only real admission results change local usability.
func TestSelectorDoesNotFabricateAdmission(t *testing.T) {
	selector := newPathSelector(forward.NewTable(model.NetworkState{}, "manager", func(peer.ID, forward.Envelope) error { return nil }))
	source, _ := peer.Decode(peerSource)
	destination, _ := peer.Decode(peerDestination)
	selector.replaceAssignments([]model.RouteAssignment{assignment()})

	for index := 0; index < 3; index++ {
		if _, _, ok := selector.selectFor(source, destination); !ok {
			t.Fatal("selection failed")
		}
	}
	if _, exists := selector.admissions["direct"]; exists {
		t.Fatal("selection recorded an admission result")
	}
}

func TestSelectorRejectsUnknownAssignment(t *testing.T) {
	selector := newPathSelector(forward.NewTable(model.NetworkState{}, "manager", func(peer.ID, forward.Envelope) error { return nil }))
	source, _ := peer.Decode(peerSource)
	destination, _ := peer.Decode(peerDestination)
	if _, _, ok := selector.selectFor(source, destination); ok {
		t.Fatal("unknown assignment selected")
	}
}
