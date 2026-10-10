package client

import (
	"errors"
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

func pathSnapshot(directEnabled bool, assignments ...model.RouteAssignment) model.SignedSnapshot {
	return model.SignedSnapshot{State: model.NetworkState{
		NetworkID:   "path-selector-test",
		Settings:    model.NetworkSettings{DirectPathEnabled: directEnabled},
		Assignments: assignments,
	}}
}

func init() {
	if peerDestination == peerSource {
		panic("test peer ids must differ")
	}
}

func TestSelectorPrefersDirectAndFallsBack(t *testing.T) {
	sender := func(peer.ID, forward.Envelope) error { return nil }
	selector := newPathSelector(forward.NewTable(model.NetworkState{}, "manager", sender), nil)
	source, _ := peer.Decode(peerSource)
	destination, _ := peer.Decode(peerDestination)
	assignmentRecord := assignment()
	if err := selector.syncSnapshot(pathSnapshot(true, assignmentRecord)); err != nil {
		t.Fatal(err)
	}

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
	selector := newPathSelector(forward.NewTable(model.NetworkState{}, "manager", func(peer.ID, forward.Envelope) error { return nil }), nil)
	source, _ := peer.Decode(peerSource)
	destination, _ := peer.Decode(peerDestination)
	assignmentRecord := assignment()
	assignmentRecord.Primary = model.PathSpec{ID: "via", Kind: model.PathKindViaManager, ManagerHops: []string{"manager"}}
	assignmentRecord.Fallbacks = []model.PathSpec{{ID: "direct", Kind: model.PathKindDirect}}
	if err := selector.syncSnapshot(pathSnapshot(true, assignmentRecord)); err != nil {
		t.Fatal(err)
	}

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
	selector := newPathSelector(forward.NewTable(model.NetworkState{}, "manager", func(peer.ID, forward.Envelope) error { return nil }), nil)
	source, _ := peer.Decode(peerSource)
	destination, _ := peer.Decode(peerDestination)
	if err := selector.syncSnapshot(pathSnapshot(true, assignment())); err != nil {
		t.Fatal(err)
	}

	for index := 0; index < 3; index++ {
		if _, _, ok := selector.selectFor(source, destination); !ok {
			t.Fatal("selection failed")
		}
	}
	if _, exists := selector.admissions["direct"]; exists {
		t.Fatal("selection recorded an admission result")
	}
}

func TestSelectorRequiresSnapshotSync(t *testing.T) {
	selector := newPathSelector(forward.NewTable(model.NetworkState{}, "manager", func(peer.ID, forward.Envelope) error { return nil }), nil)
	source, _ := peer.Decode(peerSource)
	destination, _ := peer.Decode(peerDestination)
	selector.replaceAssignments([]model.RouteAssignment{assignment()})

	_, _, status := selector.selectWithStatus(source, destination)
	if status.OK || status.State != PathSelectionSyncFailed || !errors.Is(status.Err, ErrPathSyncFailed) {
		t.Fatalf("unsynchronized status = %+v", status)
	}
}

func TestSelectorReportsInvalidSnapshotSync(t *testing.T) {
	selector := newPathSelector(forward.NewTable(model.NetworkState{}, "manager", func(peer.ID, forward.Envelope) error { return nil }), nil)
	source, _ := peer.Decode(peerSource)
	destination, _ := peer.Decode(peerDestination)
	if err := selector.syncSnapshot(model.SignedSnapshot{}); !errors.Is(err, ErrPathSyncFailed) {
		t.Fatalf("sync error = %v", err)
	}
	_, _, status := selector.selectWithStatus(source, destination)
	if status.OK || status.State != PathSelectionSyncFailed || !errors.Is(status.Err, ErrPathSyncFailed) {
		t.Fatalf("invalid snapshot status = %+v", status)
	}
}

func TestSelectorAllowsUnassignedDirectWithValidAddress(t *testing.T) {
	selector := newPathSelector(forward.NewTable(model.NetworkState{}, "manager", func(peer.ID, forward.Envelope) error { return nil }), nil)
	source, _ := peer.Decode(peerSource)
	destination, _ := peer.Decode(peerDestination)
	snapshot := pathSnapshot(true)
	snapshot.State.Peers = []model.PeerRecord{{
		PeerID: peerDestination, Addresses: []string{"/ip4/192.0.2.10/udp/4001/quic-v1"},
	}}
	if err := selector.syncSnapshot(snapshot); err != nil {
		t.Fatal(err)
	}

	assignment, path, status := selector.selectWithStatus(source, destination)
	if !status.OK || status.State != PathSelectionDirect || status.Certified || assignment.ID != "" ||
		path.Kind != model.PathKindDirect || path.ID != "direct" {
		t.Fatalf("unassigned direct status = assignment %+v path %+v status %+v", assignment, path, status)
	}
}

func TestSelectorRejectsUnassignedDirectWhenDirectDisabled(t *testing.T) {
	selector := newPathSelector(forward.NewTable(model.NetworkState{}, "manager", func(peer.ID, forward.Envelope) error { return nil }), nil)
	source, _ := peer.Decode(peerSource)
	destination, _ := peer.Decode(peerDestination)
	snapshot := pathSnapshot(false)
	snapshot.State.Peers = []model.PeerRecord{{
		PeerID: peerDestination, Addresses: []string{"/ip4/192.0.2.10/udp/4001/quic-v1"},
	}}
	if err := selector.syncSnapshot(snapshot); err != nil {
		t.Fatal(err)
	}

	_, _, status := selector.selectWithStatus(source, destination)
	if status.OK || status.State != PathSelectionAssignmentMissing ||
		!errors.Is(status.Err, ErrAssignmentMissing) || !errors.Is(status.Err, ErrDirectPathDisabled) {
		t.Fatalf("disabled direct status = %+v", status)
	}
}

func TestSelectorRejectsUnassignedDirectWithoutValidAddress(t *testing.T) {
	selector := newPathSelector(forward.NewTable(model.NetworkState{}, "manager", func(peer.ID, forward.Envelope) error { return nil }), nil)
	source, _ := peer.Decode(peerSource)
	destination, _ := peer.Decode(peerDestination)
	if err := selector.syncSnapshot(pathSnapshot(true)); err != nil {
		t.Fatal(err)
	}

	_, _, status := selector.selectWithStatus(source, destination)
	if status.OK || status.State != PathSelectionAssignmentMissing ||
		!errors.Is(status.Err, ErrAssignmentMissing) || !errors.Is(status.Err, ErrDirectPeerUnavailable) {
		t.Fatalf("missing address status = %+v", status)
	}
}

func TestSelectorUsesCertifiedViaManagerWhenDirectDisabled(t *testing.T) {
	selector := newPathSelector(forward.NewTable(model.NetworkState{}, "manager", func(peer.ID, forward.Envelope) error { return nil }), nil)
	source, _ := peer.Decode(peerSource)
	destination, _ := peer.Decode(peerDestination)
	assignmentRecord := assignment()
	assignmentRecord.Primary = model.PathSpec{ID: "via", Kind: model.PathKindViaManager, ManagerHops: []string{"manager"}}
	assignmentRecord.Fallbacks = []model.PathSpec{{ID: "direct", Kind: model.PathKindDirect}}
	if err := selector.syncSnapshot(pathSnapshot(false, assignmentRecord)); err != nil {
		t.Fatal(err)
	}

	current, path, status := selector.selectWithStatus(source, destination)
	if !status.OK || !status.Certified || current.ID != "assignment" || path.ID != "via" {
		t.Fatalf("certified via status = current %+v path %+v status %+v", current, path, status)
	}
}

func TestSelectorDoesNotLeaveDirectOnlyAssignmentWhenDirectDisabled(t *testing.T) {
	selector := newPathSelector(forward.NewTable(model.NetworkState{}, "manager", func(peer.ID, forward.Envelope) error { return nil }), nil)
	source, _ := peer.Decode(peerSource)
	destination, _ := peer.Decode(peerDestination)
	assignmentRecord := assignment()
	assignmentRecord.Fallbacks = nil
	if err := selector.syncSnapshot(pathSnapshot(false, assignmentRecord)); err != nil {
		t.Fatal(err)
	}

	_, _, status := selector.selectWithStatus(source, destination)
	if status.OK || status.State != PathSelectionDirectDisabled || !errors.Is(status.Err, ErrDirectPathDisabled) {
		t.Fatalf("direct-only status = %+v", status)
	}
}

func TestSelectorRejectsStaleSnapshot(t *testing.T) {
	selector := newPathSelector(forward.NewTable(model.NetworkState{}, "manager", func(peer.ID, forward.Envelope) error { return nil }), nil)
	source, _ := peer.Decode(peerSource)
	destination, _ := peer.Decode(peerDestination)
	initial := pathSnapshot(true, assignment())
	initial.Height = 2
	if err := selector.syncSnapshot(initial); err != nil {
		t.Fatal(err)
	}
	stale := pathSnapshot(true, assignment())
	stale.Height = 1
	if err := selector.syncSnapshot(stale); !errors.Is(err, ErrPathSyncFailed) {
		t.Fatalf("stale sync error = %v", err)
	}
	_, _, status := selector.selectWithStatus(source, destination)
	if status.OK || status.State != PathSelectionSyncFailed || !errors.Is(status.Err, ErrPathSyncFailed) {
		t.Fatalf("stale status = %+v", status)
	}
}

func TestSelectorRejectsUnknownAssignmentWhenDirectDisabled(t *testing.T) {
	selector := newPathSelector(forward.NewTable(model.NetworkState{}, "manager", func(peer.ID, forward.Envelope) error { return nil }), nil)
	source, _ := peer.Decode(peerSource)
	destination, _ := peer.Decode(peerDestination)
	if err := selector.syncSnapshot(pathSnapshot(false)); err != nil {
		t.Fatal(err)
	}
	if _, _, ok := selector.selectFor(source, destination); ok {
		t.Fatal("unknown assignment selected")
	}
}
