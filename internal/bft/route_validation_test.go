package bft

import (
	"testing"

	"github.com/netp2p/netp2p/internal/model"
)

func TestUpsertRouteRequiresExitNodeGateway(t *testing.T) {
	state := testState()
	route := model.Route{
		ID: "subnet", Destination: "10.10.0.0/16", RoutingGroup: "clients-b",
		DistributionGroup: []string{"clients-a"}, Masquerade: true,
	}
	// clients-b has no exit-node peer yet, so the route must be rejected.
	if err := ApplyTransition(&state, model.StateTransition{Type: TransitionUpsertRoute, Route: &route}); err == nil {
		t.Fatal("route without an exit-node gateway was accepted")
	}

	// Promote a member of clients-b to an exit node and retry.
	state.Peers = append(state.Peers, model.PeerRecord{
		PeerID: "exit-1", OverlayIP: "100.64.0.9", Groups: []string{"clients-b"}, IsExitNode: true,
	})
	state.Groups[1].PeerIDs = []string{"exit-1"}
	if err := ApplyTransition(&state, model.StateTransition{Type: TransitionUpsertRoute, Route: &route}); err != nil {
		t.Fatalf("valid route rejected: %v", err)
	}

	route.Destination = "not-a-cidr"
	if err := ApplyTransition(&state, model.StateTransition{Type: TransitionUpsertRoute, Route: &route}); err == nil {
		t.Fatal("invalid destination was accepted")
	}
}

func TestRegisterPeerCannotBecomeExitNode(t *testing.T) {
	state := testState()
	transition := model.StateTransition{
		Type: TransitionRegisterPeer, SetupKey: "key-a",
		Peer: model.PeerRecord{PeerID: "malicious", IsExitNode: true, Hostname: "malicious"},
	}
	if err := ApplyTransition(&state, transition); err != nil {
		t.Fatalf("registration rejected: %v", err)
	}
	registered := state.Peers[len(state.Peers)-1]
	if registered.PeerID == "malicious" && registered.IsExitNode {
		t.Fatal("register_peer may not grant exit-node capability")
	}
}

func TestUpdatePeerControlsExitNodeCapability(t *testing.T) {
	state := testState()
	apply(t, &state, model.StateTransition{
		Type: TransitionRegisterPeer, SetupKey: "key-a",
		Peer: model.PeerRecord{PeerID: "exit-1", Hostname: "gateway"},
	})
	update := model.StateTransition{
		Type: TransitionUpdatePeer,
		Peer: model.PeerRecord{PeerID: "exit-1", Hostname: "gateway", IsExitNode: true},
	}
	if err := ApplyTransition(&state, update); err != nil {
		t.Fatalf("update peer rejected: %v", err)
	}
	if !state.Peers[0].IsExitNode {
		t.Fatal("update_peer did not grant exit-node capability")
	}
	update.Peer.IsExitNode = false
	if err := ApplyTransition(&state, update); err != nil {
		t.Fatalf("update peer rejected: %v", err)
	}
	if state.Peers[0].IsExitNode {
		t.Fatal("update_peer did not clear exit-node capability")
	}
}

// An admin action that only toggles the exit-node flag must not wipe the
// peer's certified metadata.
func TestUpdatePeerPartialPreservesMetadata(t *testing.T) {
	state := testState()
	apply(t, &state, model.StateTransition{
		Type: TransitionRegisterPeer, SetupKey: "key-a",
		Peer: model.PeerRecord{PeerID: "exit-1", Hostname: "gateway", OS: "linux", ClientVersion: "1.2.3"},
	})
	apply(t, &state, model.StateTransition{
		Type: TransitionUpdatePeer,
		Peer: model.PeerRecord{PeerID: "exit-1", IsExitNode: true},
	})
	peer := state.Peers[0]
	if !peer.IsExitNode {
		t.Fatal("exit-node flag not applied")
	}
	if peer.Hostname != "gateway" || peer.OS != "linux" || peer.ClientVersion != "1.2.3" {
		t.Fatalf("partial update wiped metadata: %+v", peer)
	}
}

func TestRegisterPeerSanitizesPosture(t *testing.T) {
	state := testState()
	apply(t, &state, model.StateTransition{
		Type: TransitionRegisterPeer, SetupKey: "key-a",
		Peer: model.PeerRecord{PeerID: "postured", Hostname: "laptop", Posture: []string{"edr", "disk-encrypted", "edr"}},
	})
	peer := state.Peers[len(state.Peers)-1]
	if len(peer.Posture) != 2 || peer.Posture[0] != "disk-encrypted" || peer.Posture[1] != "edr" {
		t.Fatalf("posture = %v, want deduped and sorted", peer.Posture)
	}

	// Blank labels are rejected rather than silently dropped.
	blank := model.StateTransition{
		Type: TransitionRegisterPeer, SetupKey: "key-a",
		Peer: model.PeerRecord{PeerID: "blank", Posture: []string{"  "}},
	}
	if err := ApplyTransition(&state, blank); err == nil {
		t.Fatal("blank posture label was accepted")
	}
}

func TestUpdatePeerReplacesPosture(t *testing.T) {
	state := testState()
	apply(t, &state, model.StateTransition{
		Type: TransitionRegisterPeer, SetupKey: "key-a",
		Peer: model.PeerRecord{PeerID: "postured", Posture: []string{"edr"}},
	})
	// A nil posture in a metadata refresh must leave the certified labels alone.
	apply(t, &state, model.StateTransition{
		Type: TransitionUpdatePeer,
		Peer: model.PeerRecord{PeerID: "postured", Hostname: "renamed"},
	})
	if len(state.Peers[0].Posture) != 1 || state.Peers[0].Posture[0] != "edr" {
		t.Fatalf("nil posture refreshed to %v, want [edr]", state.Peers[0].Posture)
	}
	// An explicit list replaces the labels.
	apply(t, &state, model.StateTransition{
		Type: TransitionUpdatePeer,
		Peer: model.PeerRecord{PeerID: "postured", Posture: []string{"agentless"}},
	})
	if len(state.Peers[0].Posture) != 1 || state.Peers[0].Posture[0] != "agentless" {
		t.Fatalf("posture = %v, want [agentless]", state.Peers[0].Posture)
	}
}

func TestUpsertRouteValidatesPathTypesAndFlowClass(t *testing.T) {
	state := testState()
	state.Peers = append(state.Peers, model.PeerRecord{
		PeerID: "exit-1", OverlayIP: "100.64.0.9", Groups: []string{"clients-b"}, IsExitNode: true,
	})
	state.Groups[1].PeerIDs = []string{"exit-1"}
	base := model.Route{
		ID: "subnet", Destination: "10.10.0.0/16", RoutingGroup: "clients-b", DistributionGroup: []string{"clients-a"},
	}

	bad := base
	bad.AllowedPathTypes = []string{"teleport"}
	if err := ApplyTransition(&state, model.StateTransition{Type: TransitionUpsertRoute, Route: &bad}); err == nil {
		t.Fatal("unknown allowed path type was accepted")
	}

	bad = base
	bad.FlowClass = "warp"
	if err := ApplyTransition(&state, model.StateTransition{Type: TransitionUpsertRoute, Route: &bad}); err == nil {
		t.Fatal("unknown flow class was accepted")
	}

	bad = base
	bad.Metric = -1
	if err := ApplyTransition(&state, model.StateTransition{Type: TransitionUpsertRoute, Route: &bad}); err == nil {
		t.Fatal("negative metric was accepted")
	}

	good := base
	good.AllowedPathTypes = []string{"direct", "via_manager", "multi-hop"}
	good.FlowClass = "throughput"
	good.Metric = 100
	good.MaxHops = 2
	if err := ApplyTransition(&state, model.StateTransition{Type: TransitionUpsertRoute, Route: &good}); err != nil {
		t.Fatalf("valid route rejected: %v", err)
	}
}
