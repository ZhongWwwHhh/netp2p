package manager

import (
	"context"
	"testing"
	"time"

	"github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/netp2p/netp2p/internal/bft"
	"github.com/netp2p/netp2p/internal/model"
	"github.com/netp2p/netp2p/internal/p2p"
)

func TestFourManagerMeshRegistersPeer(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	state := model.NetworkState{
		NetworkID:    "net-test",
		OverlayCIDR:  "100.64.0.0/24",
		NextIPOffset: 1,
		Groups:       []model.Group{{ID: "clients-a"}, {ID: "clients-b"}},
		SetupKeys: []model.SetupKey{
			{ID: "key-a", Token: "key-a", TokenHash: model.SetupKeyHash("key-a"), Groups: []string{"clients-a"}},
			{ID: "key-b", Token: "key-b", TokenHash: model.SetupKeyHash("key-b"), Groups: []string{"clients-b"}},
		},
		Policies: []model.Policy{{
			ID: "allow-a-to-b", SourceGroups: []string{"clients-a"}, DestinationGroups: []string{"clients-b"},
			Services: []model.Service{{Protocol: "icmp"}}, Effect: model.EffectAllow,
		}},
	}

	const count = 4
	members := make([]model.CommitteeMember, count)
	for index := range members {
		seed := int64(index + 101)
		privateKey := bft.SeededPrivateKey(seed)
		libp2pKey, _, err := crypto.KeyPairFromStdKey(&privateKey)
		if err != nil {
			t.Fatal(err)
		}
		peerID, err := peer.IDFromPrivateKey(libp2pKey)
		if err != nil {
			t.Fatal(err)
		}
		members[index] = model.CommitteeMember{
			ID:      string(rune('A' + index)),
			PeerID:  peerID.String(),
			KeySeed: seed,
		}
	}

	nodes := make([]*p2p.Node, count)
	engines := make([]*bft.Engine, count)
	meshes := make([]*CommitteeMesh, count)
	managers := make([]*Manager, count)
	for index, member := range members {
		node, err := p2p.New(ctx, p2p.Config{IdentitySeed: member.KeySeed})
		if err != nil {
			t.Fatal(err)
		}
		defer node.Close()
		addresses := node.Addresses()
		if len(addresses) == 0 {
			t.Fatal("manager has no addresses")
		}
		members[index].Address = addresses[0]
		privateKey := bft.SeededPrivateKey(member.KeySeed)
		engine, err := bft.NewEngine(state, members, member.ID, privateKey)
		if err != nil {
			t.Fatal(err)
		}
		mesh, err := NewCommitteeMesh(node, engine, members)
		if err != nil {
			t.Fatal(err)
		}
		nodes[index] = node
		engines[index] = engine
		meshes[index] = mesh
		managers[index] = New(node, engine, mesh, Config{})
	}

	for index, mesh := range meshes {
		if err := mesh.Connect(ctx); err != nil {
			t.Fatalf("mesh %d connect: %v", index, err)
		}
	}

	// Submit through a non-leader manager to exercise proposal forwarding.
	if _, err := meshes[0].Submit(model.StateTransition{Type: bft.TransitionGenesis}); err != nil {
		t.Fatalf("genesis submit: %v", err)
	}
	snapshot, peerRecord, err := managers[0].Register(Registration{SetupKey: "key-a", PeerID: "peer-a"})
	if err != nil {
		t.Fatal(err)
	}
	if peerRecord.OverlayIP == "" || len(snapshot.State.Peers) != 1 {
		t.Fatalf("unexpected registration: peer=%+v peers=%+v", peerRecord, snapshot.State.Peers)
	}
	deadline := time.Now().Add(3 * time.Second)
	for _, engine := range engines {
		for engine.Height() < 2 && time.Now().Before(deadline) {
			time.Sleep(10 * time.Millisecond)
		}
		if engine.Height() != 2 {
			t.Fatalf("manager %s height=%d, want 2", engine.Leader(0, 0).ID, engine.Height())
		}
	}

	// An admin may promote the peer to an exit node; a later routine metadata
	// refresh must not silently clear that capability.
	if _, err := managers[0].Submit(model.StateTransition{
		Type: bft.TransitionUpdatePeer,
		Peer: model.PeerRecord{PeerID: "peer-a", IsExitNode: true},
	}); err != nil {
		t.Fatalf("promote exit node: %v", err)
	}
	refreshed, updated, err := managers[0].Register(Registration{SetupKey: "key-a", PeerID: "peer-a", Hostname: "renamed"})
	if err != nil {
		t.Fatalf("metadata refresh: %v", err)
	}
	if !updated.IsExitNode {
		t.Fatal("metadata refresh cleared the exit-node capability")
	}
	if !findPeer(refreshed, "peer-a").IsExitNode {
		t.Fatal("certified state lost the exit-node capability after a refresh")
	}
}

func findEngineLeader(engines []*bft.Engine, height uint64) int {
	leaderID := engines[0].Leader(height, 0).ID
	for index := range engines {
		if engines[index].LocalID() == leaderID {
			return index
		}
	}
	return -1
}

// TestQuorumSurvivesSingleManagerFailure stops one manager and verifies the
// remaining three can still certify a new registration.
func TestQuorumSurvivesSingleManagerFailure(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	state := model.NetworkState{
		NetworkID:    "net-test",
		OverlayCIDR:  "100.64.0.0/24",
		NextIPOffset: 1,
		Groups:       []model.Group{{ID: "clients-a"}},
		SetupKeys:    []model.SetupKey{{ID: "key-a", Token: "key-a", TokenHash: model.SetupKeyHash("key-a"), Groups: []string{"clients-a"}}},
	}

	const count = 4
	members := make([]model.CommitteeMember, count)
	for index := range members {
		seed := int64(index + 101)
		privateKey := bft.SeededPrivateKey(seed)
		libp2pKey, _, err := crypto.KeyPairFromStdKey(&privateKey)
		if err != nil {
			t.Fatal(err)
		}
		peerID, err := peer.IDFromPrivateKey(libp2pKey)
		if err != nil {
			t.Fatal(err)
		}
		members[index] = model.CommitteeMember{ID: string(rune('A' + index)), PeerID: peerID.String(), KeySeed: seed}
	}

	engines := make([]*bft.Engine, count)
	meshes := make([]*CommitteeMesh, count)
	nodes := make([]*p2p.Node, count)
	for index, member := range members {
		node, err := p2p.New(ctx, p2p.Config{IdentitySeed: member.KeySeed})
		if err != nil {
			t.Fatal(err)
		}
		defer node.Close()
		addresses := node.Addresses()
		if len(addresses) == 0 {
			t.Fatal("manager has no addresses")
		}
		members[index].Address = addresses[0]
		engine, err := bft.NewEngine(state, members, member.ID, bft.SeededPrivateKey(member.KeySeed))
		if err != nil {
			t.Fatal(err)
		}
		mesh, err := NewCommitteeMesh(node, engine, members)
		if err != nil {
			t.Fatal(err)
		}
		nodes[index] = node
		engines[index] = engine
		meshes[index] = mesh
	}
	for index, mesh := range meshes {
		if err := mesh.Connect(ctx); err != nil {
			t.Fatalf("mesh %d connect: %v", index, err)
		}
	}
	if _, err := meshes[0].Submit(model.StateTransition{Type: bft.TransitionGenesis}); err != nil {
		t.Fatalf("genesis submit: %v", err)
	}

	// Take down the last committee member; height-2 quorum only needs three.
	_ = nodes[3].Close()

	transition := model.StateTransition{Type: bft.TransitionRegisterPeer, SetupKey: "key-a", Peer: model.PeerRecord{PeerID: "peer-a"}}
	if _, err := meshes[0].Submit(transition); err != nil {
		t.Fatalf("submit with one manager down: %v", err)
	}
	for index := 0; index < 3; index++ {
		if engines[index].Height() != 2 {
			t.Fatalf("manager %d height=%d, want 2", index, engines[index].Height())
		}
	}
}

// TestSubmitWithLeaderDown verifies that when the round-0 leader for the next
// height is stopped, Submit rotates to the next round's leader and commits.
func TestSubmitWithLeaderDown(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	state := model.NetworkState{
		NetworkID:    "net-test",
		OverlayCIDR:  "100.64.0.0/24",
		NextIPOffset: 1,
		Groups:       []model.Group{{ID: "clients-a"}},
		SetupKeys:    []model.SetupKey{{ID: "key-a", Token: "key-a", TokenHash: model.SetupKeyHash("key-a"), Groups: []string{"clients-a"}}},
	}

	const count = 4
	members := make([]model.CommitteeMember, count)
	for index := range members {
		seed := int64(index + 101)
		privateKey := bft.SeededPrivateKey(seed)
		libp2pKey, _, err := crypto.KeyPairFromStdKey(&privateKey)
		if err != nil {
			t.Fatal(err)
		}
		peerID, err := peer.IDFromPrivateKey(libp2pKey)
		if err != nil {
			t.Fatal(err)
		}
		members[index] = model.CommitteeMember{ID: string(rune('A' + index)), PeerID: peerID.String(), KeySeed: seed}
	}

	engines := make([]*bft.Engine, count)
	meshes := make([]*CommitteeMesh, count)
	nodes := make([]*p2p.Node, count)
	for index, member := range members {
		node, err := p2p.New(ctx, p2p.Config{IdentitySeed: member.KeySeed})
		if err != nil {
			t.Fatal(err)
		}
		defer node.Close()
		addresses := node.Addresses()
		if len(addresses) == 0 {
			t.Fatal("manager has no addresses")
		}
		members[index].Address = addresses[0]
		engine, err := bft.NewEngine(state, members, member.ID, bft.SeededPrivateKey(member.KeySeed))
		if err != nil {
			t.Fatal(err)
		}
		mesh, err := NewCommitteeMesh(node, engine, members)
		if err != nil {
			t.Fatal(err)
		}
		nodes[index] = node
		engines[index] = engine
		meshes[index] = mesh
	}
	for index, mesh := range meshes {
		if err := mesh.Connect(ctx); err != nil {
			t.Fatalf("mesh %d connect: %v", index, err)
		}
	}
	if _, err := meshes[0].Submit(model.StateTransition{Type: bft.TransitionGenesis}); err != nil {
		t.Fatalf("genesis: %v", err)
	}

	// Height 2 leader: committee sorted [A,B,C,D]; (2)%4 = B. Stop B.
	nextLeader := engines[0].Leader(2, 0).ID
	leaderNode := -1
	for index := range engines {
		if engines[index].LocalID() == nextLeader {
			leaderNode = index
		}
	}
	if leaderNode < 0 {
		t.Fatal("next leader not found")
	}
	_ = nodes[leaderNode].Close()

	// Submit through a non-dead, non-leader manager to test round rotation.
	submitter := -1
	for index := range meshes {
		if index != leaderNode {
			submitter = index
			break
		}
	}
	transition := model.StateTransition{Type: bft.TransitionRegisterPeer, SetupKey: "key-a", Peer: model.PeerRecord{PeerID: "peer-a"}}
	snapshot, err := meshes[submitter].Submit(transition)
	if err != nil {
		t.Fatalf("submit with round-0 leader down: %v", err)
	}
	if snapshot.Height != 2 {
		t.Fatalf("snapshot height %d, want 2", snapshot.Height)
	}
}

// TestSubmitRejectsInvalidTransition verifies that a transition which cannot
// apply against the committed state fails fast with the real reason instead of
// exhausting every committee round and reporting a consensus timeout.
func TestSubmitRejectsInvalidTransition(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	state := model.NetworkState{
		NetworkID:    "net-test",
		OverlayCIDR:  "100.64.0.0/24",
		NextIPOffset: 1,
		Groups:       []model.Group{{ID: "clients-a"}},
	}

	const count = 4
	members := make([]model.CommitteeMember, count)
	for index := range members {
		seed := int64(index + 201)
		privateKey := bft.SeededPrivateKey(seed)
		libp2pKey, _, err := crypto.KeyPairFromStdKey(&privateKey)
		if err != nil {
			t.Fatal(err)
		}
		peerID, err := peer.IDFromPrivateKey(libp2pKey)
		if err != nil {
			t.Fatal(err)
		}
		members[index] = model.CommitteeMember{ID: string(rune('A' + index)), PeerID: peerID.String(), KeySeed: seed}
	}

	meshes := make([]*CommitteeMesh, count)
	for index, member := range members {
		node, err := p2p.New(ctx, p2p.Config{IdentitySeed: member.KeySeed})
		if err != nil {
			t.Fatal(err)
		}
		defer node.Close()
		addresses := node.Addresses()
		if len(addresses) == 0 {
			t.Fatal("manager has no addresses")
		}
		members[index].Address = addresses[0]
		engine, err := bft.NewEngine(state, members, member.ID, bft.SeededPrivateKey(member.KeySeed))
		if err != nil {
			t.Fatal(err)
		}
		mesh, err := NewCommitteeMesh(node, engine, members)
		if err != nil {
			t.Fatal(err)
		}
		meshes[index] = mesh
	}
	for index, mesh := range meshes {
		if err := mesh.Connect(ctx); err != nil {
			t.Fatalf("mesh %d connect: %v", index, err)
		}
	}
	if _, err := meshes[0].Submit(model.StateTransition{Type: bft.TransitionGenesis}); err != nil {
		t.Fatalf("genesis: %v", err)
	}

	start := time.Now()
	_, err := meshes[0].Submit(model.StateTransition{Type: bft.TransitionRemoveGroup, TargetID: "does-not-exist"})
	if err == nil {
		t.Fatal("expected invalid transition to be rejected")
	}
	if elapsed := time.Since(start); elapsed > 3*time.Second {
		t.Fatalf("invalid transition took %s, want fast rejection", elapsed)
	}
	if want := `group "does-not-exist" not found`; err.Error() != want {
		t.Fatalf("error %q, want %q", err.Error(), want)
	}
}

// TestAdminSubmitRoundTrip verifies the admin CLI path end to end: a token
// authenticated transition over AdminProtocol is committed and the certified
// snapshot comes back to the caller.
func TestAdminSubmitRoundTrip(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	state := model.NetworkState{
		NetworkID:    "net-test",
		OverlayCIDR:  "100.64.0.0/24",
		NextIPOffset: 1,
	}

	const count = 4
	members := make([]model.CommitteeMember, count)
	for index := range members {
		seed := int64(index + 301)
		privateKey := bft.SeededPrivateKey(seed)
		libp2pKey, _, err := crypto.KeyPairFromStdKey(&privateKey)
		if err != nil {
			t.Fatal(err)
		}
		peerID, err := peer.IDFromPrivateKey(libp2pKey)
		if err != nil {
			t.Fatal(err)
		}
		members[index] = model.CommitteeMember{ID: string(rune('A' + index)), PeerID: peerID.String(), KeySeed: seed}
	}

	meshes := make([]*CommitteeMesh, count)
	nodes := make([]*p2p.Node, count)
	for index, member := range members {
		node, err := p2p.New(ctx, p2p.Config{IdentitySeed: member.KeySeed})
		if err != nil {
			t.Fatal(err)
		}
		defer node.Close()
		addresses := node.Addresses()
		if len(addresses) == 0 {
			t.Fatal("manager has no addresses")
		}
		members[index].Address = addresses[0]
		engine, err := bft.NewEngine(state, members, member.ID, bft.SeededPrivateKey(member.KeySeed))
		if err != nil {
			t.Fatal(err)
		}
		mesh, err := NewCommitteeMesh(node, engine, members)
		if err != nil {
			t.Fatal(err)
		}
		RegisterAdminHandler(node, mesh, "test-token")
		meshes[index] = mesh
		nodes[index] = node
	}
	for index, mesh := range meshes {
		if err := mesh.Connect(ctx); err != nil {
			t.Fatalf("mesh %d connect: %v", index, err)
		}
	}
	if _, err := meshes[0].Submit(model.StateTransition{Type: bft.TransitionGenesis}); err != nil {
		t.Fatalf("genesis: %v", err)
	}

	adminNode, err := p2p.New(ctx, p2p.Config{Listen: []string{"/ip4/127.0.0.1/udp/0/quic-v1"}})
	if err != nil {
		t.Fatal(err)
	}
	defer adminNode.Close()
	if err := adminNode.Host.Connect(ctx, peer.AddrInfo{ID: nodes[0].Host.ID(), Addrs: nodes[0].Host.Addrs()}); err != nil {
		t.Fatalf("connect admin node: %v", err)
	}

	group := model.Group{ID: "admin-group"}
	snapshot, err := SubmitAdmin(ctx, adminNode, nodes[0].Host.ID(), "test-token", model.StateTransition{Type: bft.TransitionUpsertGroup, Group: &group})
	if err != nil {
		t.Fatalf("submit admin group: %v", err)
	}
	if snapshot.Height != 2 {
		t.Fatalf("snapshot height %d, want 2", snapshot.Height)
	}
	if _, err := SubmitAdmin(ctx, adminNode, nodes[0].Host.ID(), "wrong-token", model.StateTransition{Type: bft.TransitionRemoveGroup, TargetID: "admin-group"}); err == nil {
		t.Fatal("expected wrong token to be rejected")
	}
}
