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

// This regression covers a cold-start race observed in CI: a follower whose
// round-0 deadline had expired advanced to an idle higher view and rejected
// the leader's round-0 proposal. Only the authenticated proposal may rejoin
// that idle view; readiness acknowledgements themselves must not mutate BFT.
func TestLeaderProposalRecoversIdleAdvancedView(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	state := model.NetworkState{
		NetworkID: "net-cold-start", OverlayCIDR: "100.64.0.0/24", NextIPOffset: 1,
		Groups:    []model.Group{{ID: "clients-a"}},
		SetupKeys: []model.SetupKey{{ID: "key-a", Token: "key-a", TokenHash: model.SetupKeyHash("key-a"), Groups: []string{"clients-a"}}},
	}
	const count = 3
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
		members[index] = model.CommitteeMember{
			ID: string(rune('A' + index)), PeerID: peerID.String(), KeySeed: seed,
			PublicKey: append([]byte(nil), bft.SeededPublicKey(seed)...),
		}
	}

	nodes := make([]*p2p.Node, count)
	engines := make([]*bft.Engine, count)
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
		member.Address = addresses[0]
		members[index] = member
		engine, err := bft.NewEngine(state, members, member.ID, bft.SeededPrivateKey(member.KeySeed))
		if err != nil {
			t.Fatal(err)
		}
		mesh, err := NewCommitteeMesh(node, engine, members)
		if err != nil {
			t.Fatal(err)
		}
		nodes[index], engines[index], meshes[index] = node, engine, mesh
	}

	leaderIndex := -1
	for index, engine := range engines {
		if engine.LocalID() == engine.Leader(1, 0).ID {
			leaderIndex = index
			break
		}
	}
	if leaderIndex < 0 {
		t.Fatal("no height-1 leader")
	}
	followerOne := (leaderIndex + 1) % count
	followerTwo := (leaderIndex + 2) % count

	for index, mesh := range meshes {
		if err := mesh.Connect(ctx); err != nil {
			t.Fatalf("mesh %d connect: %v", index, err)
		}
	}

	// Simulate peers whose round-0 views expired before the leader observed it.
	// Their readiness acknowledgements advertise round one, but cannot move
	// the leader. The leader's signed/authenticated proposal is the authority.
	for _, follower := range []*bft.Engine{engines[followerOne], engines[followerTwo]} {
		if err := follower.SetRoundTimeout(time.Nanosecond); err != nil {
			t.Fatal(err)
		}
		time.Sleep(2 * time.Millisecond)
	}
	engines[followerOne].AdvanceExpiredRound(1)
	engines[followerTwo].AdvanceExpiredRound(1)
	if got := engines[followerOne].CurrentRound(); got != 1 {
		t.Fatalf("stale follower round=%d, want 1", got)
	}

	leaderRound := engines[leaderIndex].CurrentRound()
	if err := meshes[followerOne].send(meshes[leaderIndex].node.Host.ID(), model.CommitteeEnvelope{Type: "ready", Height: 1, Round: 999}); err != nil {
		t.Fatalf("send forged readiness acknowledgement: %v", err)
	}
	time.Sleep(100 * time.Millisecond)
	if got := engines[leaderIndex].CurrentRound(); got != leaderRound {
		t.Fatalf("ready acknowledgement changed leader round from %d to %d", leaderRound, got)
	}

	if _, err := meshes[leaderIndex].Submit(model.StateTransition{Type: bft.TransitionGenesis}); err != nil {
		t.Fatalf("genesis after readiness alignment: %v", err)
	}
	for index, engine := range engines {
		if engine.Height() != 1 {
			t.Fatalf("manager %d height=%d, want 1 (rounds leader=%d stale=%d current=%d)",
				index, engine.Height(), engines[leaderIndex].CurrentRound(), engines[followerOne].CurrentRound(), engines[followerTwo].CurrentRound())
		}
	}
}
