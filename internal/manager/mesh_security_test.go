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
	"github.com/netp2p/netp2p/internal/wire"
)

func TestStateUpdateRejectsNonCommitteeForwarding(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	state := model.NetworkState{
		NetworkID: "net-security", OverlayCIDR: "100.64.0.0/24",
		CommitteeConfig: model.CommitteeConfig{Threshold: 3, Size: 4},
	}
	members := make([]model.CommitteeMember, 4)
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
			ID: string(rune('A' + index)), PeerID: peerID.String(), KeySeed: seed,
		}
	}

	managerNode, err := p2p.New(ctx, p2p.Config{IdentitySeed: members[0].KeySeed})
	if err != nil {
		t.Fatal(err)
	}
	defer managerNode.Close()
	members[0].Address = managerNode.Addresses()[0]
	engine, err := bft.NewEngine(state, members, members[0].ID, bft.SeededPrivateKey(members[0].KeySeed))
	if err != nil {
		t.Fatal(err)
	}
	_, err = NewCommitteeMesh(managerNode, engine, members)
	if err != nil {
		t.Fatal(err)
	}

	attacker, err := p2p.New(ctx, p2p.Config{})
	if err != nil {
		t.Fatal(err)
	}
	defer attacker.Close()
	target, err := peer.AddrInfoFromString(members[0].Address)
	if err != nil {
		t.Fatal(err)
	}
	if err := attacker.Host.Connect(ctx, *target); err != nil {
		t.Fatal(err)
	}

	transition := model.StateTransition{Type: bft.TransitionGenesis}
	message := model.CommitteeEnvelope{Type: "forward", Transition: &transition}
	if err := attacker.Send(ctx, managerNode.Host.ID(), p2p.StateUpdateProtocol, wire.CommitteeEnvelopeToProto(message)); err != nil {
		t.Fatal(err)
	}

	deadline := time.Now().Add(300 * time.Millisecond)
	for time.Now().Before(deadline) {
		if _, ok := engine.Proposal(1); ok {
			t.Fatal("non-committee peer forwarded an unauthenticated transition")
		}
		time.Sleep(10 * time.Millisecond)
	}
	if _, ok := engine.Proposal(1); ok {
		t.Fatal("non-committee peer forwarded an unauthenticated transition")
	}
}
