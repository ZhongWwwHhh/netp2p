package bft

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"sort"
	"testing"

	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
	"github.com/netp2p/netp2p/internal/crypto/bls"
	"github.com/netp2p/netp2p/internal/model"
)

func TestNewEngineWithKeySetUsesInitialDKGMaterial(t *testing.T) {
	ids := []string{"fr", "sg", "us-phx"}
	sort.Strings(ids)
	points := make([]fr.Element, len(ids))
	for index, id := range ids {
		points[index] = bls.PointForIdentity(id)
	}
	states := make([]*bls.DKGState, len(ids))
	results := make([]*bls.DKGResult, len(ids))
	for index := range ids {
		state, err := bls.NewDKGState(3, 3, index, points, nil)
		if err != nil {
			t.Fatal(err)
		}
		states[index] = state
		if err := state.AddCommitments(index, state.Commitments()); err != nil {
			t.Fatal(err)
		}
	}
	for dealer := range ids {
		for recipient := range ids {
			if err := states[recipient].AddCommitments(dealer, states[dealer].Commitments()); err != nil {
				t.Fatal(err)
			}
			share, err := states[dealer].ShareFor(recipient)
			if err != nil {
				t.Fatal(err)
			}
			if err := states[recipient].AddShare(dealer, share); err != nil {
				t.Fatal(err)
			}
		}
	}
	for index := range ids {
		result, err := states[index].Finalize()
		if err != nil {
			t.Fatal(err)
		}
		results[index] = result
		if !bytes.Equal(result.GroupPublicKey, results[0].GroupPublicKey) {
			t.Fatal("members computed different DKG group keys")
		}
	}

	keys, err := results[0].KeySet(3, 3, 0, points)
	if err != nil {
		t.Fatal(err)
	}
	committee := make([]model.CommitteeMember, len(ids))
	var localPrivateKey ed25519.PrivateKey
	for index, id := range ids {
		_, privateKey, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		committee[index] = model.CommitteeMember{
			ID: id, PublicKey: []byte("public-key-" + id), Address: "/ip4/127.0.0.1/udp/4001/quic-v1",
		}
		if id == ids[0] {
			localPrivateKey = privateKey
		}
	}
	engine, err := NewEngineWithKeySet(
		model.NetworkState{NetworkID: "dkg", OverlayCIDR: "100.64.0.0/24"},
		committee, ids[0], localPrivateKey, model.DefaultCommitteeParams(), keys, 1,
	)
	if err != nil {
		t.Fatalf("NewEngineWithKeySet: %v", err)
	}
	config := engine.CurrentState().CommitteeConfig
	if !bytes.Equal(config.GroupPublicKey, results[0].GroupPublicKey) {
		t.Fatal("engine did not adopt the DKG group key")
	}
	if config.Threshold != 3 || config.Size != 3 || config.CommitteeEpoch != 1 {
		t.Fatalf("committee config = %+v", config)
	}
}
