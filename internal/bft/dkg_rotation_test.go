package bft

import (
	"bytes"
	"crypto/sha256"
	"testing"

	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
	"github.com/netp2p/netp2p/internal/crypto/bls"
	"github.com/netp2p/netp2p/internal/model"
)

// runPedersenDKG simulates the ceremony in-process for a set of member points.
func runPedersenDKG(t *testing.T, threshold int, points []fr.Element) []*bls.DKGResult {
	t.Helper()
	size := len(points)
	states := make([]*bls.DKGState, size)
	for index := range states {
		reader := bytes.NewReader(streamBytes(byte(index)))
		state, err := bls.NewDKGState(threshold, size, index, points, reader)
		if err != nil {
			t.Fatalf("dkg state %d: %v", index, err)
		}
		states[index] = state
	}
	for dealer, state := range states {
		for member, target := range states {
			if err := target.AddCommitments(dealer, state.Commitments()); err != nil {
				t.Fatalf("commitments %d->%d: %v", dealer, member, err)
			}
		}
	}
	for dealer, state := range states {
		for member, target := range states {
			share, err := state.ShareFor(member)
			if err != nil {
				t.Fatalf("share %d->%d: %v", dealer, member, err)
			}
			if err := target.AddShare(dealer, share); err != nil {
				t.Fatalf("accept %d->%d: %v", dealer, member, err)
			}
		}
	}
	results := make([]*bls.DKGResult, size)
	for index, state := range states {
		result, err := state.Finalize()
		if err != nil {
			t.Fatalf("finalize %d: %v", index, err)
		}
		results[index] = result
	}
	return results
}

func streamBytes(tag byte) []byte {
	out := make([]byte, 0, 512)
	for len(out) < 512 {
		digest := sha256.Sum256([]byte{tag, byte(len(out))})
		out = append(out, digest[:]...)
	}
	return out
}

// TestDKGKeyRotation rotates the committee to a DKG-derived group key and
// verifies the committee keeps certifying under the new epoch while the old
// configuration is rejected.
func TestDKGKeyRotation(t *testing.T) {
	committee, keys := legacyCommittee()
	for index := range committee {
		committee[index].PeerID = "peer-" + committee[index].ID
		committee[index].Address = "/ip4/10.0.0.1/udp/1/quic-v1"
		committee[index].ForwardingEnabled = true
	}
	state := testState()
	engines := make([]*Engine, len(committee))
	for index, key := range keys {
		engine, err := NewEngineWithParams(state, committee, committee[index].ID, key, legacyCommitteeParams())
		if err != nil {
			t.Fatal(err)
		}
		engines[index] = engine
	}

	points := make([]fr.Element, len(committee))
	for index := range points {
		points[index] = bls.PointForIdentity(committee[index].ID)
	}
	results := runPedersenDKG(t, legacyCommitteeParams().QuorumSize, points)
	for index, engine := range engines {
		keySet, err := results[index].KeySet(legacyCommitteeParams().QuorumSize, len(committee), index, points)
		if err != nil {
			t.Fatalf("key set %d: %v", index, err)
		}
		engine.SetDKGLoader(func(epoch uint64) (*bls.KeySet, bool) {
			if epoch == 1 {
				return keySet, true
			}
			return nil, false
		})
	}

	rotate := model.StateTransition{
		Type:            TransitionRotateCommittee,
		CommitteeConfig: &model.CommitteeConfig{GroupPublicKey: append([]byte(nil), results[0].GroupPublicKey...)},
	}
	snapshot := advance(t, keys, engines, rotate)
	// The rotation QC itself was signed under the previous epoch.
	if snapshot.QC.CommitteeEpoch != 0 {
		t.Fatalf("rotation QC epoch = %d, want 0", snapshot.QC.CommitteeEpoch)
	}
	for index, engine := range engines {
		if engine.committeeConfig.CommitteeEpoch != 1 {
			t.Fatalf("engine %d epoch = %d, want 1", index, engine.committeeConfig.CommitteeEpoch)
		}
		if !bytes.Equal(engine.committeeConfig.GroupPublicKey, results[0].GroupPublicKey) {
			t.Fatalf("engine %d did not adopt the DKG group key", index)
		}
	}

	// The next height must be certified with the DKG shares at epoch 1.
	next := advance(t, keys, engines, model.StateTransition{
		Type: TransitionRegisterPeer, SetupKey: "key-a", Peer: model.PeerRecord{PeerID: "peer-dkg"},
	})
	if next.QC.CommitteeEpoch != 1 {
		t.Fatalf("post-rotation QC epoch = %d, want 1", next.QC.CommitteeEpoch)
	}
	if err := ValidateSnapshot(next); err != nil {
		t.Fatalf("DKG-certified snapshot rejected: %v", err)
	}

	// A snapshot claiming epoch 0 under the DKG key configuration is invalid.
	stale := next
	stale.QC.CommitteeEpoch = 0
	stale.CommitteeConfig = legacyCommitteeParams().CommitteeConfig(1, results[0].GroupPublicKey)
	if err := ValidateSnapshot(stale); err == nil {
		t.Fatal("epoch-0 QC accepted under a DKG epoch-1 configuration")
	}
}
