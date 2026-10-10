package bft

import (
	"testing"

	"github.com/netp2p/netp2p/internal/model"
)

func TestDefaultCommitteeParamsAreThreeZeroThree(t *testing.T) {
	params := model.DefaultCommitteeParams()
	if params.Size != 3 || params.FaultLimit != 0 || params.QuorumSize != 3 {
		t.Fatalf("default committee params = %+v, want 3/0/3", params)
	}
	if CommitteeSize != 3 || FaultLimit != 0 || QuorumSize != 3 {
		t.Fatalf("compatibility constants = %d/%d/%d, want 3/0/3", CommitteeSize, FaultLimit, QuorumSize)
	}
}

func TestInvalidCommitteeParamsAreRejected(t *testing.T) {
	invalid := []model.CommitteeParams{
		{Size: 0, FaultLimit: 0, QuorumSize: 0},
		{Size: 3, FaultLimit: -1, QuorumSize: 4},
		{Size: 3, FaultLimit: 0, QuorumSize: 2},
		{Size: 3, FaultLimit: 1, QuorumSize: 2},
		{Size: 4, FaultLimit: 2, QuorumSize: 2},
	}
	for _, params := range invalid {
		if err := params.Validate(); err == nil {
			t.Fatalf("invalid params accepted: %+v", params)
		}
	}
}

func TestNewEngineWithParamsRejectsCommitteeMismatch(t *testing.T) {
	committee, keys := testCommittee()
	state := testState()
	params := model.CommitteeParams{Size: 4, FaultLimit: 0, QuorumSize: 4}
	if _, err := NewEngineWithParams(state, committee, committee[0].ID, keys[0], params); err == nil {
		t.Fatal("engine accepted a committee size that does not match CommitteeParams")
	}
}

func TestSnapshotRejectsAuthenticityViolations(t *testing.T) {
	committee, keys := testCommittee()
	state := testState()
	engines := make([]*Engine, len(committee))
	for index, key := range keys {
		engine, err := NewEngine(state, committee, committee[index].ID, key)
		if err != nil {
			t.Fatal(err)
		}
		engines[index] = engine
	}
	valid := advance(t, keys, engines, model.StateTransition{
		Type: TransitionRegisterPeer, SetupKey: "key-a",
		Peer: model.PeerRecord{PeerID: "peer-a"},
	})
	if err := ValidateSnapshot(valid); err != nil {
		t.Fatalf("valid snapshot rejected: %v", err)
	}

	cases := []struct {
		name   string
		mutate func(snapshot *model.SignedSnapshot)
	}{
		{
			name: "committee count mismatch",
			mutate: func(snapshot *model.SignedSnapshot) {
				snapshot.Committee = append(snapshot.Committee, model.CommitteeMember{ID: "extra"})
			},
		},
		{
			name: "signer bit out of range",
			mutate: func(snapshot *model.SignedSnapshot) {
				snapshot.QC.SignerBitmap[0] |= 1 << 3
			},
		},
		{
			name: "insufficient signers",
			mutate: func(snapshot *model.SignedSnapshot) {
				snapshot.QC.SignerBitmap = []byte{0b00000011}
			},
		},
		{
			name: "outer and state committee config mismatch",
			mutate: func(snapshot *model.SignedSnapshot) {
				snapshot.State.CommitteeConfig.Threshold++
			},
		},
		{
			name: "missing group public key",
			mutate: func(snapshot *model.SignedSnapshot) {
				snapshot.CommitteeConfig.GroupPublicKey = nil
				snapshot.State.CommitteeConfig.GroupPublicKey = nil
			},
		},
		{
			name: "QC state hash mismatch",
			mutate: func(snapshot *model.SignedSnapshot) {
				snapshot.QC.StateHash[0] ^= 1
			},
		},
		{
			name: "invalid aggregate signature",
			mutate: func(snapshot *model.SignedSnapshot) {
				snapshot.QC.AggregateSignature[0] ^= 1
			},
		},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			invalid := valid
			testCase.mutate(&invalid)
			if err := ValidateSnapshot(invalid); err == nil {
				t.Fatalf("%s accepted", testCase.name)
			}
		})
	}
}
