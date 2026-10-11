package bft

import (
	"bytes"
	"crypto/ed25519"
	"strings"
	"testing"

	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
	"github.com/netp2p/netp2p/internal/crypto/bls"
	"github.com/netp2p/netp2p/internal/model"
)

func TestCommitteeTransitionRequiresConfig(t *testing.T) {
	err := validateSnapshotCommitteeTransition(model.SignedSnapshot{
		Transition: model.StateTransition{Type: TransitionActivateCommittee},
	}, model.CommitteeConfig{})
	if err == nil || !strings.Contains(err.Error(), "missing its config") {
		t.Fatalf("missing activation config error = %v", err)
	}
}

func TestCommitteeResizeThreeFourSevenFiveFourWithDKGAndRecovery(t *testing.T) {
	state := testState()
	members := committeeMembersForIDs(t, []string{"A", "B", "C"}, 101)
	keys := committeePrivateKeys(members, 101)
	engines := newCommitteeEngines(t, state, members, keys, model.DefaultCommitteeParams())

	// 3 -> 4: token-discovered D is queued, approved by an admin, then activated
	// only after a new 3-of-4 DKG key set exists.
	submitAndApproveManagerJoin(t, engines, keys, "D", int64('D'))
	fourMembers := committeeMembersForIDs(t, []string{"A", "B", "C", "D"}, 101)
	fourParams := model.CommitteeParams{Size: 4, FaultLimit: 1, QuorumSize: 3}
	fourKeys, fourSnapshot := activateCommitteeWithDKG(t, engines, keys, fourMembers, fourParams, 1)
	engines = append(engines, appendCommitteeEngine(t, fourSnapshot, fourMembers, fourParams, fourKeys, "D", int64('D'), 1))
	keys = append(keys, SeededPrivateKey(int64('D')))
	assertCommitteeParams(t, engines, fourParams, fourSnapshot)

	// 4 -> 7: three more managers join and the committee moves to 5-of-7.
	for _, id := range []string{"E", "F", "G"} {
		seed := int64(id[0])
		submitAndApproveManagerJoin(t, engines, keys, id, seed)
	}
	sevenMembers := committeeMembersForIDs(t, []string{"A", "B", "C", "D", "E", "F", "G"}, 101)
	sevenParams := model.CommitteeParams{Size: 7, FaultLimit: 2, QuorumSize: 5}
	sevenKeys, sevenSnapshot := activateCommitteeWithDKG(t, engines, keys, sevenMembers, sevenParams, 2)
	for _, id := range []string{"E", "F", "G"} {
		engines = append(engines, appendCommitteeEngine(t, sevenSnapshot, sevenMembers, sevenParams, sevenKeys, id, int64(id[0]), 2))
		keys = append(keys, SeededPrivateKey(int64(id[0])))
	}
	assertCommitteeParams(t, engines, sevenParams, sevenSnapshot)

	// 7 -> 5 -> 4: shrink through valid BFT parameter transitions. Each step
	// rotates to a fresh DKG key set so removed managers cannot sign later
	// heights with old shares.
	fiveMembers := committeeMembersForIDs(t, []string{"A", "C", "D", "E", "G"}, 101)
	fiveParams := model.CommitteeParams{Size: 5, FaultLimit: 1, QuorumSize: 4}
	_, fiveSnapshot := activateCommitteeWithDKG(t, engines, keys, fiveMembers, fiveParams, 3)
	engines, keys = retainCommitteeEngines(engines, keys, fiveMembers)
	assertCommitteeParams(t, engines, fiveParams, fiveSnapshot)

	fourMembers = committeeMembersForIDs(t, []string{"A", "C", "E", "G"}, 101)
	fourParams = model.CommitteeParams{Size: 4, FaultLimit: 1, QuorumSize: 3}
	finalKeys, finalSnapshot := activateCommitteeWithDKG(t, engines, keys, fourMembers, fourParams, 4)
	engines, keys = retainCommitteeEngines(engines, keys, fourMembers)
	assertCommitteeParams(t, engines, fourParams, finalSnapshot)

	final := advance(t, keys, engines, model.StateTransition{
		Type: TransitionRegisterPeer, SetupKey: "key-a",
		Peer: model.PeerRecord{PeerID: "peer-after-resize"},
	})
	if err := ValidateSnapshot(final); err != nil {
		t.Fatalf("validate final 4-manager snapshot: %v", err)
	}

	// Recovery starts four fresh engines from the certified state and DKG
	// shares, catches up to the final snapshot, and certifies another height.
	recoveredEngines := make([]*Engine, len(fourMembers))
	recoveredKeys := make([]ed25519.PrivateKey, len(fourMembers))
	for index, member := range fourMembers {
		engine, err := NewEngineWithKeySet(
			final.State, fourMembers, member.ID, SeededPrivateKey(int64(member.ID[0])),
			fourParams, finalKeys[member.ID], 4,
		)
		if err != nil {
			t.Fatalf("create recovered engine %s: %v", member.ID, err)
		}
		if err := engine.CatchUp(final); err != nil {
			t.Fatalf("recover engine %s: %v", member.ID, err)
		}
		recoveredEngines[index] = engine
		recoveredKeys[index] = SeededPrivateKey(int64(member.ID[0]))
	}
	recovered := advance(t, recoveredKeys, recoveredEngines, model.StateTransition{
		Type: TransitionUpsertGroup, Group: &model.Group{ID: "recovered"},
	})
	if recovered.Height != final.Height+1 {
		t.Fatalf("recovered height = %d, want %d", recovered.Height, final.Height+1)
	}
	if err := ValidateSnapshot(recovered); err != nil {
		t.Fatalf("validate recovered snapshot: %v", err)
	}
}

func committeeMembersForIDs(t *testing.T, ids []string, firstSeed int64) []model.CommitteeMember {
	t.Helper()
	members := make([]model.CommitteeMember, len(ids))
	for index, id := range ids {
		seed := firstSeed + int64(index)
		if len(id) == 1 {
			seed = int64(id[0])
		}
		members[index] = model.CommitteeMember{
			ID: id, PeerID: "peer-" + id,
			Address:   "/dns4/manager-" + id + "/udp/4001/quic-v1",
			PublicKey: SeededPublicKey(seed), ForwardingEnabled: true,
		}
	}
	return members
}

func itoa(value int) string {
	if value == 0 {
		return "0"
	}
	digits := []byte{}
	for value > 0 {
		digits = append([]byte{byte('0' + value%10)}, digits...)
		value /= 10
	}
	return string(digits)
}

func committeePrivateKeys(members []model.CommitteeMember, firstSeed int64) []ed25519.PrivateKey {
	keys := make([]ed25519.PrivateKey, len(members))
	for index := range members {
		seed := firstSeed + int64(index)
		if len(members[index].ID) == 1 {
			seed = int64(members[index].ID[0])
		}
		keys[index] = SeededPrivateKey(seed)
	}
	return keys
}

func newCommitteeEngines(
	t *testing.T, state model.NetworkState, members []model.CommitteeMember,
	keys []ed25519.PrivateKey, params model.CommitteeParams,
) []*Engine {
	t.Helper()
	engines := make([]*Engine, len(members))
	for index := range members {
		engine, err := NewEngineWithParams(state, members, members[index].ID, keys[index], params)
		if err != nil {
			t.Fatalf("create engine %s: %v", members[index].ID, err)
		}
		engines[index] = engine
	}
	return engines
}

func submitAndApproveManagerJoin(
	t *testing.T, engines []*Engine, keys []ed25519.PrivateKey, id string, seed int64,
) {
	t.Helper()
	request := model.ManagerJoinRequest{
		ID: "join-" + id, ManagerID: id, PeerID: "peer-" + id,
		Address:   "/dns4/manager-" + id + "/udp/4001/quic-v1",
		PublicKey: SeededPublicKey(seed), RequestedAt: "2026-10-11T00:00:00Z",
		Status: model.ManagerJoinPending,
	}
	advance(t, keys, engines, model.StateTransition{
		Type: TransitionSubmitManagerJoin, ManagerJoin: &request,
	})
	request.Status = model.ManagerJoinApproved
	request.ReviewedBy = "owner@example.com"
	request.ReviewedAt = "2026-10-11T00:01:00Z"
	advance(t, keys, engines, model.StateTransition{
		Type: TransitionReviewManagerJoin, ManagerJoin: &request,
		Actor: &model.Actor{ID: "owner", Role: model.RoleOwner},
	})
}

func activateCommitteeWithDKG(
	t *testing.T, engines []*Engine, keys []ed25519.PrivateKey,
	target []model.CommitteeMember, params model.CommitteeParams, epoch uint64,
) (map[string]*bls.KeySet, model.SignedSnapshot) {
	t.Helper()
	points := make([]fr.Element, len(target))
	for index := range target {
		points[index] = bls.PointForIdentity(target[index].ID)
	}
	results := runPedersenDKG(t, params.QuorumSize, points)
	keySets := make(map[string]*bls.KeySet, len(target))
	for index, result := range results {
		keySet, err := result.KeySet(params.QuorumSize, params.Size, index, points)
		if err != nil {
			t.Fatalf("build DKG key set for %s: %v", target[index].ID, err)
		}
		keySets[target[index].ID] = keySet
	}
	for _, engine := range engines {
		engine.SetDKGLoader(func(wantEpoch uint64, committee []model.CommitteeMember, params model.CommitteeParams) (*bls.KeySet, bool) {
			if wantEpoch != epoch {
				return nil, false
			}
			_ = committee
			_ = params
			keySet, ok := keySets[engine.LocalID()]
			return keySet, ok
		})
	}
	config := params.CommitteeConfig(epoch, results[0].GroupPublicKey)
	snapshot := advanceActivation(t, keys, engines, target, model.StateTransition{
		Type: TransitionActivateCommittee, Committee: target, CommitteeConfig: &config,
		Actor: &model.Actor{ID: "owner", Role: model.RoleOwner},
	})
	if err := ValidateSnapshot(snapshot); err != nil {
		t.Fatalf("validate activation to %d managers: %v", params.Size, err)
	}
	return keySets, snapshot
}

func advanceActivation(
	t *testing.T, keys []ed25519.PrivateKey, engines []*Engine,
	target []model.CommitteeMember, transition model.StateTransition,
) model.SignedSnapshot {
	t.Helper()
	targetIDs := make(map[string]struct{}, len(target))
	for _, member := range target {
		targetIDs[member.ID] = struct{}{}
	}
	height := engines[0].Height() + 1
	leader := engines[0].Leader(height, 0)
	var leaderEngine *Engine
	for _, engine := range engines {
		if engine.LocalID() == leader.ID {
			leaderEngine = engine
			break
		}
	}
	if leaderEngine == nil {
		t.Fatalf("activation leader %s not found", leader.ID)
	}
	proposal, localVote, err := leaderEngine.Propose(transition, 0)
	if err != nil {
		t.Fatalf("propose activation: %v", err)
	}
	if _, _, err := leaderEngine.ProcessVote(localVote); err != nil {
		t.Fatalf("leader activation vote: %v", err)
	}
	var quorum model.QuorumCertificate
	ready := false
	for _, engine := range engines {
		if engine.LocalID() == leader.ID {
			continue
		}
		vote, err := engine.ProcessProposal(proposal)
		if err != nil {
			t.Fatalf("activation vote on %s: %v", engine.LocalID(), err)
		}
		quorum, ready, err = leaderEngine.ProcessVote(vote)
		if err != nil {
			t.Fatalf("process activation vote from %s: %v", vote.VoterID, err)
		}
		if ready {
			break
		}
	}
	if !ready {
		t.Fatal("activation quorum not reached")
	}
	var snapshot model.SignedSnapshot
	for _, engine := range engines {
		if _, retained := targetIDs[engine.LocalID()]; !retained {
			continue
		}
		committed, err := engine.Commit(proposal, quorum)
		if err != nil {
			t.Fatalf("commit activation on %s: %v", engine.LocalID(), err)
		}
		if snapshot.Height == 0 {
			snapshot = committed
		} else if !bytes.Equal(snapshot.StateHash, committed.StateHash) {
			t.Fatal("activation committed state fork")
		}
	}
	return snapshot
}

func appendCommitteeEngine(
	t *testing.T, snapshot model.SignedSnapshot, members []model.CommitteeMember,
	params model.CommitteeParams, keySets map[string]*bls.KeySet, id string,
	seed int64, epoch uint64,
) *Engine {
	t.Helper()
	privateKey := SeededPrivateKey(seed)
	engine, err := NewEngineWithKeySet(
		snapshot.State, members, id, privateKey, params, keySets[id], epoch,
	)
	if err != nil {
		t.Fatalf("create activated engine %s: %v", id, err)
	}
	engine.height = snapshot.Height
	engine.committed[snapshot.Height] = snapshot
	return engine
}

func retainCommitteeEngines(
	engines []*Engine, keys []ed25519.PrivateKey, members []model.CommitteeMember,
) ([]*Engine, []ed25519.PrivateKey) {
	keep := make(map[string]struct{}, len(members))
	for _, member := range members {
		keep[member.ID] = struct{}{}
	}
	keptEngines := make([]*Engine, 0, len(members))
	keptKeys := make([]ed25519.PrivateKey, 0, len(members))
	for index, engine := range engines {
		if _, exists := keep[engine.LocalID()]; exists {
			keptEngines = append(keptEngines, engine)
			keptKeys = append(keptKeys, keys[index])
		}
	}
	return keptEngines, keptKeys
}

func assertCommitteeParams(
	t *testing.T, engines []*Engine, params model.CommitteeParams, snapshot model.SignedSnapshot,
) {
	t.Helper()
	for _, engine := range engines {
		if engine.CommitteeParams() != params {
			t.Fatalf("engine %s params = %+v, want %+v", engine.LocalID(), engine.CommitteeParams(), params)
		}
	}
	stateParams, err := model.CommitteeParamsFromConfig(snapshot.State.CommitteeConfig)
	if err != nil {
		t.Fatalf("state committee params: %v", err)
	}
	if stateParams != params {
		t.Fatalf("state params = %+v, want %+v", stateParams, params)
	}
	if !bytes.Equal(snapshot.State.CommitteeConfig.GroupPublicKey, snapshot.Transition.CommitteeConfig.GroupPublicKey) {
		t.Fatal("activated state did not carry the DKG group key")
	}
}
