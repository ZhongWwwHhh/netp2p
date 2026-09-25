package bft

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"strings"
	"testing"

	"github.com/netp2p/netp2p/internal/model"
)

func testCommittee() ([]model.CommitteeMember, []ed25519.PrivateKey) {
	members := make([]model.CommitteeMember, CommitteeSize)
	privateKeys := make([]ed25519.PrivateKey, CommitteeSize)
	for index := range members {
		seed := int64(index + 1)
		privateKeys[index] = SeededPrivateKey(seed)
		members[index] = model.CommitteeMember{
			ID:        string(rune('A' + index)),
			KeySeed:   seed,
			PeerID:    "",
			Address:   "",
			PublicKey: append([]byte(nil), SeededPublicKey(seed)...),
		}
	}
	return members, privateKeys
}

func testState() model.NetworkState {
	return model.NetworkState{
		NetworkID:    "net-1",
		OverlayCIDR:  "100.64.0.0/24",
		NextIPOffset: 1,
		Groups:       []model.Group{{ID: "clients-a"}, {ID: "clients-b"}},
		SetupKeys: []model.SetupKey{
			{ID: "key-a", Token: "key-a", TokenHash: model.SetupKeyHash("key-a"), Groups: []string{"clients-a"}},
			{ID: "key-b", Token: "key-b", TokenHash: model.SetupKeyHash("key-b"), Groups: []string{"clients-b"}},
		},
		Policies: []model.Policy{{
			ID: "a-to-b", SourceGroups: []string{"clients-a"}, DestinationGroups: []string{"clients-b"},
			Services: []model.Service{{Protocol: "icmp"}}, Effect: model.EffectAllow, Direction: model.DirectionUnidirectional,
		}},
	}
}

func advance(t *testing.T, privateKeys []ed25519.PrivateKey, engines []*Engine, transition model.StateTransition) model.SignedSnapshot {
	t.Helper()
	leaderIndex := int((engines[0].Height() + 1) % CommitteeSize)
	proposal, leaderVote, err := engines[leaderIndex].Propose(transition, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := engines[leaderIndex].ProcessVote(leaderVote); err != nil {
		t.Fatal(err)
	}
	var qc model.QuorumCertificate
	ready := false
	for index, engine := range engines {
		if index == leaderIndex {
			continue
		}
		vote, err := engine.ProcessProposal(proposal)
		if err != nil {
			t.Fatal(err)
		}
		qc, ready, err = engines[leaderIndex].ProcessVote(vote)
		if err != nil {
			t.Fatal(err)
		}
		if ready {
			break
		}
	}
	if !ready {
		t.Fatal("quorum not reached")
	}
	var snapshot model.SignedSnapshot
	for _, engine := range engines {
		committed, err := engine.Commit(proposal, qc)
		if err != nil {
			t.Fatal(err)
		}
		if snapshot.Height == 0 {
			snapshot = committed
		} else if !bytes.Equal(snapshot.StateHash, committed.StateHash) {
			t.Fatal("committed state fork")
		}
	}
	return snapshot
}

func TestCanonicalHashAndQuorumCommit(t *testing.T) {
	state := testState()
	first := StateHash(state)
	second := StateHash(testState())
	if !bytes.Equal(first, second) {
		t.Fatal("equivalent states produced different hashes")
	}

	committee, privateKeys := testCommittee()
	engines := make([]*Engine, CommitteeSize)
	for index, key := range privateKeys {
		engine, err := NewEngine(state, committee, committee[index].ID, key)
		if err != nil {
			t.Fatal(err)
		}
		engines[index] = engine
	}
	snapshot := advance(t, privateKeys, engines, model.StateTransition{
		Type: TransitionRegisterPeer, SetupKey: "key-a",
		Peer: model.PeerRecord{PeerID: "peer-a"},
	})
	if snapshot.Height != 1 || len(snapshot.State.Peers) != 1 || snapshot.State.Peers[0].OverlayIP == "" {
		t.Fatalf("unexpected snapshot: %+v", snapshot)
	}
	if err := ValidateSnapshot(snapshot); err != nil {
		t.Fatal(err)
	}
}

func TestRejectTamperedSnapshot(t *testing.T) {
	committee, privateKeys := testCommittee()
	state := testState()
	engines := make([]*Engine, CommitteeSize)
	for index, key := range privateKeys {
		engine, err := NewEngine(state, committee, committee[index].ID, key)
		if err != nil {
			t.Fatal(err)
		}
		engines[index] = engine
	}
	snapshot := advance(t, privateKeys, engines, model.StateTransition{
		Type: TransitionRegisterPeer, SetupKey: "key-a", Peer: model.PeerRecord{PeerID: "peer-a"},
	})
	snapshot.State.Policies[0].ID = "changed"
	if err := ValidateSnapshot(snapshot); err == nil {
		t.Fatal("tampered snapshot accepted")
	}
}

// TestQuorumToleratesOneOfflineManager verifies n=4, f=1: three live managers
// (leader plus two voters) are enough to certify state without the fourth.
func TestQuorumToleratesOneOfflineManager(t *testing.T) {
	committee, privateKeys := testCommittee()
	state := testState()
	engines := make([]*Engine, CommitteeSize)
	for index, key := range privateKeys {
		engine, err := NewEngine(state, committee, committee[index].ID, key)
		if err != nil {
			t.Fatal(err)
		}
		engines[index] = engine
	}

	online := []int{0, 1, 2}
	leaderIndex := -1
	leaderID := engines[0].Leader(1, 0).ID
	for _, index := range online {
		if engines[index].LocalID() == leaderID {
			leaderIndex = index
		}
	}
	if leaderIndex < 0 {
		t.Fatal("leader must be online")
	}
	proposal, leaderVote, err := engines[leaderIndex].Propose(model.StateTransition{
		Type: TransitionRegisterPeer, SetupKey: "key-a", Peer: model.PeerRecord{PeerID: "peer-a"},
	}, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := engines[leaderIndex].ProcessVote(leaderVote); err != nil {
		t.Fatal(err)
	}
	var qc model.QuorumCertificate
	ready := false
	for _, index := range online {
		if index == leaderIndex {
			continue
		}
		vote, err := engines[index].ProcessProposal(proposal)
		if err != nil {
			t.Fatal(err)
		}
		qc, ready, err = engines[leaderIndex].ProcessVote(vote)
		if err != nil {
			t.Fatal(err)
		}
	}
	if !ready {
		t.Fatal("three live managers should reach quorum")
	}
	snapshot, err := engines[leaderIndex].Commit(proposal, qc)
	if err != nil {
		t.Fatal(err)
	}
	if err := ValidateSnapshot(snapshot); err != nil {
		t.Fatal(err)
	}
}

// TestRejectInsufficientQuorum rejects a certificate signed by only two
// managers, which is below the 2f+1 threshold.
func TestRejectInsufficientQuorum(t *testing.T) {
	committee, privateKeys := testCommittee()
	state := testState()
	engines := make([]*Engine, CommitteeSize)
	for index, key := range privateKeys {
		engine, err := NewEngine(state, committee, committee[index].ID, key)
		if err != nil {
			t.Fatal(err)
		}
		engines[index] = engine
	}
	snapshot := advance(t, privateKeys, engines, model.StateTransition{
		Type: TransitionRegisterPeer, SetupKey: "key-a", Peer: model.PeerRecord{PeerID: "peer-a"},
	})
	// Rebuild the certificate with only two partial signatures: below the 3-of-4
	// threshold, so it must not verify against the group public key.
	message := voteMessage(Vote{
		Height: snapshot.QC.Height, Round: snapshot.QC.Round, NetworkID: snapshot.State.NetworkID,
		StateHash: snapshot.QC.StateHash, TransitionHash: snapshot.QC.TransitionHash,
		CommitteeEpoch: snapshot.QC.CommitteeEpoch,
	})
	partials := map[int][]byte{}
	for _, index := range []int{0, 1} {
		signature, err := engines[0].blsKeys.SignShare(index, message)
		if err != nil {
			t.Fatal(err)
		}
		partials[index] = signature
	}
	aggregate, err := engines[0].blsKeys.Aggregate(partials)
	if err != nil {
		t.Fatal(err)
	}
	snapshot.QC.AggregateSignature = aggregate
	snapshot.QC.SignerBitmap = []byte{0b00000011}
	if err := ValidateSnapshot(snapshot); err == nil {
		t.Fatal("insufficient quorum accepted")
	}
}

// TestRejectInvalidVoteSignature ensures a forged or corrupted vote never
// contributes to a quorum certificate.
func TestRejectInvalidVoteSignature(t *testing.T) {
	committee, privateKeys := testCommittee()
	state := testState()
	engines := make([]*Engine, CommitteeSize)
	for index, key := range privateKeys {
		engine, err := NewEngine(state, committee, committee[index].ID, key)
		if err != nil {
			t.Fatal(err)
		}
		engines[index] = engine
	}
	leaderIndex := -1
	leaderID := engines[0].Leader(1, 0).ID
	for index := range engines {
		if engines[index].LocalID() == leaderID {
			leaderIndex = index
		}
	}
	proposal, _, err := engines[leaderIndex].Propose(model.StateTransition{
		Type: TransitionRegisterPeer, SetupKey: "key-a", Peer: model.PeerRecord{PeerID: "peer-a"},
	}, 0)
	if err != nil {
		t.Fatal(err)
	}
	follower := (leaderIndex + 1) % CommitteeSize
	vote, err := engines[follower].ProcessProposal(proposal)
	if err != nil {
		t.Fatal(err)
	}
	vote.Signature = append([]byte(nil), vote.Signature...)
	vote.Signature[0] ^= 0xff
	if _, _, err := engines[leaderIndex].ProcessVote(vote); err == nil {
		t.Fatal("forged vote accepted")
	}
}

// TestRegisterPeerAllocatesAddressesAndGroups verifies sequential overlay IP
// allocation and that a setup key materializes group membership.
func TestRegisterPeerAllocatesAddressesAndGroups(t *testing.T) {
	state := testState()
	state.SetupKeys = append(state.SetupKeys, model.SetupKey{ID: "key-ab", Token: "key-ab", TokenHash: model.SetupKeyHash("key-ab"), Groups: []string{"clients-a", "clients-b"}})
	if err := ApplyTransition(&state, model.StateTransition{Type: TransitionRegisterPeer, SetupKey: "key-a", Peer: model.PeerRecord{PeerID: "peer-1"}}); err != nil {
		t.Fatal(err)
	}
	if err := ApplyTransition(&state, model.StateTransition{Type: TransitionRegisterPeer, SetupKey: "key-ab", Peer: model.PeerRecord{PeerID: "peer-2"}}); err != nil {
		t.Fatal(err)
	}
	if len(state.Peers) != 2 {
		t.Fatalf("expected 2 peers, got %d", len(state.Peers))
	}
	if state.Peers[0].OverlayIP != "100.64.0.1" || state.Peers[1].OverlayIP != "100.64.0.2" {
		t.Fatalf("unexpected addresses: %q %q", state.Peers[0].OverlayIP, state.Peers[1].OverlayIP)
	}
	if len(state.Peers[1].Groups) != 2 {
		t.Fatalf("expected peer-2 in two groups, got %v", state.Peers[1].Groups)
	}
	for _, peerID := range []string{"peer-1", "peer-2"} {
		members := map[string]bool{}
		for _, group := range state.Groups {
			for _, id := range group.PeerIDs {
				if id == peerID {
					members[group.ID] = true
				}
			}
		}
		if peerID == "peer-1" && !members["clients-a"] {
			t.Fatalf("peer-1 missing from clients-a: %v", members)
		}
		if peerID == "peer-2" && (!members["clients-a"] || !members["clients-b"]) {
			t.Fatalf("peer-2 group expansion wrong: %v", members)
		}
	}
	if err := ApplyTransition(&state, model.StateTransition{Type: TransitionRegisterPeer, SetupKey: "missing", Peer: model.PeerRecord{PeerID: "peer-3"}}); err == nil {
		t.Fatal("unknown setup key accepted")
	}
	if err := ApplyTransition(&state, model.StateTransition{Type: TransitionRegisterPeer, SetupKey: "key-a", Peer: model.PeerRecord{PeerID: "peer-1"}}); err == nil {
		t.Fatal("duplicate peer registration accepted")
	}
}

// TestCatchUpCommitsCertifiedSnapshot verifies that a manager which missed a
// proposal can advance directly from a valid peer snapshot.
func TestCatchUpCommitsCertifiedSnapshot(t *testing.T) {
	committee, privateKeys := testCommittee()
	state := testState()
	engines := make([]*Engine, CommitteeSize)
	for index, key := range privateKeys {
		engine, err := NewEngine(state, committee, committee[index].ID, key)
		if err != nil {
			t.Fatal(err)
		}
		engines[index] = engine
	}
	// Three engines commit height 1; the fourth misses it entirely.
	snapshot := advanceSubset(t, privateKeys, engines, []int{0, 1, 2}, model.StateTransition{
		Type: TransitionRegisterPeer, SetupKey: "key-a", Peer: model.PeerRecord{PeerID: "peer-a"},
	})
	lagging := engines[3]
	if lagging.Height() != 0 {
		t.Fatalf("lagging engine should still be at height 0, got %d", lagging.Height())
	}
	if err := lagging.CatchUp(snapshot); err != nil {
		t.Fatalf("catch-up: %v", err)
	}
	if lagging.Height() != 1 {
		t.Fatalf("lagging engine height %d, want 1", lagging.Height())
	}
	if len(lagging.CurrentState().Peers) != 1 {
		t.Fatalf("lagging engine did not adopt the peer: %+v", lagging.CurrentState().Peers)
	}
	if err := lagging.CatchUp(snapshot); err == nil {
		t.Fatal("stale catch-up accepted")
	}
	// Tampered snapshot must be rejected.
	tampered := snapshot
	tampered.State.Peers[0].OverlayIP = "1.2.3.4"
	if err := lagging.CatchUp(tampered); err == nil {
		t.Fatal("tampered snapshot accepted by CatchUp")
	}
}

// advanceSubset commits a height using only the listed engine indices, leaving
// the rest of the committee unaware.
func advanceSubset(t *testing.T, privateKeys []ed25519.PrivateKey, engines []*Engine, online []int, transition model.StateTransition) model.SignedSnapshot {
	t.Helper()
	leaderIndex := -1
	leaderID := engines[0].Leader(1, 0).ID
	for _, index := range online {
		if engines[index].LocalID() == leaderID {
			leaderIndex = index
		}
	}
	if leaderIndex < 0 {
		t.Fatal("leader must be online")
	}
	proposal, leaderVote, err := engines[leaderIndex].Propose(transition, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := engines[leaderIndex].ProcessVote(leaderVote); err != nil {
		t.Fatal(err)
	}
	var qc model.QuorumCertificate
	ready := false
	for _, index := range online {
		if index == leaderIndex {
			continue
		}
		vote, err := engines[index].ProcessProposal(proposal)
		if err != nil {
			t.Fatal(err)
		}
		qc, ready, err = engines[leaderIndex].ProcessVote(vote)
		if err != nil {
			t.Fatal(err)
		}
	}
	if !ready {
		t.Fatal("subset quorum not reached")
	}
	snapshot, err := engines[leaderIndex].Commit(proposal, qc)
	if err != nil {
		t.Fatal(err)
	}
	return snapshot
}

func TestSnapshotAndLatestSnapshot(t *testing.T) {
	committee, privateKeys := testCommittee()
	state := testState()
	engines := make([]*Engine, CommitteeSize)
	for index, key := range privateKeys {
		engine, err := NewEngine(state, committee, committee[index].ID, key)
		if err != nil {
			t.Fatal(err)
		}
		engines[index] = engine
	}
	if _, ok := engines[0].LatestSnapshot(); ok {
		t.Fatal("empty engine should have no latest snapshot")
	}
	if _, ok := engines[0].Snapshot(1); ok {
		t.Fatal("empty engine should not have height 1")
	}
	advance(t, privateKeys, engines, model.StateTransition{
		Type: TransitionRegisterPeer, SetupKey: "key-a", Peer: model.PeerRecord{PeerID: "peer-a"},
	})
	latest, ok := engines[0].LatestSnapshot()
	if !ok || latest.Height != 1 {
		t.Fatalf("latest snapshot height %d ok=%v, want 1 true", latest.Height, ok)
	}
	byHeight, ok := engines[0].Snapshot(1)
	if !ok || !bytes.Equal(byHeight.StateHash, latest.StateHash) {
		t.Fatalf("snapshot(1) mismatch: ok=%v hashEq=%v", ok, bytes.Equal(byHeight.StateHash, latest.StateHash))
	}
	if _, ok := engines[0].Snapshot(99); ok {
		t.Fatal("snapshot(99) should not exist")
	}
}

// TestAdminTransitions verifies every upsert/remove operation in the
// ApplyTransition switch.
func TestAdminTransitions(t *testing.T) {
	state := testState()
	// Upsert existing group.
	if err := ApplyTransition(&state, model.StateTransition{Type: TransitionUpsertGroup, Group: &model.Group{ID: "clients-a", UserIDs: []string{"alice"}}}); err != nil {
		t.Fatal(err)
	}
	// New group.
	if err := ApplyTransition(&state, model.StateTransition{Type: TransitionUpsertGroup, Group: &model.Group{ID: "clients-c"}}); err != nil {
		t.Fatal(err)
	}
	// Remove group.
	if err := ApplyTransition(&state, model.StateTransition{Type: TransitionRemoveGroup, TargetID: "clients-c"}); err != nil {
		t.Fatal(err)
	}
	// Policy upsert and remove.
	policy := model.Policy{ID: "block-c", Effect: model.EffectDeny, SourceGroups: []string{"clients-a"}, DestinationGroups: []string{"clients-b"}}
	if err := ApplyTransition(&state, model.StateTransition{Type: TransitionUpsertPolicy, Policy: &policy}); err != nil {
		t.Fatal(err)
	}
	if len(state.Policies) != 2 {
		t.Fatalf("expected 2 policies, got %d", len(state.Policies))
	}
	if err := ApplyTransition(&state, model.StateTransition{Type: TransitionRemovePolicy, TargetID: "block-c"}); err != nil {
		t.Fatal(err)
	}
	if len(state.Policies) != 1 {
		t.Fatalf("expected 1 policy after remove, got %d", len(state.Policies))
	}
	// Setup key upsert and remove.
	record := model.SetupKey{ID: "key-c", Token: "key-c", TokenHash: model.SetupKeyHash("key-c"), Groups: []string{"clients-a"}}
	if err := ApplyTransition(&state, model.StateTransition{Type: TransitionUpsertSetupKey, Record: &record}); err != nil {
		t.Fatal(err)
	}
	if len(state.SetupKeys) != 3 {
		t.Fatalf("expected 3 setup keys, got %d", len(state.SetupKeys))
	}
	if err := ApplyTransition(&state, model.StateTransition{Type: TransitionRemoveSetupKey, TargetID: "key-c"}); err != nil {
		t.Fatal(err)
	}
	// Route upsert/remove.
	route := model.Route{ID: "route-x", Destination: "10.0.0.0/8"}
	if err := ApplyTransition(&state, model.StateTransition{Type: TransitionUpsertRoute, Route: &route}); err != nil {
		t.Fatal(err)
	}
	if err := ApplyTransition(&state, model.StateTransition{Type: TransitionRemoveRoute, TargetID: "route-x"}); err != nil {
		t.Fatal(err)
	}
	// Budget upsert/remove.
	budget := model.TrafficBudget{ID: "budget-x", DailyBytes: 100}
	if err := ApplyTransition(&state, model.StateTransition{Type: TransitionUpsertBudget, Budget: &budget}); err != nil {
		t.Fatal(err)
	}
	if err := ApplyTransition(&state, model.StateTransition{Type: TransitionRemoveBudget, TargetID: "budget-x"}); err != nil {
		t.Fatal(err)
	}
	// Missing records.
	if err := ApplyTransition(&state, model.StateTransition{Type: TransitionRemoveGroup, TargetID: "nope"}); err == nil {
		t.Fatal("removing missing group should fail")
	}
	if err := ApplyTransition(&state, model.StateTransition{Type: TransitionRemovePolicy, TargetID: "nope"}); err == nil {
		t.Fatal("removing missing policy should fail")
	}
	if err := ApplyTransition(&state, model.StateTransition{Type: TransitionRemoveSetupKey, TargetID: "nope"}); err == nil {
		t.Fatal("removing missing setup key should fail")
	}
	// Nil records.
	if err := ApplyTransition(&state, model.StateTransition{Type: TransitionUpsertGroup}); err == nil {
		t.Fatal("upsert group without record should fail")
	}
	if err := ApplyTransition(&state, model.StateTransition{Type: TransitionUpsertPolicy}); err == nil {
		t.Fatal("upsert policy without record should fail")
	}
	if err := ApplyTransition(&state, model.StateTransition{Type: TransitionUpsertSetupKey}); err == nil {
		t.Fatal("upsert setup key without record should fail")
	}
}

func TestNormalizeStateEmitsEmptyArrays(t *testing.T) {
	state := model.NetworkState{NetworkID: "net-1", OverlayCIDR: "100.64.0.0/24"}
	encoded, err := json.Marshal(NormalizeState(state))
	if err != nil {
		t.Fatal(err)
	}
	for _, field := range []string{"\"peers\"", "\"groups\"", "\"policies\"", "\"routes\"", "\"budgets\"", "\"setupKeys\""} {
		if !strings.Contains(string(encoded), field+":[]") {
			t.Fatalf("expected %s to serialize as an empty array, got %s", field, encoded)
		}
	}
}

func TestDNSAndPeerTransitions(t *testing.T) {
	state := testState()
	state.Nameservers = nil
	state.Zones = nil

	nameserver := model.Nameserver{
		ID: "ns-1", Name: "corp", Groups: []string{"clients-a"},
		Servers: []string{"1.1.1.1"}, Enabled: true,
	}
	if err := ApplyTransition(&state, model.StateTransition{Type: TransitionUpsertNS, Nameserver: &nameserver}); err != nil {
		t.Fatalf("upsert nameserver: %v", err)
	}
	if len(state.Nameservers) != 1 || state.Nameservers[0].ID != "ns-1" {
		t.Fatalf("nameserver not applied: %+v", state.Nameservers)
	}

	unknownGroup := nameserver
	unknownGroup.ID = "ns-2"
	unknownGroup.Groups = []string{"ghost"}
	if err := ApplyTransition(&state, model.StateTransition{Type: TransitionUpsertNS, Nameserver: &unknownGroup}); err == nil {
		t.Fatal("nameserver referencing an unknown group should fail")
	}

	zone := model.DNSZone{
		ID: "zone-1", Domain: "internal.example", Groups: []string{"clients-b"},
		Records: []model.DNSRecord{{Name: "api", Type: "A", Value: "100.64.0.1"}}, Enabled: true,
	}
	if err := ApplyTransition(&state, model.StateTransition{Type: TransitionUpsertZone, Zone: &zone}); err != nil {
		t.Fatalf("upsert zone: %v", err)
	}
	missingDomain := zone
	missingDomain.ID = "zone-2"
	missingDomain.Domain = ""
	if err := ApplyTransition(&state, model.StateTransition{Type: TransitionUpsertZone, Zone: &missingDomain}); err == nil {
		t.Fatal("zone without a domain should fail")
	}

	if err := ApplyTransition(&state, model.StateTransition{Type: TransitionUpdateDNS, DNSSettings: &model.DNSSettings{Groups: []string{"clients-a"}}}); err != nil {
		t.Fatalf("update dns settings: %v", err)
	}
	if err := ApplyTransition(&state, model.StateTransition{Type: TransitionUpdateDNS, DNSSettings: &model.DNSSettings{Disabled: true, Groups: []string{"ghost"}}}); err == nil {
		t.Fatal("dns settings referencing an unknown group should fail")
	}
	if err := ApplyTransition(&state, model.StateTransition{Type: TransitionRemoveNS, TargetID: "nope"}); err == nil {
		t.Fatal("removing a missing nameserver should fail")
	}
	if err := ApplyTransition(&state, model.StateTransition{Type: TransitionRemoveZone, TargetID: "nope"}); err == nil {
		t.Fatal("removing a missing zone should fail")
	}
}

func TestUpdatePeerOnlyChangesMetadata(t *testing.T) {
	state := testState()
	state.Peers = []model.PeerRecord{{PeerID: "peer-a", OverlayIP: "100.64.0.11", Groups: []string{"clients-a"}}}

	transition := model.StateTransition{
		Type: TransitionUpdatePeer,
		Peer: model.PeerRecord{PeerID: "peer-a", Hostname: "laptop", OS: "linux", ClientVersion: "0.2.0"},
	}
	if err := ApplyTransition(&state, transition); err != nil {
		t.Fatalf("update peer: %v", err)
	}
	peer := state.Peers[0]
	if peer.Hostname != "laptop" || peer.OS != "linux" || peer.ClientVersion != "0.2.0" {
		t.Fatalf("metadata not applied: %+v", peer)
	}
	if peer.OverlayIP != "100.64.0.11" || len(peer.Groups) != 1 {
		t.Fatalf("overlay ip/groups must not change: %+v", peer)
	}

	if err := ApplyTransition(&state, model.StateTransition{Type: TransitionUpdatePeer, Peer: model.PeerRecord{PeerID: "peer-a", OverlayIP: "100.64.0.99"}}); err == nil {
		t.Fatal("client must not be able to choose its overlay ip")
	}
	if err := ApplyTransition(&state, model.StateTransition{Type: TransitionUpdatePeer, Peer: model.PeerRecord{PeerID: "ghost"}}); err == nil {
		t.Fatal("updating an unregistered peer should fail")
	}
}

func TestValidateSnapshotRejectsTamperedTransition(t *testing.T) {
	committee, _ := testCommittee()

	// Commit a real registration so we hold a valid QC covering a transition.
	state := testState()
	engines := make([]*Engine, len(committee))
	for index := range committee {
		engine, err := NewEngine(state, committee, committee[index].ID, SeededPrivateKey(committee[index].KeySeed))
		if err != nil {
			t.Fatal(err)
		}
		engines[index] = engine
	}
	transition := model.StateTransition{Type: TransitionUpsertGroup, Group: &model.Group{ID: "extra"}}
	var snapshot model.SignedSnapshot
	for round := uint64(0); round < CommitteeSize; round++ {
		leader := engines[0].Leader(1, round).ID
		var leaderEngine *Engine
		for index, member := range committee {
			if member.ID == leader {
				leaderEngine = engines[index]
			}
		}
		proposal, leaderVote, err := leaderEngine.Propose(transition, round)
		if err != nil {
			continue
		}

		// Every member must first see the proposal, then vote on it, which is
		// exactly how the mesh relays messages in production.
		votes := []Vote{leaderVote}
		for _, engine := range engines {
			if engine.LocalID() == leader {
				continue
			}
			vote, err := engine.ProcessProposal(proposal)
			if err != nil {
				t.Fatalf("process proposal: %v", err)
			}
			votes = append(votes, vote)
		}

		var qc model.QuorumCertificate
		ready := false
		for _, engine := range engines {
			for _, vote := range votes {
				processed, ok, err := engine.ProcessVote(vote)
				if err != nil {
					t.Fatal(err)
				}
				if ok {
					qc, ready = processed, true
				}
			}
		}
		if !ready {
			continue
		}
		committed, err := engines[0].Commit(proposal, qc)
		if err != nil {
			t.Fatal(err)
		}
		snapshot = committed
		goto validated
	}
	t.Fatal("could not commit a transition")

validated:
	if err := ValidateSnapshot(snapshot); err != nil {
		t.Fatalf("freshly committed snapshot should validate: %v", err)
	}

	// Rewriting the decision log must invalidate the certificate.
	tampered := snapshot
	tampered.Transition = model.StateTransition{Type: TransitionUpsertGroup, Group: &model.Group{ID: "forged"}}
	if err := ValidateSnapshot(tampered); err == nil {
		t.Fatal("a rewritten transition must not validate")
	}

	// A snapshot claiming the wrong leader must not validate either.
	wrongLeader := snapshot
	wrongLeader.LeaderID = "not-the-leader"
	if err := ValidateSnapshot(wrongLeader); err == nil {
		t.Fatal("a snapshot with the wrong leader must not validate")
	}
}

// TestTransitionHashCoversActor proves the audit identity is part of the signed
// transition: two transitions that differ only in their actor must hash
// differently, and rewriting the actor in a committed snapshot must invalidate
// the certificate.
func TestTransitionHashCoversActor(t *testing.T) {
	base := model.StateTransition{Type: TransitionUpsertGroup, Group: &model.Group{ID: "g"}}
	withActor := base
	withActor.Actor = &model.Actor{ID: "user-1", Name: "Ada", Role: model.RoleAdmin}
	otherActor := base
	otherActor.Actor = &model.Actor{ID: "user-2", Name: "Bob", Role: model.RoleOwner}

	if bytes.Equal(TransitionHash(base), TransitionHash(withActor)) {
		t.Fatal("adding an actor did not change the transition hash")
	}
	if bytes.Equal(TransitionHash(withActor), TransitionHash(otherActor)) {
		t.Fatal("different actors produced the same transition hash")
	}

	committee, privateKeys := testCommittee()
	engines := make([]*Engine, len(committee))
	for index := range committee {
		engine, err := NewEngine(testState(), committee, committee[index].ID, privateKeys[index])
		if err != nil {
			t.Fatal(err)
		}
		engines[index] = engine
	}
	transition := model.StateTransition{
		Type: TransitionUpsertGroup, Group: &model.Group{ID: "audited"},
		Actor: &model.Actor{ID: "user-1", Name: "Ada", Role: model.RoleAdmin},
	}
	snapshot := advance(t, privateKeys, engines, transition)
	if err := ValidateSnapshot(snapshot); err != nil {
		t.Fatalf("freshly committed snapshot should validate: %v", err)
	}
	if snapshot.Transition.Actor == nil || snapshot.Transition.Actor.ID != "user-1" {
		t.Fatalf("committed snapshot lost its actor: %#v", snapshot.Transition.Actor)
	}

	forged := snapshot
	forged.Transition.Actor = &model.Actor{ID: "attacker", Role: model.RoleOwner}
	if err := ValidateSnapshot(forged); err == nil {
		t.Fatal("a forged actor must invalidate the snapshot")
	}
}

func TestAllocateDNSLabelIsUniqueAndDeterministic(t *testing.T) {
	state := model.NetworkState{
		Peers: []model.PeerRecord{
			{PeerID: "a", DNSLabel: "web"},
			{PeerID: "b", DNSLabel: "web-2"},
		},
	}
	if got := allocateDNSLabel(state, "web"); got != "web-3" {
		t.Fatalf("label = %q, want web-3", got)
	}
	if got := allocateDNSLabel(state, "WEB-01.corp.example"); got != "web-01" {
		t.Fatalf("label = %q, want web-01", got)
	}
	// Same input, same output: consensus depends on determinism.
	first := allocateDNSLabel(state, "db_primary")
	if second := allocateDNSLabel(state, "db_primary"); first != second {
		t.Fatalf("non-deterministic: %q vs %q", first, second)
	}
	if first != "db-primary" {
		t.Fatalf("label = %q, want db-primary", first)
	}
	if got := allocateDNSLabel(state, "..."); got != "" {
		t.Fatalf("label = %q, want empty for an unusable hostname", got)
	}
}

func TestRegisterPeerAssignsDNSLabel(t *testing.T) {
	state := model.NetworkState{
		NetworkID:   "net-1",
		OverlayCIDR: "100.64.0.0/24",
		Groups:      []model.Group{{ID: "clients"}},
		SetupKeys:   []model.SetupKey{{ID: "key", Token: "key", TokenHash: model.SetupKeyHash("key"), Groups: []string{"clients"}}},
	}
	transition := model.StateTransition{
		Type: TransitionRegisterPeer, SetupKey: "key",
		Peer: model.PeerRecord{PeerID: "peer-a", Hostname: "Web-01.corp.example"},
	}
	if err := ApplyTransition(&state, transition); err != nil {
		t.Fatalf("apply: %v", err)
	}
	if len(state.Peers) != 1 {
		t.Fatalf("peers = %d, want 1", len(state.Peers))
	}
	if state.Peers[0].DNSLabel != "web-01" {
		t.Fatalf("dns label = %q, want web-01", state.Peers[0].DNSLabel)
	}
}

func TestNormalizeStateEmitsUsersArray(t *testing.T) {
	encoded, err := json.Marshal(NormalizeState(model.NetworkState{NetworkID: "net-1"}))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(encoded), `"users":[]`) {
		t.Fatalf("state json %s missing empty users array", encoded)
	}
}

// TestApplyTransitionValidatesManagerHopsAgainstPeerIDs locks the hop identity
// contract: route assignment hops are libp2p PeerIDs, matched against the
// committee's PeerIDs and their forwarding capability.
func TestApplyTransitionValidatesManagerHopsAgainstPeerIDs(t *testing.T) {
	state := model.NetworkState{
		NetworkID:   "net-1",
		OverlayCIDR: "100.64.0.0/24",
		Peers: []model.PeerRecord{
			{PeerID: "client-a", OverlayIP: "100.64.0.1"},
			{PeerID: "client-b", OverlayIP: "100.64.0.2"},
		},
		EngineCommittee: []model.CommitteeMember{
			{ID: "manager-1", PeerID: "peer-manager-1", ForwardingEnabled: true},
			{ID: "manager-2", PeerID: "peer-manager-2", ForwardingEnabled: false},
		},
	}
	base := model.RouteAssignment{
		ID: "assignment", NetworkID: "net-1", SourcePeerID: "client-a", DestinationPeerID: "client-b",
		Primary: model.PathSpec{ID: "via", Kind: model.PathKindViaManager, ManagerHops: []string{"peer-manager-1"}},
	}
	if err := ApplyTransition(&state, model.StateTransition{Type: TransitionUpdateAssignment, Assignment: &base}); err != nil {
		t.Fatalf("peer-id hop rejected: %v", err)
	}

	// A committee label is not a hop identity.
	labelHop := base
	labelHop.Primary = model.PathSpec{ID: "via", Kind: model.PathKindViaManager, ManagerHops: []string{"manager-1"}}
	if err := ApplyTransition(&state, model.StateTransition{Type: TransitionUpdateAssignment, Assignment: &labelHop}); err == nil {
		t.Fatal("committee label accepted as a hop")
	}

	// A known PeerID that cannot forward is rejected.
	nonForwarding := base
	nonForwarding.Primary = model.PathSpec{ID: "via", Kind: model.PathKindViaManager, ManagerHops: []string{"peer-manager-2"}}
	if err := ApplyTransition(&state, model.StateTransition{Type: TransitionUpdateAssignment, Assignment: &nonForwarding}); err == nil {
		t.Fatal("non-forwarding manager accepted as a hop")
	}

	// An empty hop list is rejected outright.
	empty := base
	empty.Primary = model.PathSpec{ID: "via", Kind: model.PathKindViaManager}
	if err := ApplyTransition(&state, model.StateTransition{Type: TransitionUpdateAssignment, Assignment: &empty}); err == nil {
		t.Fatal("empty manager hop list accepted")
	}
}

// TestUpdateCommitteeValidation covers the size and churn limits on member
// replacement.
func TestUpdateCommitteeValidation(t *testing.T) {
	committee, _ := testCommittee()
	for index := range committee {
		committee[index].PeerID = "peer-" + committee[index].ID
		committee[index].Address = "/ip4/10.0.0.1/udp/1/quic-v1"
		committee[index].ForwardingEnabled = true
	}
	base := testState()
	base.EngineCommittee = append([]model.CommitteeMember(nil), committee...)

	if err := ApplyTransition(&base, model.StateTransition{
		Type: TransitionUpdateCommittee, Committee: committee,
	}); err != nil {
		t.Fatalf("identity replacement rejected: %v", err)
	}

	// Too many members replaced at once (f=1).
	churned := model.StateTransition{Type: TransitionUpdateCommittee}
	for index, member := range committee {
		if index < 2 {
			member.ID = member.ID + "-new"
			member.PeerID = member.PeerID + "-new"
			member.Address = "/ip4/10.0.0.1/udp/1/quic-v1"
		}
		churned.Committee = append(churned.Committee, member)
	}
	if err := ApplyTransition(&base, churned); err == nil {
		t.Fatal("replacing more than f members accepted")
	}

	// Size change is rejected.
	if err := ApplyTransition(&base, model.StateTransition{
		Type: TransitionUpdateCommittee, Committee: committee[:3],
	}); err == nil {
		t.Fatal("committee size change accepted")
	}

	// A replacement missing its transport identity is rejected.
	broken := model.StateTransition{Type: TransitionUpdateCommittee, Committee: append([]model.CommitteeMember(nil), committee...)}
	broken.Committee[3] = model.CommitteeMember{ID: "E", PeerID: "", Address: ""}
	if err := ApplyTransition(&base, broken); err == nil {
		t.Fatal("committee member without peer id accepted")
	}

	// Removing the last forwarding member is rejected.
	noForwarding := model.StateTransition{Type: TransitionUpdateCommittee, Committee: append([]model.CommitteeMember(nil), committee...)}
	for index := range noForwarding.Committee {
		noForwarding.Committee[index].ForwardingEnabled = false
	}
	if err := ApplyTransition(&base, noForwarding); err == nil {
		t.Fatal("committee without forwarding members accepted")
	}
}

// TestRotateCommitteeKeysBumpsEpoch verifies that key rotation advances the
// epoch and changes the group public key.
func TestRotateCommitteeKeysBumpsEpoch(t *testing.T) {
	committee, _ := testCommittee()
	state := testState()
	state.EngineCommittee = append([]model.CommitteeMember(nil), committee...)
	state.CommitteeConfig = model.CommitteeConfig{Threshold: QuorumSize, Size: CommitteeSize}
	before, _, _, err := deriveCommitteeKeys(committee, state.NetworkID, 0)
	if err != nil {
		t.Fatal(err)
	}
	state.CommitteeConfig = before

	if err := ApplyTransition(&state, model.StateTransition{Type: TransitionRotateCommittee}); err != nil {
		t.Fatal(err)
	}
	if state.CommitteeConfig.CommitteeEpoch != 1 {
		t.Fatalf("expected epoch 1, got %d", state.CommitteeConfig.CommitteeEpoch)
	}
	if bytes.Equal(state.CommitteeConfig.GroupPublicKey, before.GroupPublicKey) {
		t.Fatal("group public key did not rotate")
	}
}

// TestCommitteeReplacementKeepsQuorum replaces one member online and verifies
// the committee keeps certifying with the new membership.
func TestCommitteeReplacementKeepsQuorum(t *testing.T) {
	committee, keys := testCommittee()
	for index := range committee {
		committee[index].PeerID = "peer-" + committee[index].ID
		committee[index].Address = "/ip4/10.0.0.1/udp/1/quic-v1"
		committee[index].ForwardingEnabled = true
	}
	state := testState()
	engines := make([]*Engine, CommitteeSize)
	for index, key := range keys {
		engine, err := NewEngine(state, committee, committee[index].ID, key)
		if err != nil {
			t.Fatal(err)
		}
		engines[index] = engine
	}

	replacement := model.CommitteeMember{
		ID: "E", KeySeed: 99, PeerID: "peer-E", Address: "/ip4/10.0.0.2/udp/1/quic-v1",
		ForwardingEnabled: true,
	}
	newCommittee := []model.CommitteeMember{committee[0], committee[1], committee[2], replacement}
	snapshot := advance(t, keys, engines, model.StateTransition{
		Type: TransitionUpdateCommittee, Committee: newCommittee,
	})
	members := map[string]bool{}
	for _, member := range snapshot.Committee {
		members[member.ID] = true
	}
	if !members["D"] || members["E"] {
		t.Fatalf("snapshot should carry the pre-transition committee: %v", members)
	}
	for index := 0; index < CommitteeSize-1; index++ {
		adopted := engines[index].CommitteeMembers()
		if len(adopted) != CommitteeSize || adopted[CommitteeSize-1].ID != "E" {
			t.Fatalf("engine %d did not adopt the new committee: %+v", index, adopted)
		}
	}

	// Bring the replacement online and keep certifying.
	engineE, err := NewEngine(snapshot.State, newCommittee, "E", SeededPrivateKey(99))
	if err != nil {
		t.Fatal(err)
	}
	engineE.height = snapshot.Height
	engines[3] = engineE
	keys[3] = SeededPrivateKey(99)
	next := advance(t, keys, engines, model.StateTransition{
		Type: TransitionRegisterPeer, SetupKey: "key-a", Peer: model.PeerRecord{PeerID: "peer-a"},
	})
	if next.Height != snapshot.Height+1 {
		t.Fatalf("expected height %d, got %d", snapshot.Height+1, next.Height)
	}
}

// TestStaleEpochVoteRejected ensures votes signed under an old committee epoch
// cannot contribute after a rotation.
func TestStaleEpochVoteRejected(t *testing.T) {
	committee, keys := testCommittee()
	state := testState()
	engines := make([]*Engine, CommitteeSize)
	for index, key := range keys {
		engine, err := NewEngine(state, committee, committee[index].ID, key)
		if err != nil {
			t.Fatal(err)
		}
		engines[index] = engine
	}
	advance(t, keys, engines, model.StateTransition{Type: TransitionRotateCommittee})
	if engines[0].committeeConfig.CommitteeEpoch != 1 {
		t.Fatalf("expected epoch 1, got %d", engines[0].committeeConfig.CommitteeEpoch)
	}

	height := engines[0].Height() + 1
	stale := Vote{
		Height: height, Round: 0, NetworkID: state.NetworkID,
		StateHash: make([]byte, 32), TransitionHash: make([]byte, 32),
		VoterID: committee[0].ID, CommitteeEpoch: 0,
	}
	if err := engines[0].signVoteShare(&stale); err != nil {
		t.Fatal(err)
	}
	if _, _, err := engines[0].ProcessVote(stale); err == nil {
		t.Fatal("stale-epoch vote accepted")
	}
}

// TestUpdateBudgetUsageSettlesCounters verifies that aggregated usage is
// written into certified state and that the period anchor advances.
func TestUpdateBudgetUsageSettlesCounters(t *testing.T) {
	state := testState()
	state.Budgets = []model.TrafficBudget{{ID: "b1", SubjectType: "peer", SubjectID: "peer-a", DailyBytes: 1000, MonthlyBytes: 1000}}
	transition := model.StateTransition{
		Type: TransitionUpdateBudgetUse,
		BudgetUsage: &model.BudgetUsage{
			BudgetID: "b1", DailyBytes: 400, MonthlyBytes: 400,
			PeriodDay: "2026-09-25", PeriodMonth: "2026-09",
		},
	}
	if err := ApplyTransition(&state, transition); err != nil {
		t.Fatal(err)
	}
	if state.Budgets[0].UsedDailyBytes != 400 || state.Budgets[0].UsedMonthlyBytes != 400 {
		t.Fatalf("usage not settled: %+v", state.Budgets[0])
	}
	if state.Budgets[0].UpdatedAt.IsZero() {
		t.Fatal("period anchor was not advanced")
	}

	unknown := transition
	unknown.BudgetUsage = &model.BudgetUsage{BudgetID: "missing", DailyBytes: 1}
	if err := ApplyTransition(&state, unknown); err == nil {
		t.Fatal("unknown budget accepted")
	}
	if err := ApplyTransition(&state, model.StateTransition{Type: TransitionUpdateBudgetUse}); err == nil {
		t.Fatal("missing usage accepted")
	}
}
