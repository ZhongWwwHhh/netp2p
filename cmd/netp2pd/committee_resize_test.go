package main

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"path/filepath"
	"sort"
	"sync"
	"testing"
	"time"

	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
	hostcrypto "github.com/libp2p/go-libp2p/core/crypto"
	"github.com/netp2p/netp2p/internal/bft"
	"github.com/netp2p/netp2p/internal/config"
	"github.com/netp2p/netp2p/internal/crypto/bls"
	"github.com/netp2p/netp2p/internal/dkg"
	"github.com/netp2p/netp2p/internal/manager"
	"github.com/netp2p/netp2p/internal/model"
	"github.com/netp2p/netp2p/internal/p2p"
)

func TestCommitteeResizeWatcherActivatesFourthManager(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	const networkID = "netp2p-resize-test"
	const managerCount = 3
	ids := []string{"manager-a", "manager-b", "manager-c"}
	sort.Strings(ids)

	nodes := make([]*p2p.Node, managerCount)
	privateKeys := make([]ed25519.PrivateKey, managerCount)
	members := make([]model.CommitteeMember, managerCount)
	dataDirs := make([]string, managerCount)
	root := t.TempDir()

	for index := range ids {
		node, privateKey, err := newCommitteeResizeNode(ctx, int64(101+index))
		if err != nil {
			t.Fatalf("create manager node %s: %v", ids[index], err)
		}
		defer node.Close()
		nodes[index] = node
		privateKeys[index] = privateKey
		dataDirs[index] = filepath.Join(root, ids[index])
		publicKey := privateKey.Public().(ed25519.PublicKey)
		members[index] = model.CommitteeMember{
			ID: ids[index], PeerID: node.Host.ID().String(),
			Address:    nodeTransportAddress(t, node, "quic-v1"),
			ListenAddr: nodeTransportAddress(t, node, "webrtc-direct"),
			PublicKey:  append([]byte(nil), publicKey...), ForwardingEnabled: true,
		}
	}
	sort.Slice(members, func(i, j int) bool { return members[i].ID < members[j].ID })

	initialKeys, initialResults := generateCommitteeResizeDKG(t, ids)
	for index := range ids {
		if err := dkg.SaveShare(dataDirs[index], 1, ids[index], 3, 3, initialResults[index]); err != nil {
			t.Fatalf("save initial share for %s: %v", ids[index], err)
		}
	}

	engines := make([]*bft.Engine, managerCount)
	meshes := make([]*manager.CommitteeMesh, managerCount)
	params := model.CommitteeParams{Size: 3, FaultLimit: 0, QuorumSize: 3}
	for index := range ids {
		engine, err := bft.NewEngineWithKeySet(
			model.NetworkState{NetworkID: networkID, OverlayCIDR: "100.64.0.0/24"},
			members, ids[index], privateKeys[index], params, initialKeys[index], 1,
		)
		if err != nil {
			t.Fatalf("create engine %s: %v", ids[index], err)
		}
		localDataDir := dataDirs[index]
		localID := ids[index]
		engine.SetDKGLoader(func(epoch uint64, committee []model.CommitteeMember, params model.CommitteeParams) (*bls.KeySet, bool) {
			currentIDs := make([]string, 0, len(committee))
			for _, member := range committee {
				currentIDs = append(currentIDs, member.ID)
			}
			return dkg.LoadShare(localDataDir, epoch, localID, currentIDs, params.QuorumSize)
		})
		mesh, err := manager.NewCommitteeMesh(nodes[index], engine, members)
		if err != nil {
			t.Fatalf("create mesh %s: %v", ids[index], err)
		}
		engines[index] = engine
		meshes[index] = mesh
	}
	for index, mesh := range meshes {
		if err := mesh.Connect(ctx); err != nil {
			t.Fatalf("connect mesh %s: %v", ids[index], err)
		}
	}

	candidateNode, candidatePrivateKey, err := newCommitteeResizeNode(ctx, 404)
	if err != nil {
		t.Fatalf("create candidate node: %v", err)
	}
	defer candidateNode.Close()
	candidateID := "manager-d"
	candidateAddress := nodeTransportAddress(t, candidateNode, "quic-v1")
	candidateListen := nodeTransportAddress(t, candidateNode, "webrtc-direct")
	candidateLibp2pKey, _, err := hostcrypto.KeyPairFromStdKey(&candidatePrivateKey)
	if err != nil {
		t.Fatalf("derive candidate libp2p key: %v", err)
	}
	encodedCandidateKey, err := hostcrypto.MarshalPrivateKey(candidateLibp2pKey)
	if err != nil {
		t.Fatalf("marshal candidate private key: %v", err)
	}
	bundle := config.ManagerJoinBundle{
		Version: config.ManagerJoinBundleVersion, NetworkID: networkID, ManagerID: candidateID,
		PrivateKey:    base64.StdEncoding.EncodeToString(encodedCandidateKey),
		AdminToken:    "0123456789abcdef0123456789abcdef",
		SessionSecret: "0123456789abcdef0123456789abcdef",
		JoinToken:     "0123456789abcdef0123456789abcdef",
		InitDomain:    "manager-a.netp2p.example", Address: candidateAddress,
		QuicListen: candidateAddress, ListenAddr: candidateListen, TrustManagers: members,
	}
	if err := bundle.Validate(); err != nil {
		t.Fatalf("validate candidate bundle: %v", err)
	}
	candidate, err := bundle.PublicCommitteeMember()
	if err != nil {
		t.Fatalf("derive candidate member: %v", err)
	}
	if candidate.PeerID != candidateNode.Host.ID().String() {
		t.Fatalf("candidate peer id = %q, want %q", candidate.PeerID, candidateNode.Host.ID().String())
	}
	if _, err := connectTrustManagers(ctx, candidateNode, members); err != nil {
		t.Fatalf("connect candidate to trust managers: %v", err)
	}

	request := model.ManagerJoinRequest{
		ID: candidateID, ManagerID: candidateID, PeerID: candidate.PeerID,
		Address: candidate.Address, ListenAddr: candidate.ListenAddr,
		PublicKey:   append([]byte(nil), candidate.PublicKey...),
		RequestedAt: time.Now().UTC().Format(time.RFC3339Nano),
		Status:      model.ManagerJoinPending,
	}
	if _, err := meshes[0].Submit(model.StateTransition{
		Type: bft.TransitionSubmitManagerJoin, ManagerJoin: &request,
	}); err != nil {
		t.Fatalf("submit manager join: %v", err)
	}
	request.Status = model.ManagerJoinApproved
	request.ReviewedBy = "owner"
	request.ReviewedAt = time.Now().UTC().Format(time.RFC3339Nano)
	approval, err := meshes[0].Submit(model.StateTransition{
		Type: bft.TransitionReviewManagerJoin, ManagerJoin: &request,
		Actor: &model.Actor{ID: "owner", Role: model.RoleOwner},
	})
	if err != nil {
		t.Fatalf("approve manager join: %v", err)
	}
	for index := range engines {
		if engines[index].Height() < approval.Height {
			if err := engines[index].CatchUp(approval); err != nil {
				t.Fatalf("catch up manager %s approval: %v", ids[index], err)
			}
		}
	}
	watchers := make([]committeeResizeWatcher, managerCount)
	for index := range watchers {
		watchers[index] = committeeResizeWatcher{
			node: nodes[index], engine: engines[index], mesh: meshes[index],
			localID: ids[index], dataDir: dataDirs[index], networkID: networkID,
		}
	}
	candidateDataDir := filepath.Join(root, candidateID)
	watcherContext, watcherCancel := context.WithCancel(ctx)
	defer watcherCancel()
	var wait sync.WaitGroup
	for index := range watchers {
		wait.Add(1)
		go func(index int) {
			defer wait.Done()
			runCommitteeResizeWatcher(watcherContext, watchers[index])
		}(index)
	}
	wait.Add(1)
	go func() {
		defer wait.Done()
		if err := runCandidateDKG(ctx, candidateNode, bundle, approval, candidateDataDir); err != nil {
			t.Errorf("candidate dkg: %v", err)
		}
	}()
	wait.Wait()

	activatedParams := model.CommitteeParams{Size: 4, FaultLimit: 1, QuorumSize: 3}
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if engines[0].CommitteeParams() == activatedParams {
			break
		}
		select {
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		case <-time.After(50 * time.Millisecond):
		}
	}
	if engines[0].CommitteeParams() != activatedParams {
		t.Fatalf("committee params = %+v, want %+v", engines[0].CommitteeParams(), activatedParams)
	}
	watcherCancel()
	activation, ok := engines[0].LatestSnapshot()
	if !ok || activation.Transition.Type != bft.TransitionActivateCommittee {
		t.Fatalf("activation snapshot missing or invalid: ok=%v type=%q", ok, activation.Transition.Type)
	}
	for index := range engines {
		if engines[index].Height() < activation.Height {
			if err := engines[index].CatchUp(activation); err != nil {
				t.Fatalf("catch up manager %s activation: %v", ids[index], err)
			}
		}
		if engines[index].CommitteeParams() != activatedParams {
			t.Fatalf("manager %s committee params = %+v, want %+v", ids[index], engines[index].CommitteeParams(), activatedParams)
		}
	}
	postActivation, err := meshes[0].Submit(model.StateTransition{
		Type: bft.TransitionUpsertGroup, Group: &model.Group{ID: "post-activation"},
	})
	if err != nil {
		t.Fatalf("submit post-activation transition: %v", err)
	}
	if postActivation.Height <= activation.Height {
		t.Fatalf("post-activation height = %d, want greater than %d", postActivation.Height, activation.Height)
	}

	targetIDs := make([]string, 0, len(postActivation.Committee))
	for _, member := range postActivation.Committee {
		targetIDs = append(targetIDs, member.ID)
	}
	sort.Strings(targetIDs)
	candidateKeys, ok := dkg.LoadShare(candidateDataDir, 2, candidateID, targetIDs, activatedParams.QuorumSize)
	if !ok {
		t.Fatal("candidate did not persist its activated DKG share")
	}
	candidateEngine, err := bft.NewEngineWithKeySet(
		postActivation.State, postActivation.Committee, candidateID, candidatePrivateKey,
		activatedParams, candidateKeys, 2,
	)
	if err != nil {
		t.Fatalf("create activated candidate engine: %v", err)
	}
	if err := candidateEngine.CatchUp(postActivation); err != nil {
		t.Fatalf("catch up activated candidate engine: %v", err)
	}
	candidateEngine.SetDKGLoader(func(epoch uint64, committee []model.CommitteeMember, params model.CommitteeParams) (*bls.KeySet, bool) {
		currentIDs := make([]string, 0, len(committee))
		for _, member := range committee {
			currentIDs = append(currentIDs, member.ID)
		}
		return dkg.LoadShare(candidateDataDir, epoch, candidateID, currentIDs, params.QuorumSize)
	})
	candidateMesh, err := manager.NewCommitteeMesh(candidateNode, candidateEngine, postActivation.Committee)
	if err != nil {
		t.Fatalf("create candidate mesh: %v", err)
	}
	if err := candidateMesh.Connect(ctx); err != nil {
		t.Fatalf("connect candidate mesh: %v", err)
	}
	postResize, err := candidateMesh.Submit(model.StateTransition{
		Type: bft.TransitionUpsertGroup, Group: &model.Group{ID: "post-resize"},
	})
	if err != nil {
		t.Fatalf("submit post-resize transition: %v", err)
	}
	if postResize.Height <= activation.Height {
		t.Fatalf("post-resize height = %d, want greater than %d", postResize.Height, activation.Height)
	}
	if postResize.State.CommitteeConfig.CommitteeEpoch != 2 {
		t.Fatalf("post-resize epoch = %d, want 2", postResize.State.CommitteeConfig.CommitteeEpoch)
	}
}

func newCommitteeResizeNode(ctx context.Context, seed int64) (*p2p.Node, ed25519.PrivateKey, error) {
	privateKey := bft.SeededPrivateKey(seed)
	libp2pKey, _, err := hostcrypto.KeyPairFromStdKey(&privateKey)
	if err != nil {
		return nil, nil, err
	}
	node, err := p2p.New(ctx, p2p.Config{
		Identity: libp2pKey, Listen: []string{"/ip4/127.0.0.1/udp/0/quic-v1"},
		WebRTCListen: []string{"/ip4/127.0.0.1/udp/0/webrtc-direct"},
	})
	if err != nil {
		return nil, nil, err
	}
	return node, privateKey, nil
}

func nodeTransportAddress(t *testing.T, node *p2p.Node, protocolName string) string {
	t.Helper()
	for _, address := range node.Host.Addrs() {
		for _, protocol := range address.Protocols() {
			if protocol.Name == protocolName {
				return address.String()
			}
		}
	}
	t.Fatalf("node has no %s address", protocolName)
	return ""
}

func generateCommitteeResizeDKG(t *testing.T, ids []string) ([]*bls.KeySet, []*bls.DKGResult) {
	t.Helper()
	points := make([]fr.Element, len(ids))
	for index, id := range ids {
		points[index] = bls.PointForIdentity(id)
	}
	states := make([]*bls.DKGState, len(ids))
	for index := range ids {
		state, err := bls.NewDKGState(3, 3, index, points, nil)
		if err != nil {
			t.Fatalf("create dkg state %s: %v", ids[index], err)
		}
		if err := state.AddCommitments(index, state.Commitments()); err != nil {
			t.Fatalf("add own commitment %s: %v", ids[index], err)
		}
		states[index] = state
	}
	for dealer := range ids {
		for recipient := range ids {
			if err := states[recipient].AddCommitments(dealer, states[dealer].Commitments()); err != nil {
				t.Fatalf("add commitment from %s to %s: %v", ids[dealer], ids[recipient], err)
			}
			share, err := states[dealer].ShareFor(recipient)
			if err != nil {
				t.Fatalf("derive share from %s for %s: %v", ids[dealer], ids[recipient], err)
			}
			if err := states[recipient].AddShare(dealer, share); err != nil {
				t.Fatalf("add share from %s to %s: %v", ids[dealer], ids[recipient], err)
			}
		}
	}
	results := make([]*bls.DKGResult, len(ids))
	keySets := make([]*bls.KeySet, len(ids))
	for index := range ids {
		result, err := states[index].Finalize()
		if err != nil {
			t.Fatalf("finalize dkg %s: %v", ids[index], err)
		}
		keySet, err := result.KeySet(3, 3, index, points)
		if err != nil {
			t.Fatalf("build key set %s: %v", ids[index], err)
		}
		results[index] = result
		keySets[index] = keySet
	}
	return keySets, results
}
