package manager

import (
	"context"
	"net"
	"testing"
	"time"

	bls12381fr "github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
	libp2pcrypto "github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/netp2p/netp2p/internal/bft"
	"github.com/netp2p/netp2p/internal/crypto/bls"
	"github.com/netp2p/netp2p/internal/forward"
	"github.com/netp2p/netp2p/internal/link"
	"github.com/netp2p/netp2p/internal/metrics"
	"github.com/netp2p/netp2p/internal/model"
	"github.com/netp2p/netp2p/internal/p2p"
	"github.com/netp2p/netp2p/internal/packet"
	"github.com/netp2p/netp2p/internal/path"
	"github.com/netp2p/netp2p/internal/presence"
	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
)

func TestRoutingEpochRequiresThresholdAndSurvivesRoundChange(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	now := time.Date(2026, 10, 14, 0, 0, 0, 0, time.UTC)
	ids := []string{"manager-a", "manager-b", "manager-c"}
	params := model.CommitteeParams{Size: 3, FaultLimit: 0, QuorumSize: 3}
	keys, engines, _, node, state := routingEpochTestFixture(t, ctx, ids, params)
	defer node.Close()
	localID := ids[2]
	manager := &Manager{node: node, engine: engines[2]}
	manager.metrics = metrics.New()
	runtime := newRoutingRuntime(manager)
	runtime.now = func() time.Time { return now }

	if err := engines[2].SetRoundTimeout(time.Millisecond); err != nil {
		t.Fatal(err)
	}
	time.Sleep(5 * time.Millisecond)
	if round := engines[2].AdvanceExpiredRound(engines[2].Height() + 1); round != 1 {
		t.Fatalf("current round = %d, want 1", round)
	}
	result, err := runtime.plan(state, now)
	if err != nil {
		t.Fatal(err)
	}
	result.Epoch.ManagerID = localID
	if result.Epoch.Round != 1 {
		t.Fatalf("planned round = %d, want 1", result.Epoch.Round)
	}
	signed := signRoutingEpochFixture(t, result.Epoch, ids, engines, keys)
	if err := runtime.installEpoch(signed, state, now); err != nil {
		t.Fatal(err)
	}
	if runtime.signedEpoch() == nil || !runtime.signedEpoch().ThresholdSigned {
		t.Fatal("threshold epoch was not installed")
	}
	if got := routingGaugeValue(t, manager.metrics.RoutingEpochPresent); got != 1 {
		t.Fatalf("routing epoch present metric = %v, want 1", got)
	}
	if got := routingGaugeValue(t, manager.metrics.RoutingEpochSequence); got != float64(signed.Epoch.Sequence) {
		t.Fatalf("routing epoch sequence metric = %v, want %d", got, signed.Epoch.Sequence)
	}
	if got := routingGaugeValue(t, manager.metrics.RoutingEpochAge); got < 0 {
		t.Fatalf("routing epoch age metric = %v, want non-negative", got)
	}
	if got := routingGaugeValue(t, manager.metrics.RoutingEpochSize); got <= 0 {
		t.Fatalf("routing epoch size metric = %v, want positive", got)
	}

	envelope := forward.ScaleEnvelope{
		Header: forward.ScaleHeader{
			SourcePeerID: "peer-a", DestinationPeerID: "peer-b",
			RoutingDomainID: "routing-domain", FlowClass: string(path.FlowLatency),
			TTL: forward.DefaultTTL,
		},
	}
	payload, err := packet.BuildEchoRequest(
		net.ParseIP("100.64.0.1"), net.ParseIP("100.64.0.2"), 0x5150, 1, []byte("routing"),
	)
	if err != nil {
		t.Fatal(err)
	}
	envelope.Payload = payload
	if err := runtime.applySelection(&envelope); err != nil {
		t.Fatalf("threshold epoch did not authorize forwarding: %v", err)
	}
	if envelope.Header.PathFamilyID == "" {
		t.Fatal("threshold epoch selected no path family")
	}

	insufficient := signed
	insufficient.Signers = insufficient.Signers[:2]
	if err := runtime.installEpoch(insufficient, state, now); err == nil {
		t.Fatal("epoch with fewer signers than threshold was installed")
	}
	if got := routingCounterValue(t, manager.metrics.RoutingEpochInvalid); got != 1 {
		t.Fatalf("routing epoch invalid metric = %v, want 1", got)
	}

	roundZero := result.Epoch
	roundZero.Round = 0
	roundZero.ManagerID = localID
	if err := runtime.installEpoch(
		signRoutingEpochFixture(t, roundZero, ids, engines, keys), state, now,
	); err == nil {
		t.Fatal("round-0 signature from the round-1 leader was accepted")
	}

	if err := runtime.installEpoch(signed, state, now); err == nil {
		t.Fatal("replayed epoch was accepted")
	}
	expired := result.Epoch
	expired.ExpiresAt = now.Add(-time.Second)
	if err := runtime.installEpoch(
		signRoutingEpochFixture(t, expired, ids, engines, keys), state, now,
	); err == nil {
		t.Fatal("expired epoch was accepted")
	}
	wrongCommittee := result.Epoch
	wrongCommittee.CommitteeEpoch++
	if err := runtime.installEpoch(
		signRoutingEpochFixture(t, wrongCommittee, ids, engines, keys), state, now,
	); err == nil {
		t.Fatal("old committee epoch was accepted")
	}
	wrongSnapshot := result.Epoch
	wrongSnapshot.SnapshotHash[0] ^= 0xff
	if err := runtime.installEpoch(
		signRoutingEpochFixture(t, wrongSnapshot, ids, engines, keys), state, now,
	); err == nil {
		t.Fatal("epoch bound to another snapshot was accepted")
	}
}

func TestReconcileSkipsEmptyRoutingEpochWhenNoDomains(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	node, err := p2p.New(ctx, p2p.Config{IdentitySeed: 4242})
	if err != nil {
		t.Fatal(err)
	}
	defer node.Close()

	state := model.NetworkState{
		NetworkID:   "netp2p-empty-routing-test",
		OverlayCIDR: "10.70.0.0/24",
		Settings:    model.NetworkSettings{ViaManagerEnabled: true},
		PathFamilies: []model.PathFamily{{
			ID: "family-via-manager-1", Kind: model.PathKindViaManager,
			ManagerHops:  []string{node.Host.ID().String()},
			SourceGroups: []string{"*"}, DestinationScopes: []string{"*"},
			FlowClasses: model.AllFlowClasses(), MinBandwidthMbps: 10,
			MaxRTTMilliseconds: 300, MaxJitterMilliseconds: 60, MaxLossPercent: 15,
		}},
	}
	state.CommitteeConfig = model.CommitteeConfig{
		Threshold: 1, Size: 1, CommitteeEpoch: 1,
	}
	member := model.CommitteeMember{
		ID: "manager-1", PeerID: node.Host.ID().String(),
		KeySeed: 4242, ForwardingEnabled: true,
	}
	engine, err := bft.NewEngine(state, []model.CommitteeMember{member}, member.ID, bft.SeededPrivateKey(4242))
	if err != nil {
		t.Fatal(err)
	}
	manager := &Manager{node: node, engine: engine, metrics: metrics.New(), presence: presence.NewTable()}
	runtime := newRoutingRuntime(manager)

	if err := runtime.Reconcile(); err != nil {
		t.Fatalf("reconcile without routing domains: %v", err)
	}
	if runtime.signedEpoch() != nil {
		t.Fatal("reconcile installed a routing epoch without certified domains")
	}
	if got := routingGaugeValue(t, manager.metrics.RoutingEpochPresent); got != 0 {
		t.Fatalf("routing epoch present metric = %v, want 0", got)
	}
}

func TestPlannerFamiliesIgnoreLegacyDirectFamily(t *testing.T) {
	state := model.NetworkState{PathFamilies: []model.PathFamily{
		{ID: "family-global-direct", Kind: model.PathKindDirect},
		{ID: "family-manager-a", Kind: model.PathKindViaManager, ManagerHops: []string{"peer-a"}},
	}}
	committee := []model.CommitteeMember{{ID: "manager-a", PeerID: "peer-a"}}

	families := plannerFamilies(committee, state)
	if len(families) != 1 {
		t.Fatalf("planner families = %d, want 1", len(families))
	}
	if families[0].ID != "family-manager-a" || families[0].Kind != model.PathKindViaManager {
		t.Fatalf("unexpected planner family: %+v", families[0])
	}
	if len(families[0].ManagerHops) != 1 || families[0].ManagerHops[0] != "manager-a" {
		t.Fatalf("manager hops were not normalized: %+v", families[0].ManagerHops)
	}
}

func routingEpochTestFixture(
	t *testing.T, ctx context.Context, ids []string, params model.CommitteeParams,
) (*bls.KeySet, []*bft.Engine, []model.CommitteeMember, *p2p.Node, model.NetworkState) {
	t.Helper()

	points := make([]bls12381fr.Element, len(ids))
	for index, id := range ids {
		points[index] = bls.PointForIdentity(id)
	}
	keys, err := bls.DeriveKeySet([]byte("routing-epoch-test"), params.QuorumSize, points)
	if err != nil {
		t.Fatal(err)
	}
	members := make([]model.CommitteeMember, len(ids))
	engines := make([]*bft.Engine, len(ids))
	state := model.NetworkState{
		NetworkID: "routing-threshold-test", OverlayCIDR: "100.64.0.0/24",
		Groups: []model.Group{
			{ID: "clients", PeerIDs: []string{"peer-a"}},
			{ID: "servers", PeerIDs: []string{"peer-b"}},
		},
		Policies: []model.Policy{{
			ID: "allow-routing", SourceGroups: []string{"clients"}, DestinationGroups: []string{"servers"},
			Services: []model.Service{{Protocol: "icmp"}}, Effect: model.EffectAllow,
		}},
	}
	for index, id := range ids {
		members[index] = model.CommitteeMember{
			ID: id, KeySeed: 0,
			PublicKey:         append([]byte(nil), bft.SeededPublicKey(int64(1200+index))...),
			ForwardingEnabled: true,
		}
	}
	node, err := p2p.New(ctx, p2p.Config{IdentitySeed: 1202})
	if err != nil {
		t.Fatal(err)
	}
	for index := range members {
		privateKey := bft.SeededPrivateKey(int64(1200 + index))
		libp2pKey, _, err := libp2pcrypto.KeyPairFromStdKey(&privateKey)
		if err != nil {
			t.Fatal(err)
		}
		peerID, err := peer.IDFromPrivateKey(libp2pKey)
		if err != nil {
			t.Fatal(err)
		}
		members[index].PeerID = peerID.String()
	}
	state.EngineCommittee = append([]model.CommitteeMember(nil), members...)
	state.PathFamilies = []model.PathFamily{{
		ID: "family-manager-c", Kind: model.PathKindViaManager, ManagerHops: []string{members[2].PeerID},
		SourceGroups: []string{"clients"}, DestinationScopes: []string{"group:servers"},
		FlowClasses: model.AllFlowClasses(), MinBandwidthMbps: 10,
		MaxRTTMilliseconds: 300, MaxJitterMilliseconds: 60, MaxLossPercent: 15,
	}}
	state.RoutingDomains = []model.RoutingDomainAuthorization{{
		ID: "routing-domain",
		Key: model.RoutingDomainKey{
			SourceManagerID: ids[2], SourceGroupID: "clients",
			DestinationScope: model.DestinationScopeGroup + "servers",
			FlowClass:        string(path.FlowLatency),
		},
		PathFamilyIDs: []string{"family-manager-c"}, PolicyIDs: []string{"allow-routing"},
	}}
	for index := range members {
		engine, err := bft.NewEngineWithKeySet(
			state, members, ids[index], bft.SeededPrivateKey(int64(1200+index)), params, keys, 1,
		)
		if err != nil {
			t.Fatal(err)
		}
		engines[index] = engine
	}
	commitRoutingTransition := func(transition model.StateTransition) {
		leaderIndex := int((engines[0].Height() + 1) % uint64(len(engines)))
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
			t.Fatal("routing transition quorum was not reached")
		}
		for _, engine := range engines {
			if _, err := engine.Commit(proposal, qc); err != nil {
				t.Fatal(err)
			}
		}
	}
	commitRoutingTransition(model.StateTransition{Type: bft.TransitionGenesis})
	commitRoutingTransition(model.StateTransition{Type: bft.TransitionUpsertPathFamily, PathFamily: &state.PathFamilies[0]})
	commitRoutingTransition(model.StateTransition{Type: bft.TransitionUpsertRoutingDomain, Domain: &state.RoutingDomains[0]})
	return keys, engines, members, node, engines[2].CurrentState()
}

func signRoutingEpochFixture(
	t *testing.T, epoch link.RoutingEpoch, ids []string, engines []*bft.Engine, keys *bls.KeySet,
) link.SignedRoutingEpoch {
	t.Helper()
	shares := make(map[int][]byte, len(ids))
	signers := make(map[int]string, len(ids))
	for index, id := range ids {
		share, err := link.SignRoutingEpochShare(epoch, id, engines[index].RoutingKeySet(), index)
		if err != nil {
			t.Fatal(err)
		}
		shares[index] = share.Signature
		signers[index] = id
	}
	signed, err := link.AggregateRoutingEpochShares(epoch, shares, signers, keys)
	if err != nil {
		t.Fatal(err)
	}
	return signed
}

func routingGaugeValue(t *testing.T, gauge prometheus.Gauge) float64 {
	t.Helper()
	var metric dto.Metric
	if err := gauge.Write(&metric); err != nil {
		t.Fatal(err)
	}
	return metric.GetGauge().GetValue()
}

func routingCounterValue(t *testing.T, counter prometheus.Counter) float64 {
	t.Helper()
	var metric dto.Metric
	if err := counter.Write(&metric); err != nil {
		t.Fatal(err)
	}
	return metric.GetCounter().GetValue()
}
