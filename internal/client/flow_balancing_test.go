package client

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"testing"
	"time"

	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/netp2p/netp2p/internal/forward"
	"github.com/netp2p/netp2p/internal/model"
)

var (
	flowEpochPublicKey  ed25519.PublicKey
	flowEpochPrivateKey ed25519.PrivateKey
)

func init() {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		panic(err)
	}
	flowEpochPublicKey, flowEpochPrivateKey = publicKey, privateKey
}

func TestWeightedRendezvousDistributesFlowsAcrossCertifiedPaths(t *testing.T) {
	selector, source, destination := flowBalancingSelector(t)
	assignmentRecord := twoPathAssignment()
	snapshot := pathSnapshot(false, assignmentRecord)
	if err := selector.syncSnapshot(snapshot); err != nil {
		t.Fatal(err)
	}
	applyFlowEpoch(t, selector, snapshot.State.NetworkID, 1, map[string]float64{"via-a": .5, "via-b": .5})

	counts := map[string]int{}
	for index := 0; index < 10000; index++ {
		_, path, status := selector.selectFlowWithStatus(
			source, destination, testFlowKey(index), true, FlowClassThroughput, 1400,
		)
		if !status.OK || status.FlowClass != FlowClassThroughput {
			t.Fatalf("selection status = %+v", status)
		}
		counts[path.ID]++
	}
	if counts["via-a"] < 4300 || counts["via-a"] > 5700 || counts["via-b"] < 4300 || counts["via-b"] > 5700 {
		t.Fatalf("weighted distribution = %v", counts)
	}
	if stats := selector.flows.stats(); stats.Active != 10000 {
		t.Fatalf("active flows = %d, want 10000", stats.Active)
	}
}

func TestOrdinaryFlowPinningSurvivesWeightChanges(t *testing.T) {
	selector, source, destination := flowBalancingSelector(t)
	snapshot := pathSnapshot(false, twoPathAssignment())
	if err := selector.syncSnapshot(snapshot); err != nil {
		t.Fatal(err)
	}
	applyFlowEpoch(t, selector, snapshot.State.NetworkID, 1, map[string]float64{"via-a": .5, "via-b": .5})
	flow := testFlowKey(60000)
	_, first, status := selector.selectFlowWithStatus(source, destination, flow, true, FlowClassThroughput, 1400)
	if !status.OK {
		t.Fatalf("first selection = %+v", status)
	}

	applyFlowEpoch(t, selector, snapshot.State.NetworkID, 2, map[string]float64{"via-a": .99, "via-b": .01})
	_, second, status := selector.selectFlowWithStatus(source, destination, flow, true, FlowClassThroughput, 1400)
	if !status.OK || second.ID != first.ID || status.MigrationReason != "" {
		t.Fatalf("pinned selection = first %s second %s status %+v", first.ID, second.ID, status)
	}
}

func TestFlowClassCacheInvalidatesOnSnapshotChange(t *testing.T) {
	selector, source, destination := flowBalancingSelector(t)
	snapshot := pathSnapshot(false, twoPathAssignment())
	if err := selector.syncSnapshot(snapshot); err != nil {
		t.Fatal(err)
	}
	flow := testFlowKey(60002)
	if _, _, status := selector.selectFlowWithStatus(source, destination, flow, true, FlowClassThroughput, 1400); !status.OK {
		t.Fatalf("initial selection = %+v", status)
	}
	if class, ok := selector.cachedFlowClass(flow); !ok || class != FlowClassThroughput {
		t.Fatalf("cached class = %q ok=%v, want throughput", class, ok)
	}

	snapshot.Height = 2
	if err := selector.syncSnapshot(snapshot); err != nil {
		t.Fatal(err)
	}
	if _, ok := selector.cachedFlowClass(flow); ok {
		t.Fatal("flow class cache survived a snapshot change")
	}
}

func TestRealtimeFlowMigratesOnlyForSLAOrHardFailure(t *testing.T) {
	selector, source, destination := flowBalancingSelector(t)
	assignmentRecord := twoPathAssignment()
	snapshot := pathSnapshot(false, assignmentRecord)
	if err := selector.syncSnapshot(snapshot); err != nil {
		t.Fatal(err)
	}
	applyFlowEpoch(t, selector, snapshot.State.NetworkID, 1, map[string]float64{"via-a": .5, "via-b": .5})
	flow := testFlowKey(60001)
	_, first, status := selector.selectFlowWithStatus(source, destination, flow, true, FlowClassRealtime, 200)
	if !status.OK {
		t.Fatalf("first realtime selection = %+v", status)
	}

	// Weight churn alone must not reorder a realtime flow.
	applyFlowEpoch(t, selector, snapshot.State.NetworkID, 2, map[string]float64{"via-a": .99, "via-b": .01})
	_, unchanged, status := selector.selectFlowWithStatus(source, destination, flow, true, FlowClassRealtime, 200)
	if !status.OK || unchanged.ID != first.ID || status.MigrationReason != "" {
		t.Fatalf("realtime weight churn migrated flow: first %s second %s status %+v", first.ID, unchanged.ID, status)
	}

	if assignmentRecord.Primary.ID == first.ID {
		assignmentRecord.Primary.RTTMilliseconds = 250
		assignmentRecord.Primary.LossPercent = 5
	}
	for index := range assignmentRecord.Fallbacks {
		if assignmentRecord.Fallbacks[index].ID == first.ID {
			assignmentRecord.Fallbacks[index].RTTMilliseconds = 250
			assignmentRecord.Fallbacks[index].LossPercent = 5
		}
	}
	snapshot.Height = 2
	snapshot.State.Assignments = []model.RouteAssignment{assignmentRecord}
	if err := selector.syncSnapshot(snapshot); err != nil {
		t.Fatal(err)
	}
	_, migrated, status := selector.selectFlowWithStatus(source, destination, flow, true, FlowClassRealtime, 200)
	if !status.OK || migrated.ID == first.ID || status.MigrationReason != "realtime-sla-violation" {
		t.Fatalf("realtime SLA migration = first %s second %s status %+v", first.ID, migrated.ID, status)
	}

	selector.recordHardFailure(migrated.ID)
	_, failedOver, status := selector.selectFlowWithStatus(source, destination, flow, true, FlowClassRealtime, 200)
	if !status.OK || failedOver.ID == migrated.ID {
		t.Fatalf("realtime hard failure fallback = old %s new %s status %+v", migrated.ID, failedOver.ID, status)
	}
}

func TestSignedRoutingEpochRejectsTamperingStaleAndUnknownPaths(t *testing.T) {
	selector, _, _ := flowBalancingSelector(t)
	snapshot := pathSnapshot(false, twoPathAssignment())
	if err := selector.syncSnapshot(snapshot); err != nil {
		t.Fatal(err)
	}
	signed, err := SignRoutingEpoch(RoutingEpoch{
		NetworkID: snapshot.State.NetworkID, Sequence: 2, GeneratedAt: time.Now(),
		Weights: map[string]map[string]float64{"assignment": {"not-certified": 1}},
	}, flowEpochPrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	if err := selector.applySignedRoutingEpoch(signed, flowEpochPublicKey); !errors.Is(err, ErrInvalidRoutingEpoch) {
		t.Fatalf("unknown path error = %v", err)
	}

	signed.Payload = append([]byte(nil), signed.Payload...)
	signed.Payload[len(signed.Payload)-1] ^= 1
	if err := selector.applySignedRoutingEpoch(signed, flowEpochPublicKey); !errors.Is(err, ErrInvalidRoutingEpoch) {
		t.Fatalf("tampered payload error = %v", err)
	}

	valid, err := SignRoutingEpoch(RoutingEpoch{
		NetworkID: snapshot.State.NetworkID, Sequence: 2, GeneratedAt: time.Now(),
		Weights: map[string]map[string]float64{"assignment": {"via-a": 1}},
	}, flowEpochPrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	if err := selector.applySignedRoutingEpoch(valid, flowEpochPublicKey); err != nil {
		t.Fatal(err)
	}
	if err := selector.applySignedRoutingEpoch(valid, flowEpochPublicKey); !errors.Is(err, ErrStaleRoutingEpoch) {
		t.Fatalf("stale epoch error = %v", err)
	}
}

func flowBalancingSelector(t *testing.T) (*pathSelector, peer.ID, peer.ID) {
	t.Helper()
	selector := newPathSelector(forward.NewTable(model.NetworkState{}, "manager", func(peer.ID, forward.Envelope) error {
		return nil
	}), nil)
	source, err := peer.Decode(peerSource)
	if err != nil {
		t.Fatal(err)
	}
	destination, err := peer.Decode(peerDestination)
	if err != nil {
		t.Fatal(err)
	}
	return selector, source, destination
}

func twoPathAssignment() model.RouteAssignment {
	assignmentRecord := assignment()
	assignmentRecord.Primary = model.PathSpec{
		ID: "via-a", Kind: model.PathKindViaManager, ManagerHops: []string{"manager-a"},
		RTTMilliseconds: 20, BandwidthMbps: 100, Confidence: .9,
	}
	assignmentRecord.Fallbacks = []model.PathSpec{{
		ID: "via-b", Kind: model.PathKindViaManager, ManagerHops: []string{"manager-b"},
		RTTMilliseconds: 22, BandwidthMbps: 100, Confidence: .9,
	}}
	return assignmentRecord
}

func applyFlowEpoch(t *testing.T, selector *pathSelector, networkID string, sequence uint64, weights map[string]float64) {
	t.Helper()
	signed, err := SignRoutingEpoch(RoutingEpoch{
		NetworkID: networkID, Sequence: sequence, GeneratedAt: time.Now(),
		Weights: map[string]map[string]float64{"assignment": weights},
	}, flowEpochPrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	if err := selector.applySignedRoutingEpoch(signed, flowEpochPublicKey); err != nil {
		t.Fatal(err)
	}
}
