package loadtest

import (
	"context"
	"encoding/hex"
	"fmt"
	"math"
	"path/filepath"
	"testing"
	"time"

	"github.com/netp2p/netp2p/internal/packet"
)

func TestProtocolIncludesAllClassesAndEpochRoundTrips(t *testing.T) {
	if len(AllFlowClasses) != 5 {
		t.Fatalf("flow classes = %d, want 5", len(AllFlowClasses))
	}
	epoch := RoutingEpoch{
		NetworkID: "loadtest", SnapshotHeight: 42, CandidateSetHash: []byte{1, 2, 3},
		Version: 7, GeneratedAt: time.Unix(1000, 0), ExpiresAt: time.Unix(1015, 0),
		Allocations: []PathAllocation{
			{
				Key: RoutingDomainKey{SourceManagerID: "manager-a", SourceGroupID: "group-a", DestinationScope: "scope-a", FlowClass: FlowRealtime},
				Paths: []PathWeight{
					{PathID: "path-a", Weight: .25, Reason: "sla"},
					{PathID: "path-b", Weight: .75, Reason: "capacity"},
				},
			},
		},
		PlannerDigest: []byte{9, 8, 7}, ManagerID: "manager-a", Signature: []byte{6, 5, 4},
	}
	encoded, err := EncodeEpoch(epoch)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := DecodeEpoch(encoded)
	if err != nil {
		t.Fatal(err)
	}
	if decoded.NetworkID != epoch.NetworkID || decoded.SnapshotHeight != epoch.SnapshotHeight ||
		decoded.Version != epoch.Version || decoded.ManagerID != epoch.ManagerID {
		t.Fatalf("epoch metadata did not round-trip: %+v", decoded)
	}
	if len(decoded.Allocations) != 1 || decoded.Allocations[0].Key != epoch.Allocations[0].Key {
		t.Fatalf("allocation key did not round-trip: %+v", decoded.Allocations)
	}
	for index, weight := range decoded.Allocations[0].Paths {
		if weight.PathID != epoch.Allocations[0].Paths[index].PathID ||
			math.Abs(weight.Weight-epoch.Allocations[0].Paths[index].Weight) > 1e-6 ||
			weight.Reason != epoch.Allocations[0].Paths[index].Reason {
			t.Fatalf("path weight did not round-trip: %+v", weight)
		}
	}
}

func TestOptimizerDistributesLoadAndRespectsCapacity(t *testing.T) {
	input := OptimizerInput{
		NetworkID: "loadtest", SnapshotHeight: 1, Version: 1, ManagerID: "manager-a",
		GeneratedAt: time.Now(), ExpiresAt: time.Now().Add(time.Second),
		Paths: []PathRuntime{
			{PathID: "small", Edges: []string{"small"}, BandwidthMbps: 10, Stability: .9, Healthy: true},
			{PathID: "large", Edges: []string{"large"}, BandwidthMbps: 100, Stability: .9, Healthy: true},
		},
		Demands: []Demand{{
			Key:            RoutingDomainKey{SourceManagerID: "manager-a", SourceGroupID: "group", DestinationScope: "scope", FlowClass: FlowThroughput},
			BytesPerSecond: 1000, EligiblePaths: []int{0, 1},
		}},
		EdgeCapacity:  map[string]float64{"small": 100, "large": 10000},
		CandidateHash: []byte{1},
	}
	epoch, metrics, err := Optimize(input, DefaultOptimizerConfig())
	if err != nil {
		t.Fatal(err)
	}
	if len(epoch.Allocations) != 1 || len(epoch.Allocations[0].Paths) != 2 {
		t.Fatalf("unexpected allocations: %+v", epoch.Allocations)
	}
	total := 0.0
	weights := make(map[string]float64)
	for _, path := range epoch.Allocations[0].Paths {
		total += path.Weight
		weights[path.PathID] = path.Weight
	}
	if math.Abs(total-1) > 1e-6 {
		t.Fatalf("weights sum to %f, want 1", total)
	}
	if weights["large"] <= weights["small"] {
		t.Fatalf("expected capacity to favor large path: %+v", weights)
	}
	if metrics.MaxUtilization > 1 {
		t.Fatalf("optimizer exceeded capacity: %f", metrics.MaxUtilization)
	}
}

func authorizationEnvelope(t *testing.T, fixture *ScaleFixture, sourceIndex, destinationIndex int) ForwardingEnvelope {
	t.Helper()
	source := fixture.Peers[sourceIndex]
	destination := fixture.Peers[destinationIndex]
	key := RoutingDomainKey{
		SourceManagerID:  managerID(fixture.Config, sourceIndex),
		SourceGroupID:    sourceGroupID(fixture.Config, sourceIndex),
		DestinationScope: destinationScopeID(fixture.Config, destinationIndex),
		FlowClass:        FlowLatency,
	}
	return ForwardingEnvelope{
		SourcePeerID: source.PeerID, DestinationPeerID: destination.PeerID,
		Domain: key, PathFamilyID: "path-direct", PathInstanceID: "path-direct:direct",
		FlowClass: FlowLatency, Protocol: 6, DestinationPort: 443,
		FlowHash: 12345, Sequence: 1, TTL: 8, Payload: []byte{0x45, 0, 0, 0},
	}
}

func TestAuthorizationAllowsCertifiedAndRejectsTampering(t *testing.T) {
	fixture, err := BuildScaleFixture(ScaleConfig{Peers: 20, Domains: 4, Managers: 2}, false)
	if err != nil {
		t.Fatal(err)
	}
	envelope := authorizationEnvelope(t, fixture, 0, 1)
	if err := fixture.Authorization.AuthorizeEnvelope(envelope); err != nil {
		t.Fatalf("certified envelope rejected: %v", err)
	}
	tampered := envelope
	tampered.PathFamilyID = "uncertified-path"
	if err := fixture.Authorization.AuthorizeEnvelope(tampered); err == nil {
		t.Fatal("uncertified path accepted")
	}
	tampered = envelope
	tampered.PathInstanceID = "path-direct:wrong-instance"
	if err := fixture.Authorization.AuthorizeEnvelope(tampered); err == nil {
		t.Fatal("uncertified path instance accepted")
	}
	tampered = envelope
	tampered.DestinationPeerID = fixture.Peers[19].PeerID
	if err := fixture.Authorization.AuthorizeEnvelope(tampered); err == nil {
		t.Fatal("destination outside routing scope accepted")
	}
	tampered = envelope
	tampered.FlowClass = FlowRealtime
	if err := fixture.Authorization.AuthorizeEnvelope(tampered); err == nil {
		t.Fatal("flow-class/domain mismatch accepted")
	}
}

func TestScaleShapeUsesDomainsNotPeerPairs(t *testing.T) {
	config := ScaleConfig{Peers: 1000, Domains: 100, Managers: 3}
	fixture, err := BuildScaleFixture(config, false)
	if err != nil {
		t.Fatal(err)
	}
	expectedDomains := config.Managers * config.Domains * len(AllFlowClasses)
	if fixture.Authorization.DomainCount() != expectedDomains {
		t.Fatalf("domain count = %d, want %d", fixture.Authorization.DomainCount(), expectedDomains)
	}
	if fixture.Authorization.DomainCount() >= config.Peers*(config.Peers-1) {
		t.Fatal("authorization state grew with peer pairs")
	}
}

func TestFlowSelectionIsStableAndFailsOver(t *testing.T) {
	flow := packet.Flow{Protocol: 6, SourcePort: 1234, DestinationPort: 443}
	weights := []PathWeight{
		{PathID: "path-a", Weight: .5},
		{PathID: "path-b", Weight: .5},
	}
	first, err := SelectPath(flow, weights, "", false, nil)
	if err != nil {
		t.Fatal(err)
	}
	second, err := SelectPath(flow, weights, first, false, nil)
	if err != nil {
		t.Fatal(err)
	}
	if first != second {
		t.Fatalf("stable flow changed path: %s -> %s", first, second)
	}
	changed := []PathWeight{{PathID: first, Weight: .49}, {PathID: otherPath(first), Weight: .51}}
	retained, err := SelectPath(flow, changed, first, false, nil)
	if err != nil {
		t.Fatal(err)
	}
	if retained != first {
		t.Fatalf("small weight change remapped flow: %s -> %s", first, retained)
	}
	failed, err := SelectPath(flow, weights, first, true, func(pathID string) bool { return pathID == first })
	if err != nil {
		t.Fatal(err)
	}
	if failed == first {
		t.Fatal("hard-failed path retained")
	}
}

func otherPath(pathID string) string {
	if pathID == "path-a" {
		return "path-b"
	}
	return "path-a"
}

func TestRegistryUsesRealShardedSQLiteStorage(t *testing.T) {
	config := ScaleConfig{Peers: 100, Domains: 10, Managers: 3}
	root := filepath.Join(t.TempDir(), "registry")
	registry, err := CreateShardedRegistry(context.Background(), root, 4, config.Peers, RegistryPeerGenerator(config))
	if err != nil {
		t.Fatal(err)
	}
	defer registry.Close()
	for index := 0; index < config.Peers; index += 7 {
		peerID := fmtPeerID(index)
		record, err := registry.Peer(context.Background(), peerID)
		if err != nil {
			t.Fatal(err)
		}
		if record.PeerID != peerID || record.OverlayIP != overlayIP(index) {
			t.Fatalf("registry round-trip failed: %+v", record)
		}
		if len(record.Groups) != 2 || record.ClientVersion != "3.0.0" {
			t.Fatalf("registry record lost protocol fields: %+v", record)
		}
	}
	rootHash, err := registry.MerkleRoot(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(rootHash) != 32 {
		t.Fatalf("merkle root length = %d, want 32", len(rootHash))
	}
	if hex.EncodeToString(rootHash) == "" {
		t.Fatal("empty merkle root")
	}
	usage, err := registry.DiskUsageBytes()
	if err != nil {
		t.Fatal(err)
	}
	if usage == 0 {
		t.Fatal("registry did not write durable storage")
	}
}

func fmtPeerID(index int) string {
	return "peer-" + sevenDigits(index)
}

func sevenDigits(index int) string {
	return fmt.Sprintf("%07d", index)
}

func BenchmarkAuthorizationEnvelope(b *testing.B) {
	fixture, err := BuildScaleFixture(ScaleConfig{Peers: 1000, Domains: 100, Managers: 3}, false)
	if err != nil {
		b.Fatal(err)
	}
	envelope := ForwardingEnvelope{
		SourcePeerID: fixture.Peers[0].PeerID, DestinationPeerID: fixture.Peers[1].PeerID,
		Domain: RoutingDomainKey{
			SourceManagerID: managerID(fixture.Config, 0), SourceGroupID: sourceGroupID(fixture.Config, 0),
			DestinationScope: destinationScopeID(fixture.Config, 1), FlowClass: FlowLatency,
		},
		PathFamilyID: "path-direct", PathInstanceID: "path-direct:direct", FlowClass: FlowLatency,
		Protocol: 6, DestinationPort: 443, FlowHash: 1, Sequence: 1, TTL: 8, Payload: []byte{0x45},
	}
	b.ReportAllocs()
	b.ResetTimer()
	for index := 0; index < b.N; index++ {
		if err := fixture.Authorization.AuthorizeEnvelope(envelope); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkFlowTableLookup(b *testing.B) {
	table := NewFlowTable(64, 100000)
	flows := make([]packet.Flow, 100000)
	for index := range flows {
		flows[index] = packet.Flow{Protocol: 6, SourcePort: uint16(1024 + index), DestinationPort: 443}
		table.Observe(FlowEntry{Key: flows[index], PathID: "path-direct", Bytes: 100})
	}
	b.ReportAllocs()
	b.ResetTimer()
	for index := 0; index < b.N; index++ {
		if _, ok := table.Lookup(flows[index%len(flows)]); !ok {
			b.Fatal("flow miss")
		}
	}
}

func BenchmarkOptimizerProductionShape(b *testing.B) {
	config := DefaultScaleConfig()
	config.Flows = 0
	fixture, err := BuildScaleFixture(config, false)
	if err != nil {
		b.Fatal(err)
	}
	demands := BuildDemands(fixture)
	b.ReportAllocs()
	b.ResetTimer()
	for index := 0; index < b.N; index++ {
		_, _, err := Optimize(OptimizerInput{
			NetworkID: "benchmark", SnapshotHeight: 1, Version: uint64(index + 1), ManagerID: "manager-00",
			GeneratedAt: time.Now(), ExpiresAt: time.Now().Add(time.Second), Paths: fixture.Paths,
			Demands: demands, EdgeCapacity: fixture.EdgeCapacity, CandidateHash: CandidateSetHash(fixture.Families),
		}, DefaultOptimizerConfig())
		if err != nil {
			b.Fatal(err)
		}
	}
}
