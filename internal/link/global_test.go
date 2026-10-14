package link

import (
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"testing"
	"time"

	bls12381fr "github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
	"github.com/netp2p/netp2p/internal/crypto/bls"
	"github.com/netp2p/netp2p/internal/model"
	"github.com/netp2p/netp2p/internal/path"
)

func plannerCandidate(id, manager string, capacity, pressure float64, projected bool) PathCandidate {
	return PathCandidate{
		Family: PathFamily{
			ID: id, Kind: model.PathKindViaManager, ManagerHops: []string{manager},
			FlowClasses: allFlowClasses(),
		},
		Profile: path.LinkProfile{
			PathID: id, Type: path.PathViaManager, RTTMilliseconds: 20,
			LossPercent: 0, JitterMilliseconds: 1, BandwidthMbps: 100, Stability: 1,
		},
		Edges:                  []string{"face:" + manager},
		CapacityBytesPerSecond: capacity,
		MonthlyPressure:        pressure,
		ProjectedExhaustion:    projected,
	}
}

var plannerSnapshotHash = []byte("certified-snapshot-hash")

func allocationWeight(t *testing.T, epoch RoutingEpoch, domain RoutingDomainKey, pathID string) float64 {
	t.Helper()
	for _, allocation := range epoch.Allocations {
		if allocation.Domain == domain && allocation.PathID == pathID {
			return allocation.Weight
		}
	}
	t.Fatalf("allocation for %s/%s not found", domain.ID(), pathID)
	return 0
}

func TestAllocationHysteresisHoldsSmallWeightChanges(t *testing.T) {
	domain := &planningDomain{
		key:        RoutingDomainKey{DestinationScope: "*", FlowClass: path.FlowThroughput},
		candidates: []int{0, 1},
		weights:    []float64{0.52, 0.48},
	}
	candidates := []PathCandidate{
		plannerCandidate("manager-a", "manager-a", 1000, 0, false),
		plannerCandidate("manager-b", "manager-b", 1000, 0, false),
	}
	current := map[string]map[string]float64{
		domain.key.ID(): {"manager-a": 0.5, "manager-b": 0.5},
	}

	applyAllocationHysteresis([]*planningDomain{domain}, candidates, current, 0.03)
	if domain.weights[0] != 0.5 || domain.weights[1] != 0.5 {
		t.Fatalf("hysteresis did not hold small weight change: %+v", domain.weights)
	}
}

func TestRealtimeDomainsStayPinnedToCurrentPath(t *testing.T) {
	domain := &planningDomain{
		key:         RoutingDomainKey{DestinationScope: "*", FlowClass: path.FlowRealtime},
		currentPath: "manager-b",
		candidates:  []int{0, 1},
		weights:     []float64{0.4, 0.6},
	}
	candidates := []PathCandidate{
		plannerCandidate("manager-a", "manager-a", 1000, 0, false),
		plannerCandidate("manager-b", "manager-b", 1000, 0, false),
	}

	stabilizeRealtimeDomains([]*planningDomain{domain}, candidates)
	if domain.weights[0] != 0 || domain.weights[1] != 1 {
		t.Fatalf("realtime domain was not pinned to its current path: %+v", domain.weights)
	}
}

func TestMigrationRequiresEnoughUtilizationBenefit(t *testing.T) {
	domain := &planningDomain{
		key:         RoutingDomainKey{DestinationScope: "*", FlowClass: path.FlowThroughput},
		currentPath: "manager-a",
		candidates:  []int{0, 1},
		weights:     []float64{0.5, 0.5},
	}
	candidates := []PathCandidate{
		plannerCandidate("manager-a", "manager-a", 1000, 0, false),
		plannerCandidate("manager-b", "manager-b", 1000, 0, false),
	}
	loads := []EdgeLoad{
		{EdgeID: "face:manager-a", Utilization: 0.50},
		{EdgeID: "face:manager-b", Utilization: 0.48},
	}
	config := PlannerConfig{MaxMigrations: 1, MigrationBenefit: 0.10}
	if result := migrationCandidates([]*planningDomain{domain}, candidates, loads, config); len(result) != 0 {
		t.Fatalf("small utilization benefit produced a migration: %+v", result)
	}

	loads[1].Utilization = 0.10
	result := migrationCandidates([]*planningDomain{domain}, candidates, loads, config)
	if len(result) != 1 || result[0].FromPathID != "manager-a" || result[0].ToPathID != "manager-b" {
		t.Fatalf("large utilization benefit did not produce the expected migration: %+v", result)
	}
}

func TestGlobalPlannerDistributesComparablePaths(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	domain := RoutingDomainKey{DestinationScope: "group:servers", FlowClass: path.FlowThroughput}
	result, err := PlanRoutingEpoch(PlannerInput{
		NetworkID: "net", SnapshotHeight: 10, SnapshotHash: plannerSnapshotHash,
		CommitteeEpoch: 1, Round: 2,
		Candidates: []PathCandidate{
			plannerCandidate("manager-a", "manager-a", 1000, 0, false),
			plannerCandidate("manager-b", "manager-b", 1000, 0, false),
		},
		Demand: []DomainDemand{{Domain: domain, BytesPerSecond: 800}},
		Now:    now,
	})
	if err != nil {
		t.Fatal(err)
	}
	weightA := allocationWeight(t, result.Epoch, domain, "manager-a")
	weightB := allocationWeight(t, result.Epoch, domain, "manager-b")
	if weightA <= 0.25 || weightB <= 0.25 || weightA+weightB < 0.999 {
		t.Fatalf("weights a=%.3f b=%.3f did not distribute comparable paths", weightA, weightB)
	}
}

func TestBuildPlannerCandidatesUsesCertifiedIdentityAndPathTypes(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	families := BuildPathFamilies([]model.CommitteeMember{
		{ID: "manager-a", ForwardingEnabled: true},
		{ID: "manager-b", ForwardingEnabled: true},
	}, model.NetworkSettings{DirectPathEnabled: true, ViaManagerEnabled: true, MaxManagerHops: 2})
	telemetry := []EdgeTelemetry{
		{EdgeID: "face:manager-a", ManagerID: "manager-a", RTTMilliseconds: 10, JitterMilliseconds: 1, MeasuredBandwidth: 100, UpdatedAt: now},
		{EdgeID: "face:manager-b", ManagerID: "manager-b", RTTMilliseconds: 15, JitterMilliseconds: 2, MeasuredBandwidth: 100, UpdatedAt: now},
	}
	capacities := []ManagerCapacityUsage{{ManagerID: "manager-a", MonthlyLimitBytes: 1000, UsedMonthlyBytes: 100, ResetAt: now.Add(time.Hour)}}
	candidates := BuildPlannerCandidates(families, telemetry, capacities, now)
	if len(candidates) != len(families) {
		t.Fatalf("candidates = %d, families = %d", len(candidates), len(families))
	}
	for _, candidate := range candidates {
		if candidate.Profile.Type == "" {
			t.Fatalf("candidate %s has no path type", candidate.Family.ID)
		}
		score := path.Score(candidate.Profile, path.Constraints{
			FlowClass: path.FlowLatency, AllowedTypes: []path.PathType{candidate.Profile.Type},
		})
		if score <= 0 {
			t.Fatalf("candidate %s scored %f", candidate.Family.ID, score)
		}
	}
	firstHash, err := CandidateSetHash(candidates)
	if err != nil {
		t.Fatal(err)
	}
	telemetry[0].RTTMilliseconds = 100
	telemetry[0].MeasuredBandwidth = 10
	changed := BuildPlannerCandidates(families, telemetry, capacities, now)
	secondHash, err := CandidateSetHash(changed)
	if err != nil {
		t.Fatal(err)
	}
	if string(firstHash) != string(secondHash) {
		t.Fatal("runtime telemetry changed the certified candidate-set hash")
	}
}

func TestFamilyAllowsWildcardScopes(t *testing.T) {
	family := PathFamily{
		SourceManagerIDs:  []string{"*"},
		SourceGroups:      []string{"*"},
		DestinationScopes: []string{"*"},
		FlowClasses:       []path.FlowClass{path.FlowLatency},
	}
	domain := RoutingDomainKey{
		SourceManagerID: "manager-a", SourceGroupID: "clients",
		DestinationScope: "group:servers", FlowClass: path.FlowLatency,
	}
	if !familyAllows(domain, family) {
		t.Fatal("wildcard family scope did not match an explicit routing domain")
	}

	family.SourceGroups = []string{"servers"}
	if familyAllows(domain, family) {
		t.Fatal("explicit family source group matched another source group")
	}
}

func TestGlobalPlannerShiftsMonthlyCapacityPressure(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	domain := RoutingDomainKey{DestinationScope: "group:servers", FlowClass: path.FlowCost}
	result, err := PlanRoutingEpoch(PlannerInput{
		NetworkID: "net", SnapshotHash: plannerSnapshotHash, CommitteeEpoch: 1,
		Candidates: []PathCandidate{
			plannerCandidate("manager-a", "manager-a", 1000, 0.9, false),
			plannerCandidate("manager-b", "manager-b", 1000, 0, false),
		},
		Demand: []DomainDemand{{Domain: domain, BytesPerSecond: 800}},
		Now:    now,
	})
	if err != nil {
		t.Fatal(err)
	}
	weightA := allocationWeight(t, result.Epoch, domain, "manager-a")
	weightB := allocationWeight(t, result.Epoch, domain, "manager-b")
	if weightB <= weightA {
		t.Fatalf("monthly pressure did not shift traffic: a=%.3f b=%.3f", weightA, weightB)
	}
}

func TestGlobalPlannerExcludesProjectedExhaustionWhenAlternativeExists(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	domain := RoutingDomainKey{DestinationScope: "*", FlowClass: path.FlowLatency}
	result, err := PlanRoutingEpoch(PlannerInput{
		NetworkID: "net", SnapshotHash: plannerSnapshotHash, CommitteeEpoch: 1,
		Candidates: []PathCandidate{
			plannerCandidate("manager-a", "manager-a", 1000, 0, true),
			plannerCandidate("manager-b", "manager-b", 1000, 0, false),
		},
		Demand: []DomainDemand{{Domain: domain, BytesPerSecond: 100}},
		Now:    now,
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, allocation := range result.Epoch.Allocations {
		if allocation.Domain == domain && allocation.PathID == "manager-a" {
			t.Fatalf("projected-exhaustion path received weight %.3f", allocation.Weight)
		}
	}
}

func TestRealtimeFlowStaysPinnedDuringOrdinaryRebalance(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	domain := RoutingDomainKey{DestinationScope: "group:calls", FlowClass: path.FlowRealtime}
	result, err := PlanRoutingEpoch(PlannerInput{
		NetworkID: "net", SnapshotHash: plannerSnapshotHash, CommitteeEpoch: 1,
		Candidates: []PathCandidate{
			plannerCandidate("manager-a", "manager-a", 1000, 0, false),
			plannerCandidate("manager-b", "manager-b", 1000, 0, false),
		},
		Demand:  []DomainDemand{{Domain: domain, BytesPerSecond: 100, CurrentPathID: "manager-a"}},
		Current: []PathAllocation{{Domain: domain, PathID: "manager-a", Weight: 1}},
		Now:     now,
	})
	if err != nil {
		t.Fatal(err)
	}
	if weight := allocationWeight(t, result.Epoch, domain, "manager-a"); weight != 1 {
		t.Fatalf("realtime flow was rebalanced, weight=%.3f", weight)
	}
}

func TestRoutingEpochAndTelemetrySignaturesRejectTampering(t *testing.T) {
	public, private, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	domain := RoutingDomainKey{DestinationScope: "*", FlowClass: path.FlowLatency}
	result, err := PlanRoutingEpoch(PlannerInput{
		NetworkID: "net", SnapshotHeight: 3, SnapshotHash: plannerSnapshotHash,
		CommitteeEpoch: 1, Round: 4,
		Candidates: []PathCandidate{plannerCandidate("manager-a", "manager-a", 1000, 0, false)},
		Demand:     []DomainDemand{{Domain: domain, BytesPerSecond: 100}},
		Now:        now,
	})
	if err != nil {
		t.Fatal(err)
	}
	signed, err := SignRoutingEpoch(result.Epoch, "manager-a", Ed25519Signer{Key: private})
	if err != nil {
		t.Fatal(err)
	}
	err = VerifyRoutingEpoch(signed, Ed25519Verifier{Key: public}, now.Add(time.Second))
	if err == nil {
		t.Fatal("single-manager routing epoch verified without a committee threshold")
	}
	signed.Epoch.Allocations[0].Weight += 0.1
	if err := VerifyRoutingEpoch(signed, Ed25519Verifier{Key: public}, now.Add(time.Second)); err == nil {
		t.Fatal("tampered routing epoch verified")
	}

	telemetry := EdgeTelemetry{EdgeID: "face:manager-a", ManagerID: "manager-a", UpdatedAt: now}
	signedTelemetry, err := SignEdgeTelemetry(telemetry, Ed25519Signer{Key: private})
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyEdgeTelemetry(signedTelemetry, Ed25519Verifier{Key: public}); err != nil {
		t.Fatal(err)
	}
	signedTelemetry.Telemetry.QueueDepth = 10
	if err := VerifyEdgeTelemetry(signedTelemetry, Ed25519Verifier{Key: public}); err == nil {
		t.Fatal("tampered telemetry verified")
	}
}

func TestRoutingEpochThresholdSignature(t *testing.T) {
	identities := []string{"manager-a", "manager-b", "manager-c"}
	points := make([]bls12381fr.Element, len(identities))
	for index, identity := range identities {
		points[index] = bls.PointForIdentity(identity)
	}
	keys, err := bls.DeriveKeySet([]byte("test-seed"), 3, points)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	domain := RoutingDomainKey{DestinationScope: "*", FlowClass: path.FlowRealtime}
	result, err := PlanRoutingEpoch(PlannerInput{
		NetworkID: "net", SnapshotHash: plannerSnapshotHash, CommitteeEpoch: 1, Round: 5,
		Candidates: []PathCandidate{plannerCandidate("manager-a", "manager-a", 1000, 0, false)},
		Demand:     []DomainDemand{{Domain: domain, BytesPerSecond: 100}},
		Now:        now,
	})
	if err != nil {
		t.Fatal(err)
	}
	result.Epoch.ManagerID = identities[0]
	shares := make(map[int][]byte, len(identities))
	signers := make(map[int]string, len(identities))
	for index, identity := range identities {
		share, err := SignRoutingEpochShare(result.Epoch, identity, keys, index)
		if err != nil {
			t.Fatal(err)
		}
		shares[index] = share.Signature
		signers[index] = identity
	}
	signed, err := AggregateRoutingEpochShares(result.Epoch, shares, signers, keys)
	if err != nil {
		t.Fatal(err)
	}
	if !signed.ThresholdSigned || signed.Threshold != 3 || len(signed.Signers) != 3 {
		t.Fatalf("threshold metadata = %+v", signed)
	}
	if err := VerifyRoutingEpoch(signed, BLSVerifier{GroupPublicKey: keys.GroupPublicKey}, now.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	delete(shares, 1)
	delete(signers, 1)
	if _, err := AggregateRoutingEpochShares(result.Epoch, shares, signers, keys); err == nil {
		t.Fatal("two of three shares produced a threshold epoch")
	}
}

func TestSignedDemandReportAggregatesClientDemand(t *testing.T) {
	public, private, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 1, 1, 0, 0, 10, 0, time.UTC)
	report := DemandReport{
		PeerID: "peer-a", WindowStart: now.Add(-10 * time.Second), WindowEnd: now,
		Samples: []DemandSample{
			{PeerID: "peer-a", SourceGroupID: "clients", DestinationScope: "group:servers", FlowClass: path.FlowThroughput, PathID: "manager-a", Bytes: 100, DurationMS: 10000, ObservedAt: now.Add(-5 * time.Second)},
			{PeerID: "peer-a", SourceGroupID: "clients", DestinationScope: "group:servers", FlowClass: path.FlowThroughput, PathID: "manager-b", Bytes: 300, DurationMS: 10000, ObservedAt: now.Add(-5 * time.Second)},
		},
	}
	signed, err := SignDemandReport(report, Ed25519Signer{Key: private})
	if err != nil {
		t.Fatal(err)
	}
	verifier := StaticDemandReportVerifier(Ed25519Verifier{Key: public})
	demand, err := AggregateDemandReports([]SignedDemandReport{signed}, verifier, now, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if len(demand) != 1 {
		t.Fatalf("demand domains = %d, want 1", len(demand))
	}
	if demand[0].BytesPerSecond != 40 || demand[0].CurrentPathID != "manager-b" {
		t.Fatalf("unexpected demand %+v", demand[0])
	}
	signed.Report.Samples[0].Bytes = 10000
	if _, err := AggregateDemandReports([]SignedDemandReport{signed}, verifier, now, time.Minute); err == nil {
		t.Fatal("tampered demand report aggregated")
	}
}

func TestAllFiveFlowClassesArePlannable(t *testing.T) {
	classes := []path.FlowClass{path.FlowLatency, path.FlowThroughput, path.FlowCost, path.FlowReliability, path.FlowRealtime}
	for _, class := range classes {
		domain := RoutingDomainKey{DestinationScope: "*", FlowClass: class}
		result, err := PlanRoutingEpoch(PlannerInput{
			NetworkID: "net", SnapshotHash: plannerSnapshotHash, CommitteeEpoch: 1,
			Candidates: []PathCandidate{
				plannerCandidate("manager-a", "manager-a", 1000, 0, false),
				plannerCandidate("manager-b", "manager-b", 1000, 0, false),
			},
			Demand: []DomainDemand{{Domain: domain, BytesPerSecond: 100}},
			Now:    time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
		})
		if err != nil {
			t.Fatalf("%s: %v", class, err)
		}
		found := false
		fec := false
		for _, allocation := range result.Epoch.Allocations {
			if allocation.Domain != domain {
				continue
			}
			found = true
			fec = fec || allocation.FEC
		}
		if !found {
			t.Fatalf("class %s produced no allocation", class)
		}
		if (class == path.FlowRealtime) != fec {
			t.Fatalf("class %s fec=%v", class, fec)
		}
	}
}

func TestHotDomainExpansionIsBounded(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	base := RoutingDomainKey{DestinationScope: "group:servers", FlowClass: path.FlowThroughput}
	smallOne := base
	smallOne.HotKey = "small-1"
	smallTwo := base
	smallTwo.HotKey = "small-2"
	demand := []DomainDemand{
		{Domain: base, BytesPerSecond: 100},
		{Domain: smallOne, BytesPerSecond: 1, CurrentPathID: "manager-a"},
		{Domain: smallTwo, BytesPerSecond: 2, CurrentPathID: "manager-a"},
	}
	result, err := PlanRoutingEpoch(PlannerInput{
		NetworkID: "net", SnapshotHash: plannerSnapshotHash, CommitteeEpoch: 1,
		Candidates: []PathCandidate{
			plannerCandidate("manager-a", "manager-a", 1000, 0, false),
			plannerCandidate("manager-b", "manager-b", 1000, 0, false),
		},
		Demand: demand, Now: now,
		Config: PlannerConfig{MaxHotDomains: 1},
	})
	if err != nil {
		t.Fatal(err)
	}
	hotDomains := 0
	for _, allocation := range result.Epoch.Allocations {
		if allocation.Domain.HotKey != "" {
			hotDomains++
		}
	}
	if hotDomains == 0 {
		t.Fatal("highest-demand hot key was not retained")
	}
	if len(result.Epoch.Allocations) > 6 {
		t.Fatalf("hot expansion produced %d allocations", len(result.Epoch.Allocations))
	}
}

func TestPlannerScalesToOneHundredThousandPeers(t *testing.T) {
	state := model.NetworkState{Settings: model.NetworkSettings{DefaultFlowClass: string(path.FlowThroughput)}}
	state.Peers = make([]model.PeerRecord, 100000)
	for index := range state.Peers {
		state.Peers[index] = model.PeerRecord{PeerID: fmt.Sprintf("peer-%06d", index), Groups: []string{fmt.Sprintf("g%03d", index%100)}}
	}
	for index := 0; index < 100; index++ {
		state.Policies = append(state.Policies, model.Policy{
			ID: fmt.Sprintf("policy-%03d", index), SourceGroups: []string{fmt.Sprintf("g%03d", index)},
			DestinationGroups: []string{"servers"}, Effect: model.EffectAllow,
			Direction: model.DirectionBidirectional, FlowClass: string(path.FlowThroughput),
		})
	}
	domains := BuildRoutingDomains(state)
	if len(domains) != 101 {
		t.Fatalf("routing domains = %d, want 100 policy domains plus the default fallback", len(domains))
	}
	demand := make([]DomainDemand, 0, len(domains))
	for _, domain := range domains {
		demand = append(demand, DomainDemand{Domain: domain, BytesPerSecond: 100})
	}
	candidates := []PathCandidate{
		plannerCandidate("manager-a", "manager-a", 100000, 0, false),
		plannerCandidate("manager-b", "manager-b", 100000, 0, false),
		plannerCandidate("manager-c", "manager-c", 100000, 0, false),
	}
	start := time.Now()
	result, err := PlanRoutingEpoch(PlannerInput{
		NetworkID: "net", SnapshotHeight: 20, SnapshotHash: plannerSnapshotHash,
		CommitteeEpoch: 1, Candidates: candidates,
		Demand: demand, Now: start.UTC(),
	})
	if err != nil {
		t.Fatal(err)
	}
	elapsed := time.Since(start)
	if elapsed > 250*time.Millisecond {
		t.Fatalf("100k-peer planner took %s, budget 250ms", elapsed)
	}
	if len(result.Epoch.Allocations) != 303 {
		t.Fatalf("allocations = %d, want 303 domain-path entries", len(result.Epoch.Allocations))
	}
	encoded, err := json.Marshal(result.Epoch)
	if err != nil {
		t.Fatal(err)
	}
	if len(encoded) >= 5<<20 {
		t.Fatalf("epoch size = %d bytes, budget 5MB", len(encoded))
	}
	t.Logf("100k peers: domains=%d allocations=%d epoch=%d bytes planner=%s", len(domains), len(result.Epoch.Allocations), len(encoded), elapsed)
}

func BenchmarkPlanRoutingEpoch100KPeers(b *testing.B) {
	domains := make([]RoutingDomainKey, 100)
	demand := make([]DomainDemand, len(domains))
	for index := range domains {
		domains[index] = RoutingDomainKey{DestinationScope: fmt.Sprintf("group:servers-%d", index), FlowClass: path.FlowThroughput}
		demand[index] = DomainDemand{Domain: domains[index], BytesPerSecond: 100}
	}
	candidates := []PathCandidate{
		plannerCandidate("manager-a", "manager-a", 100000, 0, false),
		plannerCandidate("manager-b", "manager-b", 100000, 0, false),
		plannerCandidate("manager-c", "manager-c", 100000, 0, false),
	}
	b.ResetTimer()
	for index := 0; index < b.N; index++ {
		if _, err := PlanRoutingEpoch(PlannerInput{
			NetworkID: "net", SnapshotHeight: 20, SnapshotHash: plannerSnapshotHash,
			CommitteeEpoch: 1, Candidates: candidates,
			Demand: demand, Now: time.Now().UTC(),
		}); err != nil {
			b.Fatal(err)
		}
	}
}
