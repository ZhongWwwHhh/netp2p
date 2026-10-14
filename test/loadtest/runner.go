package loadtest

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"time"

	"github.com/netp2p/netp2p/internal/version"
)

type VerificationOptions struct {
	Scenario      string
	Config        ScaleConfig
	RegistryPeers int
	ShardCount    int
	RegistryRoot  string
	KeepRegistry  bool
	SampleCount   int
}

type DurationMetric struct {
	Duration time.Duration `json:"duration"`
	P50      time.Duration `json:"p50"`
	P99      time.Duration `json:"p99"`
	Max      time.Duration `json:"max"`
}

type VerificationManifest struct {
	Scenario        string           `json:"scenario"`
	GeneratedAt     time.Time        `json:"generatedAt"`
	Version         string           `json:"version"`
	Protocol        string           `json:"protocol"`
	GoVersion       string           `json:"goVersion"`
	OS              string           `json:"os"`
	Arch            string           `json:"arch"`
	Config          ScaleConfig      `json:"config"`
	RegistryPeers   int              `json:"registryPeers"`
	ShardCount      int              `json:"shardCount"`
	Optimizer       OptimizerMetrics `json:"optimizer"`
	EpochBytes      int              `json:"epochBytes"`
	FlowEntries     int              `json:"flowEntries"`
	FlowInsert      time.Duration    `json:"flowInsert"`
	FlowLookup      DurationMetric   `json:"flowLookup"`
	FlowMemory      int64            `json:"flowMemoryBytes"`
	Authorization   DurationMetric   `json:"authorization"`
	TimingBatchSize int              `json:"timingBatchSize"`
	AuthSamples     int              `json:"authSamples"`
	AuthErrors      int              `json:"authErrors"`
	RegistryCreate  time.Duration    `json:"registryCreate"`
	RegistryQuery   DurationMetric   `json:"registryQuery"`
	RegistryDisk    int64            `json:"registryDiskBytes"`
	MerkleRoot      string           `json:"merkleRoot"`
	BootstrapBytes  int              `json:"scopedBootstrapBytes"`
	DeltaBytes      int              `json:"scopedDeltaBytes"`
	Pass            bool             `json:"pass"`
	Failures        []string         `json:"failures,omitempty"`
	Command         []string         `json:"command"`
}

type scopedBootstrap struct {
	NetworkID         string       `json:"networkId"`
	PeerID            string       `json:"peerId"`
	ManagerID         string       `json:"managerId"`
	Groups            []string     `json:"groups"`
	DestinationScopes []string     `json:"destinationScopes"`
	Families          []PathFamily `json:"families"`
	MerkleRoot        string       `json:"merkleRoot"`
}

type scopedDelta struct {
	NetworkID   string           `json:"networkId"`
	PeerID      string           `json:"peerId"`
	Allocations []PathAllocation `json:"allocations"`
}

func percentile(values []time.Duration, fraction float64) time.Duration {
	if len(values) == 0 {
		return 0
	}
	sorted := append([]time.Duration(nil), values...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i] < sorted[j] })
	index := int(float64(len(sorted)-1) * fraction)
	return sorted[index]
}

func summarizeDurations(values []time.Duration) DurationMetric {
	total := time.Duration(0)
	for _, value := range values {
		total += value
	}
	return DurationMetric{
		Duration: total,
		P50:      percentile(values, .50),
		P99:      percentile(values, .99),
		Max:      percentile(values, 1),
	}
}

func heapAfterGC() uint64 {
	runtime.GC()
	var stats runtime.MemStats
	runtime.ReadMemStats(&stats)
	return stats.HeapAlloc
}

func RunScaleVerification(ctx context.Context, options VerificationOptions) (*VerificationManifest, error) {
	if options.SampleCount <= 0 {
		options.SampleCount = 100000
	}
	if options.ShardCount <= 0 {
		options.ShardCount = 16
	}
	fixture, err := BuildScaleFixture(options.Config, true)
	if err != nil {
		return nil, err
	}
	demands := BuildDemands(fixture)
	now := time.Now().UTC()
	epoch, optimizerMetrics, err := Optimize(OptimizerInput{
		NetworkID:      "loadtest",
		SnapshotHeight: 1,
		Version:        1,
		ManagerID:      "manager-00",
		GeneratedAt:    now,
		ExpiresAt:      now.Add(15 * time.Second),
		Paths:          fixture.Paths,
		Demands:        demands,
		EdgeCapacity:   fixture.EdgeCapacity,
		CandidateHash:  CandidateSetHash(fixture.Families),
	}, DefaultOptimizerConfig())
	if err != nil {
		return nil, err
	}
	encodedEpoch, err := EncodeEpoch(epoch)
	if err != nil {
		return nil, err
	}

	allocationIndex := make(map[RoutingDomainKey]PathAllocation, len(epoch.Allocations))
	for _, allocation := range epoch.Allocations {
		allocationIndex[allocation.Key] = allocation
	}
	optimizerKey := func(key RoutingDomainKey) RoutingDomainKey {
		key.SourceManagerID = "manager-aggregated"
		key.SourceGroupID = "source-group-all"
		return key
	}
	pathInstances := make(map[string]string, len(fixture.Families))
	for _, family := range fixture.Families {
		pathInstances[family.ID] = PathInstanceIDs(family)[0]
	}

	memoryBefore := heapAfterGC()
	table := NewFlowTable(64, options.Config.Flows)
	flowInsertStarted := time.Now()
	for index, flow := range fixture.Flows {
		sourceIndex := index % options.Config.Peers
		destinationIndex := (index*7919 + 1) % options.Config.Peers
		class := AllFlowClasses[index%len(AllFlowClasses)]
		key := RoutingDomainKey{
			SourceManagerID:  managerID(options.Config, sourceIndex),
			SourceGroupID:    sourceGroupID(options.Config, sourceIndex),
			DestinationScope: destinationScopeID(options.Config, destinationIndex),
			FlowClass:        class,
		}
		allocation := allocationIndex[optimizerKey(key)]
		pathID, err := SelectPath(flow, allocation.Paths, "path-direct", class == FlowRealtime, nil)
		if err != nil {
			return nil, err
		}
		table.Observe(FlowEntry{
			Key: flow, DestinationID: fixture.Peers[destinationIndex].PeerID, Domain: key,
			FlowClass: class, PathID: pathID, Bytes: 1200, LastUsedAt: now,
		})
	}
	flowInsert := time.Since(flowInsertStarted)
	memoryAfter := heapAfterGC()
	if table.Len() != options.Config.Flows {
		return nil, fmt.Errorf("flow table contains %d entries, want %d", table.Len(), options.Config.Flows)
	}

	const timingBatchSize = 256
	lookupSamples := make([]time.Duration, 0, options.SampleCount)
	for index := 0; index < options.SampleCount && index < len(fixture.Flows); index++ {
		flow := fixture.Flows[(index*104729)%len(fixture.Flows)]
		started := time.Now()
		for batch := 0; batch < timingBatchSize; batch++ {
			if _, ok := table.Lookup(flow); !ok {
				return nil, fmt.Errorf("flow lookup miss at sample %d", index)
			}
		}
		lookupSamples = append(lookupSamples, time.Since(started)/timingBatchSize)
	}
	sort.Slice(lookupSamples, func(i, j int) bool { return lookupSamples[i] < lookupSamples[j] })
	lookupMetric := summarizeDurations(lookupSamples)

	authorizationSamples := make([]time.Duration, 0, options.SampleCount)
	authorizationErrors := 0
	for index := 0; index < options.SampleCount && index < len(fixture.Flows); index++ {
		flowIndex := (index * 104729) % len(fixture.Flows)
		flow := fixture.Flows[flowIndex]
		sourceIndex := flowIndex % options.Config.Peers
		destinationIndex := (flowIndex*7919 + 1) % options.Config.Peers
		class := AllFlowClasses[flowIndex%len(AllFlowClasses)]
		key := RoutingDomainKey{
			SourceManagerID:  managerID(options.Config, sourceIndex),
			SourceGroupID:    sourceGroupID(options.Config, sourceIndex),
			DestinationScope: destinationScopeID(options.Config, destinationIndex),
			FlowClass:        class,
		}
		allocation := allocationIndex[optimizerKey(key)]
		pathID := allocation.Paths[flowIndex%len(allocation.Paths)].PathID
		envelope := ForwardingEnvelope{
			SourcePeerID:      fixture.Peers[sourceIndex].PeerID,
			DestinationPeerID: fixture.Peers[destinationIndex].PeerID,
			Domain:            key, PathFamilyID: pathID, PathInstanceID: pathInstances[pathID],
			FlowClass: class, Protocol: flow.Protocol, DestinationPort: flow.DestinationPort,
			FlowHash: FlowHash(flow), Sequence: uint64(flowIndex), TTL: 8,
			Payload: []byte{0x45, 0, 0, 0},
		}
		started := time.Now()
		for batch := 0; batch < timingBatchSize; batch++ {
			if err := fixture.Authorization.AuthorizeEnvelope(envelope); err != nil {
				authorizationErrors++
			}
		}
		authorizationSamples = append(authorizationSamples, time.Since(started)/timingBatchSize)
	}
	sort.Slice(authorizationSamples, func(i, j int) bool { return authorizationSamples[i] < authorizationSamples[j] })
	authorizationMetric := summarizeDurations(authorizationSamples)

	registryRoot := options.RegistryRoot
	if registryRoot == "" {
		registryRoot = filepath.Join("tmp", "doc", "verification", fmt.Sprintf("registry-%s", now.Format("20060102T150405Z")))
	}
	registryCreateStarted := time.Now()
	registry, err := CreateShardedRegistry(ctx, registryRoot, options.ShardCount, options.RegistryPeers, RegistryPeerGenerator(options.Config))
	if err != nil {
		return nil, err
	}
	registryCreate := time.Since(registryCreateStarted)
	registryQuerySamples := make([]time.Duration, 0, options.SampleCount)
	for index := 0; index < options.SampleCount && index < options.RegistryPeers; index++ {
		peerIndex := (index * 104729) % options.RegistryPeers
		peerID := fmt.Sprintf("peer-%07d", peerIndex)
		started := time.Now()
		record, err := registry.Peer(ctx, peerID)
		if err != nil {
			_ = registry.Close()
			return nil, fmt.Errorf("query registry peer %s: %w", peerID, err)
		}
		if record.PeerID != peerID || record.OverlayIP != overlayIP(peerIndex) {
			_ = registry.Close()
			return nil, fmt.Errorf("registry peer %s did not round-trip", peerID)
		}
		registryQuerySamples = append(registryQuerySamples, time.Since(started))
	}
	sort.Slice(registryQuerySamples, func(i, j int) bool { return registryQuerySamples[i] < registryQuerySamples[j] })
	registryQueryMetric := summarizeDurations(registryQuerySamples)
	if err := registry.Checkpoint(); err != nil {
		_ = registry.Close()
		return nil, err
	}
	registryDisk, err := registry.DiskUsageBytes()
	if err != nil {
		_ = registry.Close()
		return nil, err
	}
	merkleRootBytes, err := registry.MerkleRoot(ctx)
	if err != nil {
		_ = registry.Close()
		return nil, err
	}
	merkleRoot := fmt.Sprintf("%x", merkleRootBytes)
	if err := registry.Close(); err != nil {
		return nil, err
	}
	if !options.KeepRegistry {
		if err := os.RemoveAll(registryRoot); err != nil {
			return nil, err
		}
	}

	firstPeer := fixture.Peers[0]
	bootstrap := scopedBootstrap{
		NetworkID: "loadtest", PeerID: firstPeer.PeerID, ManagerID: managerID(options.Config, 0),
		Groups: firstPeer.Groups, DestinationScopes: []string{destinationScopeID(options.Config, 0)},
		Families: fixture.Families, MerkleRoot: merkleRoot,
	}
	bootstrapJSON, err := json.Marshal(bootstrap)
	if err != nil {
		return nil, err
	}
	deltaAllocations := make([]PathAllocation, 0, len(AllFlowClasses))
	for _, class := range AllFlowClasses {
		key := RoutingDomainKey{
			SourceManagerID: managerID(options.Config, 0), SourceGroupID: sourceGroupID(options.Config, 0),
			DestinationScope: destinationScopeID(options.Config, 0), FlowClass: class,
		}
		if allocation, exists := allocationIndex[optimizerKey(key)]; exists {
			deltaAllocations = append(deltaAllocations, allocation)
		}
	}
	delta := scopedDelta{NetworkID: "loadtest", PeerID: firstPeer.PeerID, Allocations: deltaAllocations}
	deltaJSON, err := json.Marshal(delta)
	if err != nil {
		return nil, err
	}

	manifest := &VerificationManifest{
		Scenario: options.Scenario, GeneratedAt: now, Version: version.Version, Protocol: version.ProtocolVersion,
		GoVersion: runtime.Version(), OS: runtime.GOOS, Arch: runtime.GOARCH,
		Config: options.Config, RegistryPeers: options.RegistryPeers, ShardCount: options.ShardCount,
		Optimizer: optimizerMetrics, EpochBytes: len(encodedEpoch), FlowEntries: table.Len(),
		FlowInsert: flowInsert, FlowLookup: lookupMetric, FlowMemory: int64(memoryAfter - memoryBefore),
		Authorization: authorizationMetric, AuthSamples: len(authorizationSamples), AuthErrors: authorizationErrors,
		RegistryCreate: registryCreate, RegistryQuery: registryQueryMetric, RegistryDisk: registryDisk,
		MerkleRoot: merkleRoot, BootstrapBytes: len(bootstrapJSON), DeltaBytes: len(deltaJSON),
		TimingBatchSize: timingBatchSize,
		Command:         []string{"go", "run", "./test/loadtest/cmd", "--scenario", options.Scenario},
	}
	if options.Config.Peers >= 100000 && optimizerMetrics.Duration > 250*time.Millisecond {
		manifest.Failures = append(manifest.Failures, fmt.Sprintf("optimizer duration %s exceeds 250ms", optimizerMetrics.Duration))
	}
	if len(encodedEpoch) > 5*1024*1024 {
		manifest.Failures = append(manifest.Failures, fmt.Sprintf("epoch size %d exceeds 5MB", len(encodedEpoch)))
	}
	if options.Config.Flows >= 1000000 && manifest.FlowMemory > 512*1024*1024 {
		manifest.Failures = append(manifest.Failures, fmt.Sprintf("flow memory %d exceeds 512MB", manifest.FlowMemory))
	}
	if authorizationMetric.P99 > 20*time.Microsecond {
		manifest.Failures = append(manifest.Failures, fmt.Sprintf("authorization p99 %s exceeds 20us", authorizationMetric.P99))
	}
	if authorizationErrors != 0 {
		manifest.Failures = append(manifest.Failures, fmt.Sprintf("authorization errors %d", authorizationErrors))
	}
	if options.RegistryPeers >= 1000000 && registryQueryMetric.P99 > 20*time.Millisecond {
		manifest.Failures = append(manifest.Failures, fmt.Sprintf("registry query p99 %s exceeds 20ms", registryQueryMetric.P99))
	}
	if len(bootstrapJSON) > 10*1024*1024 {
		manifest.Failures = append(manifest.Failures, fmt.Sprintf("scoped bootstrap %d exceeds 10MB", len(bootstrapJSON)))
	}
	if len(deltaJSON) > 1024*1024 {
		manifest.Failures = append(manifest.Failures, fmt.Sprintf("scoped delta %d exceeds 1MB", len(deltaJSON)))
	}
	manifest.Pass = len(manifest.Failures) == 0
	return manifest, nil
}

func WriteManifest(manifest *VerificationManifest, path string) error {
	if path == "" {
		return fmt.Errorf("manifest path is required")
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	encoded, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(encoded, '\n'), 0o600)
}
