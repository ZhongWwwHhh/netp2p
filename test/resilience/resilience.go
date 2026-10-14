// Package resilience runs local fault-injection and adversarial traffic
// scenarios against the production manager, BFT, transport, forwarding, quota,
// packet, and SQLite implementations. It never dials anything outside the
// process's loopback listeners.
package resilience

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"sync/atomic"
	"time"

	"github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/netp2p/netp2p/internal/bft"
	"github.com/netp2p/netp2p/internal/chaos"
	"github.com/netp2p/netp2p/internal/forward"
	"github.com/netp2p/netp2p/internal/manager"
	"github.com/netp2p/netp2p/internal/model"
	"github.com/netp2p/netp2p/internal/p2p"
	"github.com/netp2p/netp2p/internal/packet"
	"github.com/netp2p/netp2p/internal/store"
	"github.com/netp2p/netp2p/internal/transport"
)

const (
	SeverityCritical = "critical"
	SeverityHigh     = "high"
	SeverityMedium   = "medium"
	SeverityLow      = "low"
)

type Options struct {
	PacketStormFrames  int
	PacketPayloadBytes int
	QuotaPackets       int
	ScenarioTimeout    time.Duration
	Root               string
	KeepRoot           bool
}

type DurationMetric struct {
	P50 time.Duration `json:"p50"`
	P99 time.Duration `json:"p99"`
	Max time.Duration `json:"max"`
}

type ResourceUsage struct {
	WallClock      time.Duration `json:"wallClock"`
	CPUTime        time.Duration `json:"cpuTime"`
	HeapAllocBytes uint64        `json:"heapAllocBytes"`
	HeapObjects    uint64        `json:"heapObjects"`
	Goroutines     int           `json:"goroutines"`
}

type ManagerRestartResult struct {
	CommitteeSize            int           `json:"committeeSize"`
	QuorumSize               int           `json:"quorumSize"`
	GenesisCommit            time.Duration `json:"genesisCommit"`
	CommitDuringDowntime     time.Duration `json:"commitDuringDowntime"`
	RestoreLedger            time.Duration `json:"restoreLedger"`
	CatchUp                  time.Duration `json:"catchUp"`
	PostRestartCommit        time.Duration `json:"postRestartCommit"`
	TotalRecovery            time.Duration `json:"totalRecovery"`
	HeightDuringDowntime     uint64        `json:"heightDuringDowntime"`
	RestartedHeightBeforeUse uint64        `json:"restartedHeightBeforeUse"`
	FinalHeight              uint64        `json:"finalHeight"`
	StateHashesMatch         bool          `json:"stateHashesMatch"`
	Resource                 ResourceUsage `json:"resource"`
}

type CommitteeFailureResult struct {
	CommitteeSize       int           `json:"committeeSize"`
	QuorumSize          int           `json:"quorumSize"`
	IsolatedManager     string        `json:"isolatedManager"`
	BlockedWriteLatency time.Duration `json:"blockedWriteLatency"`
	BlockedWriteError   string        `json:"blockedWriteError"`
	HeightDuringFailure uint64        `json:"heightDuringFailure"`
	HealAndCatchUp      time.Duration `json:"healAndCatchUp"`
	CommitAfterHeal     time.Duration `json:"commitAfterHeal"`
	TotalRecovery       time.Duration `json:"totalRecovery"`
	FinalHeight         uint64        `json:"finalHeight"`
	DroppedMessages     uint64        `json:"droppedMessages"`
	StateHashesMatch    bool          `json:"stateHashesMatch"`
	Resource            ResourceUsage `json:"resource"`
}

type PacketStormResult struct {
	Frames              int            `json:"frames"`
	PayloadBytes        int            `json:"payloadBytes"`
	EnqueueLatency      DurationMetric `json:"enqueueLatency"`
	EndToEndBatch       DurationMetric `json:"endToEndBatch"`
	SendDuration        time.Duration  `json:"sendDuration"`
	StormDuration       time.Duration  `json:"stormDuration"`
	Enqueued            int            `json:"enqueued"`
	Delivered           int            `json:"delivered"`
	QueueFullErrors     int            `json:"queueFullErrors"`
	TransportDropped    uint64         `json:"transportDropped"`
	TransportSent       uint64         `json:"transportSent"`
	ThroughputPPS       float64        `json:"throughputPps"`
	GoodputMBPS         float64        `json:"goodputMbps"`
	RecoveryProbe       time.Duration  `json:"recoveryProbe"`
	MalformedCases      int            `json:"malformedCases"`
	MalformedRejected   int            `json:"malformedRejected"`
	MalformedCaseErrors []string       `json:"malformedCaseErrors,omitempty"`
	Resource            ResourceUsage  `json:"resource"`
}

type QuotaResult struct {
	PayloadBytes         int           `json:"payloadBytes"`
	BudgetBytes          uint64        `json:"budgetBytes"`
	ExpectedAllowed      int           `json:"expectedAllowed"`
	ObservedAllowed      int           `json:"observedAllowed"`
	BlockedFrames        int           `json:"blockedFrames"`
	ExhaustionLatency    time.Duration `json:"exhaustionLatency"`
	AllowedThroughputPPS float64       `json:"allowedThroughputPps"`
	RecoveryCommit       time.Duration `json:"recoveryCommit"`
	Recovered            bool          `json:"recovered"`
	Resource             ResourceUsage `json:"resource"`
}

type Finding struct {
	ID             string `json:"id"`
	Scenario       string `json:"scenario"`
	Severity       string `json:"severity"`
	Summary        string `json:"summary"`
	Observed       string `json:"observed"`
	Recommendation string `json:"recommendation"`
}

type Manifest struct {
	GeneratedAt      time.Time              `json:"generatedAt"`
	Options          Options                `json:"options"`
	ManagerRestart   ManagerRestartResult   `json:"managerRestart"`
	NetworkPartition CommitteeFailureResult `json:"networkPartition"`
	BFTStall         CommitteeFailureResult `json:"bftStall"`
	PacketStorm      PacketStormResult      `json:"packetStorm"`
	QuotaExhaustion  QuotaResult            `json:"quotaExhaustion"`
	Overall          ResourceUsage          `json:"overall"`
	Findings         []Finding              `json:"findings"`
	Pass             bool                   `json:"pass"`
}

func DefaultOptions() Options {
	return Options{
		PacketStormFrames:  100_000,
		PacketPayloadBytes: 1200,
		QuotaPackets:       100,
		ScenarioTimeout:    60 * time.Second,
	}
}

type resourceSnapshot struct {
	wall        time.Time
	cpu         time.Duration
	heapAlloc   uint64
	heapObjects uint64
	goroutines  int
}

func takeResourceSnapshot() resourceSnapshot {
	runtime.GC()
	var stats runtime.MemStats
	runtime.ReadMemStats(&stats)
	cpu, _ := processCPUTime()
	return resourceSnapshot{
		wall: time.Now(), cpu: cpu, heapAlloc: stats.HeapAlloc,
		heapObjects: stats.HeapObjects, goroutines: runtime.NumGoroutine(),
	}
}

func resourceDelta(before, after resourceSnapshot) ResourceUsage {
	cpu := after.cpu - before.cpu
	if cpu < 0 {
		cpu = 0
	}
	return ResourceUsage{
		WallClock: after.wall.Sub(before.wall), CPUTime: cpu,
		HeapAllocBytes: after.heapAlloc, HeapObjects: after.heapObjects,
		Goroutines: after.goroutines,
	}
}

func measure(ctx context.Context, options Options, run func(context.Context) error) (ResourceUsage, error) {
	before := takeResourceSnapshot()
	scenarioCtx, cancel := context.WithTimeout(ctx, options.ScenarioTimeout)
	defer cancel()
	err := run(scenarioCtx)
	after := takeResourceSnapshot()
	return resourceDelta(before, after), err
}

func percentile(values []time.Duration, fraction float64) time.Duration {
	if len(values) == 0 {
		return 0
	}
	sorted := append([]time.Duration(nil), values...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i] < sorted[j] })
	return sorted[int(float64(len(sorted)-1)*fraction)]
}

func summarize(values []time.Duration) DurationMetric {
	if len(values) == 0 {
		return DurationMetric{}
	}
	sorted := append([]time.Duration(nil), values...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i] < sorted[j] })
	return DurationMetric{P50: percentile(sorted, .50), P99: percentile(sorted, .99), Max: sorted[len(sorted)-1]}
}

type committeeGroup struct {
	ctx        context.Context
	cancel     context.CancelFunc
	members    []model.CommitteeMember
	nodes      []*p2p.Node
	engines    []*bft.Engine
	meshes     []*manager.CommitteeMesh
	managers   []*manager.Manager
	stores     []*store.Store
	controller *chaos.Controller
}

func committeeState(size, threshold uint32) model.NetworkState {
	return model.NetworkState{
		NetworkID:       "netp2p-resilience",
		OverlayCIDR:     "100.64.0.0/16",
		NextIPOffset:    1,
		CommitteeConfig: model.CommitteeConfig{Size: size, Threshold: threshold},
	}
}

func startCommittee(ctx context.Context, root string, size int, controller *chaos.Controller) (*committeeGroup, error) {
	if size < 3 {
		return nil, fmt.Errorf("committee size %d is too small", size)
	}
	threshold := size - 1
	state := committeeState(uint32(size), uint32(threshold))
	group := &committeeGroup{members: make([]model.CommitteeMember, size), controller: controller}
	group.ctx, group.cancel = context.WithTimeout(ctx, 60*time.Second)

	for index := range group.members {
		seed := int64(801 + index)
		privateKey := bft.SeededPrivateKey(seed)
		libp2pKey, _, err := crypto.KeyPairFromStdKey(&privateKey)
		if err != nil {
			group.stop()
			return nil, err
		}
		peerID, err := peer.IDFromPrivateKey(libp2pKey)
		if err != nil {
			group.stop()
			return nil, err
		}
		group.members[index] = model.CommitteeMember{
			ID: fmt.Sprintf("manager-%d", index+1), PeerID: peerID.String(),
			KeySeed: seed, ForwardingEnabled: true,
		}
	}
	for index, member := range group.members {
		node, err := p2p.New(group.ctx, p2p.Config{
			IdentitySeed: member.KeySeed,
			Listen:       []string{"/ip4/127.0.0.1/udp/0/quic-v1"},
		})
		if err != nil {
			group.stop()
			return nil, err
		}
		if controller != nil {
			node.SetSendHook(controller.HookFor(node.Host.ID()))
		}
		group.nodes = append(group.nodes, node)
		addresses := node.Addresses()
		if len(addresses) == 0 {
			group.stop()
			return nil, fmt.Errorf("manager %s has no loopback address", member.ID)
		}
		group.members[index].Address = addresses[0]
	}
	for index, member := range group.members {
		engine, err := bft.NewEngine(state, group.members, member.ID, bft.SeededPrivateKey(member.KeySeed))
		if err != nil {
			group.stop()
			return nil, err
		}
		ledger, err := store.Open(filepath.Join(root, fmt.Sprintf("manager-%d.sqlite", index)))
		if err != nil {
			group.stop()
			return nil, err
		}
		ledger.InstallCommitListener(engine)
		mesh, err := manager.NewCommitteeMesh(group.nodes[index], engine, group.members)
		if err != nil {
			_ = ledger.Close()
			group.stop()
			return nil, err
		}
		group.engines = append(group.engines, engine)
		group.stores = append(group.stores, ledger)
		group.meshes = append(group.meshes, mesh)
		group.managers = append(group.managers, manager.New(group.nodes[index], engine, mesh, manager.Config{}))
	}
	for _, mesh := range group.meshes {
		if err := mesh.Connect(group.ctx); err != nil {
			group.stop()
			return nil, err
		}
	}
	leaderID := group.engines[0].Leader(1, 0).ID
	for index, engine := range group.engines {
		if engine.LocalID() != leaderID {
			continue
		}
		if _, err := group.meshes[index].Submit(model.StateTransition{Type: bft.TransitionGenesis}); err != nil {
			group.stop()
			return nil, fmt.Errorf("genesis: %w", err)
		}
		break
	}
	if err := group.waitHeight(1); err != nil {
		group.stop()
		return nil, err
	}
	return group, nil
}

func (group *committeeGroup) stop() {
	if group.cancel != nil {
		group.cancel()
		group.cancel = nil
	}
	for _, node := range group.nodes {
		_ = node.Close()
	}
	for _, ledger := range group.stores {
		if ledger != nil {
			_ = ledger.Close()
		}
	}
}

func (group *committeeGroup) waitHeight(height uint64) error {
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		ready := true
		for _, engine := range group.engines {
			if engine.Height() < height {
				ready = false
				break
			}
		}
		if ready {
			return nil
		}
		select {
		case <-group.ctx.Done():
			return group.ctx.Err()
		case <-time.After(20 * time.Millisecond):
		}
	}
	return fmt.Errorf("committee did not reach height %d", height)
}

func runManagerRestart(ctx context.Context, root string, options Options) (ManagerRestartResult, error) {
	result := ManagerRestartResult{}
	controller := chaos.New()
	group, err := startCommittee(ctx, root, 4, controller)
	if err != nil {
		return result, err
	}
	defer group.stop()
	result.CommitteeSize = 4
	result.QuorumSize = group.engines[0].CommitteeParams().QuorumSize

	started := time.Now()
	if _, err := group.meshes[0].Submit(model.StateTransition{
		Type: bft.TransitionUpsertGroup, Group: &model.Group{ID: "before-restart"},
	}); err != nil {
		return result, fmt.Errorf("commit during downtime: %w", err)
	}
	result.CommitDuringDowntime = time.Since(started)
	if err := group.waitHeight(2); err != nil {
		return result, err
	}
	result.HeightDuringDowntime = 2

	target := 3
	if err := group.nodes[target].Close(); err != nil {
		return result, fmt.Errorf("stop manager: %w", err)
	}
	if err := group.stores[target].Close(); err != nil {
		return result, fmt.Errorf("close manager ledger: %w", err)
	}
	group.stores[target] = nil

	recoveryStarted := time.Now()
	restartedNode, err := p2p.New(group.ctx, p2p.Config{
		IdentitySeed: group.members[target].KeySeed,
		Listen:       []string{"/ip4/127.0.0.1/udp/0/quic-v1"},
	})
	if err != nil {
		return result, fmt.Errorf("restart manager listener: %w", err)
	}
	group.nodes[target] = restartedNode
	addresses := restartedNode.Addresses()
	if len(addresses) == 0 {
		return result, errors.New("restarted manager has no address")
	}
	group.members[target].Address = addresses[0]

	restartedEngine, err := bft.NewEngine(committeeState(4, 3), group.members, group.members[target].ID,
		bft.SeededPrivateKey(group.members[target].KeySeed))
	if err != nil {
		return result, fmt.Errorf("restart engine: %w", err)
	}
	ledgerPath := filepath.Join(root, fmt.Sprintf("manager-%d.sqlite", target))
	ledger, err := store.Open(ledgerPath)
	if err != nil {
		return result, fmt.Errorf("reopen ledger: %w", err)
	}
	ledger.InstallCommitListener(restartedEngine)
	group.engines[target] = restartedEngine
	group.stores[target] = ledger
	result.RestartedHeightBeforeUse = restartedEngine.Height()

	ledgerStart := time.Now()
	if err := ledger.RestoreEngine(restartedEngine); err != nil {
		return result, fmt.Errorf("restore ledger: %w", err)
	}
	result.RestoreLedger = time.Since(ledgerStart)

	mesh, err := manager.NewCommitteeMesh(restartedNode, restartedEngine, group.members)
	if err != nil {
		return result, fmt.Errorf("restart mesh: %w", err)
	}
	group.meshes[target] = mesh
	group.managers[target] = manager.New(restartedNode, restartedEngine, mesh, manager.Config{})
	for index, oldNode := range group.nodes {
		if index == target || oldNode == nil {
			continue
		}
		info := peer.AddrInfo{ID: oldNode.Host.ID(), Addrs: oldNode.Host.Addrs()}
		if err := restartedNode.Host.Connect(group.ctx, info); err != nil {
			return result, fmt.Errorf("reconnect restarted manager to %d: %w", index, err)
		}
	}
	catchUpStart := time.Now()
	if err := mesh.CatchUp(group.ctx); err != nil {
		return result, fmt.Errorf("catch up restarted manager: %w", err)
	}
	result.CatchUp = time.Since(catchUpStart)

	commitStart := time.Now()
	if _, err := mesh.Submit(model.StateTransition{
		Type: bft.TransitionUpsertGroup, Group: &model.Group{ID: "after-restart"},
	}); err != nil {
		return result, fmt.Errorf("post-restart commit: %w", err)
	}
	result.PostRestartCommit = time.Since(commitStart)
	result.TotalRecovery = time.Since(recoveryStarted)
	if err := group.waitHeight(3); err != nil {
		return result, err
	}
	result.FinalHeight = group.engines[0].Height()
	result.StateHashesMatch = bytes.Equal(bft.StateHash(group.engines[0].CurrentState()), bft.StateHash(group.engines[target].CurrentState()))
	return result, nil
}

func runCommitteeFailure(ctx context.Context, root string, isolateLeader bool) (CommitteeFailureResult, error) {
	result := CommitteeFailureResult{}
	controller := chaos.New()
	group, err := startCommittee(ctx, root, 3, controller)
	if err != nil {
		return result, err
	}
	defer group.stop()
	result.CommitteeSize = 3
	result.QuorumSize = group.engines[0].CommitteeParams().QuorumSize

	target := len(group.members) - 1
	if isolateLeader {
		leaderID := group.engines[0].Leader(group.engines[0].Height()+1, 0).ID
		for index, member := range group.members {
			if member.ID == leaderID {
				target = index
				break
			}
		}
	}
	result.IsolatedManager = group.members[target].ID
	controller.Isolate(group.members[target].PeerID)

	blockedStart := time.Now()
	_, submitErr := group.meshes[0].Submit(model.StateTransition{
		Type: bft.TransitionUpsertGroup, Group: &model.Group{ID: "must-not-certify"},
	})
	result.BlockedWriteLatency = time.Since(blockedStart)
	if submitErr == nil {
		return result, errors.New("write unexpectedly certified without quorum")
	}
	result.BlockedWriteError = submitErr.Error()
	result.HeightDuringFailure = group.engines[0].Height()
	result.DroppedMessages = controller.Stats().Dropped

	recoveryStart := time.Now()
	controller.Reconnect(group.members[target].PeerID)
	if err := group.meshes[target].CatchUp(group.ctx); err != nil {
		return result, fmt.Errorf("catch up isolated manager: %w", err)
	}
	result.HealAndCatchUp = time.Since(recoveryStart)
	commitStart := time.Now()
	if _, err := group.meshes[0].Submit(model.StateTransition{
		Type: bft.TransitionUpsertGroup, Group: &model.Group{ID: "recovered"},
	}); err != nil {
		return result, fmt.Errorf("commit after heal: %w", err)
	}
	result.CommitAfterHeal = time.Since(commitStart)
	result.TotalRecovery = time.Since(recoveryStart)
	if err := group.waitHeight(2); err != nil {
		return result, err
	}
	result.FinalHeight = group.engines[0].Height()
	result.StateHashesMatch = bytes.Equal(bft.StateHash(group.engines[0].CurrentState()), bft.StateHash(group.engines[target].CurrentState()))
	return result, nil
}

func newNode(ctx context.Context, seed int64) (*p2p.Node, error) {
	return p2p.New(ctx, p2p.Config{
		IdentitySeed: seed,
		Listen:       []string{"/ip4/127.0.0.1/udp/0/quic-v1"},
	})
}

func connect(ctx context.Context, source, destination *p2p.Node) error {
	return source.Host.Connect(ctx, peer.AddrInfo{ID: destination.Host.ID(), Addrs: destination.Host.Addrs()})
}

func stormPayload(size int) ([]byte, error) {
	if size < 32 {
		size = 32
	}
	inner := make([]byte, size-28)
	return packet.BuildEchoRequest(net.ParseIP("100.64.0.1"), net.ParseIP("100.64.0.2"), 1, 1, inner)
}

func waitCount(ctx context.Context, counter *atomic.Uint64, want uint64, timeout time.Duration) bool {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if counter.Load() >= want {
			return true
		}
		select {
		case <-ctx.Done():
			return false
		case <-time.After(10 * time.Millisecond):
		}
	}
	return counter.Load() >= want
}

func runPacketStorm(ctx context.Context, options Options) (PacketStormResult, error) {
	result := PacketStormResult{Frames: options.PacketStormFrames, PayloadBytes: options.PacketPayloadBytes}
	source, err := newNode(ctx, 9301)
	if err != nil {
		return result, err
	}
	defer source.Close()
	destination, err := newNode(ctx, 9302)
	if err != nil {
		return result, err
	}
	defer destination.Close()
	if err := connect(ctx, source, destination); err != nil {
		return result, fmt.Errorf("connect storm peers: %w", err)
	}

	var received atomic.Uint64
	destinationTransport := transport.NewWithEnvelope(ctx, destination.Host, p2p.FrameProtocol, func(peer.ID, []byte) {
		received.Add(1)
	}, func(peer.ID, []byte) error {
		received.Add(1)
		return nil
	})
	sourceTransport := transport.NewWithEnvelope(ctx, source.Host, p2p.FrameProtocol, nil, nil)
	defer destinationTransport.Close()
	defer sourceTransport.Close()

	payload, err := stormPayload(options.PacketPayloadBytes)
	if err != nil {
		return result, fmt.Errorf("build packet: %w", err)
	}
	result.PayloadBytes = len(payload)
	batchSize := 1024
	if result.Frames < batchSize {
		batchSize = result.Frames
	}
	sendSamples := make([]time.Duration, 0, result.Frames)
	batchSamples := make([]time.Duration, 0, result.Frames/batchSize+1)
	stormStart := time.Now()
	sendStart := time.Now()
	for index := 0; index < result.Frames; index++ {
		sendStartSample := time.Now()
		err := sourceTransport.SendPacket(destination.Host.ID(), payload)
		sendSamples = append(sendSamples, time.Since(sendStartSample))
		if err == nil {
			result.Enqueued++
		} else if errors.Is(err, transport.ErrQueueFull) {
			result.QueueFullErrors++
		} else {
			return result, fmt.Errorf("send storm frame %d: %w", index, err)
		}
		if batchSize > 0 && (index+1)%batchSize == 0 {
			batchStart := time.Now().Add(-time.Since(sendStartSample))
			waitCount(ctx, &received, uint64(index+1), 5*time.Second)
			batchSamples = append(batchSamples, time.Since(batchStart))
		}
	}
	result.SendDuration = time.Since(sendStart)
	waitCount(ctx, &received, uint64(result.Frames), 10*time.Second)
	result.StormDuration = time.Since(stormStart)
	result.Delivered = int(received.Load())
	result.EnqueueLatency = summarize(sendSamples)
	result.EndToEndBatch = summarize(batchSamples)
	result.TransportSent, result.TransportDropped = sourceTransport.Stats(destination.Host.ID())
	if result.StormDuration > 0 {
		result.ThroughputPPS = float64(result.Delivered) / result.StormDuration.Seconds()
		result.GoodputMBPS = float64(result.Delivered) * float64(result.PayloadBytes) / result.StormDuration.Seconds() / 1024 / 1024
	}

	beforeProbe := received.Load()
	probeStart := time.Now()
	if err := sourceTransport.SendPacket(destination.Host.ID(), payload); err != nil {
		return result, fmt.Errorf("post-storm probe enqueue: %w", err)
	}
	if !waitCount(ctx, &received, beforeProbe+1, 5*time.Second) {
		return result, errors.New("transport did not recover after packet storm")
	}
	result.RecoveryProbe = time.Since(probeStart)

	malformed := [][]byte{
		nil,
		{0},
		{0, 0, 0, 0},
		{0xff, 0xff, 0xff, 0xff},
		append([]byte("packet"), 0, 0, 0, 16),
		append([]byte("packet"), 0xff, 0xff, 0xff, 0xff),
	}
	for index, data := range malformed {
		if err := writeRawFrame(ctx, source, destination, data); err != nil {
			result.MalformedCaseErrors = append(result.MalformedCaseErrors,
				fmt.Sprintf("raw case %d: %v", index, err))
		} else {
			result.MalformedRejected++
		}
		result.MalformedCases++
	}
	for _, data := range [][]byte{{0xff}, []byte("x")} {
		if err := writeTypedFrame(ctx, source, destination, data); err != nil {
			result.MalformedCaseErrors = append(result.MalformedCaseErrors, err.Error())
		} else {
			result.MalformedRejected++
		}
		result.MalformedCases++
	}
	return result, nil
}

func writeRawFrame(ctx context.Context, source, destination *p2p.Node, data []byte) error {
	stream, err := source.Host.NewStream(ctx, destination.Host.ID(), p2p.FrameProtocol)
	if err != nil {
		return err
	}
	defer stream.Reset()
	if err := stream.SetWriteDeadline(time.Now().Add(5 * time.Second)); err != nil {
		return err
	}
	if data != nil {
		if _, err := stream.Write(data); err != nil {
			return err
		}
	}
	return nil
}

func writeTypedFrame(ctx context.Context, source, destination *p2p.Node, data []byte) error {
	stream, err := source.Host.NewStream(ctx, destination.Host.ID(), p2p.FrameProtocol)
	if err != nil {
		return err
	}
	defer stream.Reset()
	if err := stream.SetWriteDeadline(time.Now().Add(5 * time.Second)); err != nil {
		return err
	}
	if len(data) == 1 {
		return transport.WriteProtocolFrame(stream, transport.ProtocolEnvelope, data)
	}
	return transport.WriteProtocolFrame(stream, "unknown-protocol", data)
}

func forwardingState(source, manager, destination peer.ID, budget model.TrafficBudget) model.NetworkState {
	state := model.NetworkState{
		NetworkID: "netp2p-quota",
		Peers: []model.PeerRecord{
			{PeerID: source.String(), Groups: []string{"clients"}},
			{PeerID: destination.String(), Groups: []string{"clients"}},
		},
		Groups:   []model.Group{{ID: "clients", Managed: true}},
		Budgets:  []model.TrafficBudget{budget},
		Settings: model.NetworkSettings{QuotaEnforcementEnabled: true},
		Assignments: []model.RouteAssignment{{
			ID: "quota-assignment", NetworkID: "netp2p-quota",
			SourcePeerID: source.String(), DestinationPeerID: destination.String(),
			Primary: model.PathSpec{
				ID: "quota-path", Kind: model.PathKindViaManager,
				ManagerHops: []string{manager.String()},
			},
		}},
	}
	return state
}

func runQuotaExhaustion(ctx context.Context, options Options) (QuotaResult, error) {
	result := QuotaResult{PayloadBytes: options.PacketPayloadBytes}
	source, err := newNode(ctx, 9311)
	if err != nil {
		return result, err
	}
	defer source.Close()
	managerNode, err := newNode(ctx, 9312)
	if err != nil {
		return result, err
	}
	defer managerNode.Close()
	destination, err := newNode(ctx, 9313)
	if err != nil {
		return result, err
	}
	defer destination.Close()
	if err := connect(ctx, source, managerNode); err != nil {
		return result, fmt.Errorf("connect source to manager: %w", err)
	}
	if err := connect(ctx, managerNode, destination); err != nil {
		return result, fmt.Errorf("connect manager to destination: %w", err)
	}

	sourceID := source.Host.ID()
	managerID := managerNode.Host.ID()
	destinationID := destination.Host.ID()
	payload, err := stormPayload(options.PacketPayloadBytes)
	if err != nil {
		return result, err
	}
	result.PayloadBytes = len(payload)
	budget := model.TrafficBudget{
		ID: "source-daily", SubjectType: "peer", SubjectID: sourceID.String(),
		DailyBytes: uint64(options.QuotaPackets * result.PayloadBytes), OnExhausted: string("block"),
	}
	state := forwardingState(sourceID, managerID, destinationID, budget)

	var managerForwardTable *forward.Table
	var managerReceived, destinationReceived, quotaBlocked atomic.Uint64
	destinationTable := forward.NewTable(state, destinationID.String(), func(peer.ID, forward.Envelope) error {
		return nil
	})
	managerTransport := transport.NewWithEnvelope(ctx, managerNode.Host, p2p.FrameProtocol, nil, func(remote peer.ID, wire []byte) error {
		managerReceived.Add(1)
		envelope, err := forward.DecodeEnvelope(wire)
		if err != nil {
			return nil
		}
		if _, err := managerForwardTable.Accept(remote, envelope); err != nil {
			if errors.Is(err, forward.ErrQuotaExceeded) {
				quotaBlocked.Add(1)
			}
		}
		return nil
	})
	destinationTransport := transport.NewWithEnvelope(ctx, destination.Host, p2p.FrameProtocol, nil, func(remote peer.ID, wire []byte) error {
		envelope, err := forward.DecodeEnvelope(wire)
		if err != nil {
			return nil
		}
		if delivered, err := destinationTable.Accept(remote, envelope); err == nil && delivered {
			destinationReceived.Add(1)
		}
		return nil
	})
	managerForwardTable = forward.NewTable(state, managerID.String(), func(remote peer.ID, envelope forward.Envelope) error {
		wire, err := forward.EncodeEnvelope(envelope)
		if err != nil {
			return err
		}
		return managerTransport.SendEnvelope(remote, wire)
	})
	sourceTransport := transport.NewWithEnvelope(ctx, source.Host, p2p.FrameProtocol, nil, nil)
	defer managerTransport.Close()
	defer destinationTransport.Close()
	defer sourceTransport.Close()

	sourceForwardTable := forward.NewTable(state, sourceID.String(), func(remote peer.ID, envelope forward.Envelope) error {
		wire, err := forward.EncodeEnvelope(envelope)
		if err != nil {
			return err
		}
		return sourceTransport.SendEnvelope(remote, wire)
	})

	result.BudgetBytes = budget.DailyBytes
	result.ExpectedAllowed = options.QuotaPackets
	exhaustionStart := time.Now()
	for index := 0; index < options.QuotaPackets*2; index++ {
		if err := sourceForwardTable.Send(sourceID, destinationID, "quota-assignment", "quota-path", payload); err != nil {
			return result, fmt.Errorf("send quota frame %d: %w", index, err)
		}
		if !waitCount(ctx, &managerReceived, uint64(index+1), 5*time.Second) {
			return result, fmt.Errorf("manager did not receive quota frame %d", index)
		}
		if quotaBlocked.Load() > 0 {
			break
		}
	}
	result.ExhaustionLatency = time.Since(exhaustionStart)
	if !waitCount(ctx, &destinationReceived, uint64(result.ExpectedAllowed), 5*time.Second) {
		return result, fmt.Errorf("quota delivered %d frames, want %d", destinationReceived.Load(), result.ExpectedAllowed)
	}
	result.ObservedAllowed = int(destinationReceived.Load())
	result.BlockedFrames = int(quotaBlocked.Load())
	if result.ExhaustionLatency > 0 {
		result.AllowedThroughputPPS = float64(result.ObservedAllowed) / result.ExhaustionLatency.Seconds()
	}

	beforeRecovery := destinationReceived.Load()
	expanded := state
	expanded.Budgets = append([]model.TrafficBudget(nil), state.Budgets...)
	expanded.Budgets[0].DailyBytes += uint64(result.PayloadBytes * 2)
	managerForwardTable.Replace(expanded)
	recoveryStart := time.Now()
	if err := sourceForwardTable.Send(sourceID, destinationID, "quota-assignment", "quota-path", payload); err != nil {
		return result, fmt.Errorf("quota recovery send: %w", err)
	}
	if !waitCount(ctx, &destinationReceived, beforeRecovery+1, 5*time.Second) {
		return result, errors.New("quota recovery frame was not delivered")
	}
	result.RecoveryCommit = time.Since(recoveryStart)
	result.Recovered = destinationReceived.Load() == beforeRecovery+1
	return result, nil
}

func Run(ctx context.Context, options Options) (*Manifest, error) {
	if options.PacketStormFrames <= 0 || options.QuotaPackets <= 0 || options.PacketPayloadBytes <= 0 {
		return nil, errors.New("resilience counts and payload size must be positive")
	}
	if options.ScenarioTimeout <= 0 {
		options.ScenarioTimeout = DefaultOptions().ScenarioTimeout
	}
	createdRoot := false
	if options.Root == "" {
		root, err := os.MkdirTemp("", "netp2p-resilience-")
		if err != nil {
			return nil, err
		}
		options.Root = root
		createdRoot = true
	} else if err := os.MkdirAll(options.Root, 0o700); err != nil {
		return nil, err
	}
	if createdRoot && !options.KeepRoot {
		defer os.RemoveAll(options.Root)
	}

	overallBefore := takeResourceSnapshot()
	manifest := &Manifest{GeneratedAt: time.Now().UTC(), Options: options}
	var err error
	if manifest.ManagerRestart.Resource, err = measure(ctx, options, func(scenarioCtx context.Context) error {
		result, runErr := runManagerRestart(scenarioCtx, options.Root, options)
		manifest.ManagerRestart = result
		return runErr
	}); err != nil {
		return nil, fmt.Errorf("manager restart: %w", err)
	}
	if manifest.NetworkPartition.Resource, err = measure(ctx, options, func(scenarioCtx context.Context) error {
		result, runErr := runCommitteeFailure(scenarioCtx, filepath.Join(options.Root, "partition"), false)
		manifest.NetworkPartition = result
		return runErr
	}); err != nil {
		return nil, fmt.Errorf("network partition: %w", err)
	}
	if manifest.BFTStall.Resource, err = measure(ctx, options, func(scenarioCtx context.Context) error {
		result, runErr := runCommitteeFailure(scenarioCtx, filepath.Join(options.Root, "bft-stall"), true)
		manifest.BFTStall = result
		return runErr
	}); err != nil {
		return nil, fmt.Errorf("BFT stall: %w", err)
	}
	if manifest.PacketStorm.Resource, err = measure(ctx, options, func(scenarioCtx context.Context) error {
		result, runErr := runPacketStorm(scenarioCtx, options)
		manifest.PacketStorm = result
		return runErr
	}); err != nil {
		return nil, fmt.Errorf("packet storm: %w", err)
	}
	if manifest.QuotaExhaustion.Resource, err = measure(ctx, options, func(scenarioCtx context.Context) error {
		result, runErr := runQuotaExhaustion(scenarioCtx, options)
		manifest.QuotaExhaustion = result
		return runErr
	}); err != nil {
		return nil, fmt.Errorf("quota exhaustion: %w", err)
	}
	manifest.Overall = resourceDelta(overallBefore, takeResourceSnapshot())
	manifest.Findings = findings(manifest)
	manifest.Pass = pass(manifest)
	return manifest, nil
}

func findings(manifest *Manifest) []Finding {
	var result []Finding
	if restart := manifest.ManagerRestart; !restart.StateHashesMatch || restart.FinalHeight < 3 {
		result = append(result, Finding{ID: "restart-state-divergence", Scenario: "manager restart",
			Severity: SeverityCritical, Summary: "Restarted manager did not converge to the certified state.",
			Observed:       fmt.Sprintf("height=%d hashesMatch=%v", restart.FinalHeight, restart.StateHashesMatch),
			Recommendation: "Block release; inspect SQLite restore and committee catch-up."})
	} else if restart.TotalRecovery > 15*time.Second {
		result = append(result, Finding{ID: "restart-recovery-latency", Scenario: "manager restart",
			Severity: SeverityHigh, Summary: "Manager restart recovery is slow for operational recovery.",
			Observed: restart.TotalRecovery.String(), Recommendation: "Profile ledger restore and catch-up; keep snapshots indexed by height."})
	}
	for _, failure := range []struct {
		name   string
		result CommitteeFailureResult
	}{
		{"network partition", manifest.NetworkPartition},
		{"BFT stall", manifest.BFTStall},
	} {
		if failure.result.BlockedWriteError == "" || failure.result.FinalHeight < 2 || !failure.result.StateHashesMatch {
			result = append(result, Finding{ID: failure.name + "-safety", Scenario: failure.name,
				Severity: SeverityCritical, Summary: "Failure scenario did not preserve fail-stop and convergence.",
				Observed:       fmt.Sprintf("error=%q height=%d hashes=%v", failure.result.BlockedWriteError, failure.result.FinalHeight, failure.result.StateHashesMatch),
				Recommendation: "Do not deploy; verify quorum readiness and catch-up under the fault."})
		} else if failure.result.TotalRecovery > 10*time.Second {
			result = append(result, Finding{ID: failure.name + "-recovery", Scenario: failure.name,
				Severity: SeverityHigh, Summary: "Recovery after heal exceeds the local resilience budget.",
				Observed: failure.result.TotalRecovery.String(), Recommendation: "Tune readiness probes and catch-up batching."})
		}
	}
	storm := manifest.PacketStorm
	if storm.MalformedRejected != storm.MalformedCases {
		result = append(result, Finding{ID: "malformed-frame-handling", Scenario: "packet storm",
			Severity: SeverityCritical, Summary: "A malformed or unknown frame was not cleanly rejected.",
			Observed:       fmt.Sprintf("rejected=%d cases=%d errors=%v", storm.MalformedRejected, storm.MalformedCases, storm.MalformedCaseErrors),
			Recommendation: "Block release; reject before allocation and close only the offending stream."})
	}
	if storm.QueueFullErrors > 0 || storm.TransportDropped > 0 {
		result = append(result, Finding{ID: "packet-storm-backpressure", Scenario: "packet storm",
			Severity: SeverityMedium, Summary: "Storm traffic was shed rather than causing unbounded memory growth.",
			Observed:       fmt.Sprintf("queueFull=%d transportDropped=%d delivered=%d", storm.QueueFullErrors, storm.TransportDropped, storm.Delivered),
			Recommendation: "Expected safe failure mode; size queues from SLO and alert on sustained drops."})
	}
	if storm.Resource.HeapAllocBytes > 512*1024*1024 {
		result = append(result, Finding{ID: "packet-storm-memory", Scenario: "packet storm",
			Severity: SeverityHigh, Summary: "Storm scenario retains more than 512MB of heap.",
			Observed:       fmt.Sprintf("%d bytes", storm.Resource.HeapAllocBytes),
			Recommendation: "Profile retained frames/handlers and cap per-peer in-flight payloads."})
	}
	quota := manifest.QuotaExhaustion
	if quota.ObservedAllowed != quota.ExpectedAllowed || !quota.Recovered {
		result = append(result, Finding{ID: "quota-enforcement", Scenario: "quota exhaustion",
			Severity: SeverityHigh, Summary: "Quota boundary or budget refresh did not behave exactly.",
			Observed:       fmt.Sprintf("allowed=%d expected=%d recovered=%v", quota.ObservedAllowed, quota.ExpectedAllowed, quota.Recovered),
			Recommendation: "Verify budget matching, byte accounting, and certified-state replacement."})
	}
	if manifest.Overall.HeapAllocBytes > 1024*1024*1024 {
		result = append(result, Finding{ID: "overall-memory", Scenario: "all",
			Severity: SeverityCritical, Summary: "Harness retained more than 1GB after all scenarios.",
			Observed:       fmt.Sprintf("%d bytes", manifest.Overall.HeapAllocBytes),
			Recommendation: "Profile package-level state and listener leaks before another scale run."})
	}
	return result
}

func pass(manifest *Manifest) bool {
	for _, finding := range manifest.Findings {
		if finding.Severity == SeverityCritical || finding.Severity == SeverityHigh {
			return false
		}
	}
	return manifest.ManagerRestart.StateHashesMatch &&
		manifest.NetworkPartition.StateHashesMatch &&
		manifest.BFTStall.StateHashesMatch &&
		manifest.PacketStorm.MalformedRejected == manifest.PacketStorm.MalformedCases &&
		manifest.QuotaExhaustion.ObservedAllowed == manifest.QuotaExhaustion.ExpectedAllowed &&
		manifest.QuotaExhaustion.Recovered
}

func WriteManifest(manifest *Manifest, path string) error {
	if path == "" {
		return errors.New("manifest path is required")
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
