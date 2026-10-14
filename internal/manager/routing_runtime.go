package manager

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"sort"
	"strings"
	"sync"
	"time"

	hostcrypto "github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	libprotocol "github.com/libp2p/go-libp2p/core/protocol"
	"github.com/netp2p/netp2p/internal/bft"
	"github.com/netp2p/netp2p/internal/forward"
	"github.com/netp2p/netp2p/internal/link"
	"github.com/netp2p/netp2p/internal/model"
	"github.com/netp2p/netp2p/internal/packet"
	"github.com/netp2p/netp2p/internal/path"
	"github.com/netp2p/netp2p/internal/quota"
)

const (
	routingGossipProtocol = libprotocol.ID("/netp2p/routing/gossip/3.0.0")
	routingInterval       = 5 * time.Second
	routingGossipTimeout  = 5 * time.Second
	maxRoutingGossipBytes = 4 << 20
	baselineDomainDemand  = 1
	defaultFaceCapacity   = uint64(125_000_000)
	pathSLARTTMS          = 300.0
	pathSLAJitterMS       = 60.0
	pathSLALossPercent    = 15.0
	pathSLABandwidthMbps  = 10.0
	routingPendingTTL     = 3 * routingInterval
)

var errRoutingEpochUnavailable = errors.New("signed routing epoch unavailable")

type routingRuntime struct {
	manager  *Manager
	now      func() time.Time
	interval time.Duration

	mu             sync.RWMutex
	epoch          *link.SignedRoutingEpoch
	telemetry      map[string]map[string]link.SignedEdgeTelemetry
	demand         map[string]uint64
	demandWindow   time.Time
	lastRelayBytes uint64
	lastRelayAt    time.Time
	pending        map[string]*routingEpochPending
}

type routingEpochPending struct {
	epoch     link.RoutingEpoch
	shares    map[int][]byte
	signers   map[int]string
	createdAt time.Time
}

type routingGossipMessage struct {
	Kind      string                     `json:"kind"`
	Telemetry []link.SignedEdgeTelemetry `json:"telemetry,omitempty"`
	Epoch     *link.SignedRoutingEpoch   `json:"epoch,omitempty"`
	Proposal  *link.RoutingEpoch         `json:"proposal,omitempty"`
	Share     []byte                     `json:"share,omitempty"`
	SignerID  string                     `json:"signerId,omitempty"`
}

func newRoutingRuntime(manager *Manager) *routingRuntime {
	return &routingRuntime{
		manager: manager, now: time.Now, interval: routingInterval,
		telemetry: make(map[string]map[string]link.SignedEdgeTelemetry),
		demand:    make(map[string]uint64),
		pending:   make(map[string]*routingEpochPending),
	}
}

func (runtime *routingRuntime) Run(ctx context.Context) {
	runtime.replace(runtime.manager.engine.CurrentState())
	runtime.manager.node.Handle(routingGossipProtocol, runtime.handleGossip)
	ticker := time.NewTicker(runtime.interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := runtime.ReconcileAutomatic(); err != nil && ctx.Err() == nil {
				log.Printf("global routing planner: %v", err)
			}
		}
	}
}

func (runtime *routingRuntime) ReconcileAutomatic() error {
	return runtime.reconcile(true)
}

func (runtime *routingRuntime) Reconcile() error {
	return runtime.reconcile(false)
}

func (runtime *routingRuntime) reconcile(automatic bool) error {
	manager := runtime.manager
	state := manager.engine.CurrentState()
	leader := runtime.isAutomaticLeader()
	if !automatic || leader {
		updated, err := runtime.ensureCertifiedRoutingState(state)
		if err != nil {
			return err
		}
		state = updated
	}
	runtime.replace(state)

	telemetry := runtime.collectTelemetry()
	runtime.storeTelemetry(telemetry)
	// Leadership can rotate while the committee certifies the routing objects.
	// Recompute it before signing so a stale leader cannot publish an epoch.
	if !runtime.isAutomaticLeader() {
		runtime.broadcast(routingGossipMessage{Kind: "telemetry", Telemetry: telemetry, SignerID: manager.engine.LocalID()})
		return nil
	}
	if len(state.RoutingDomains) == 0 {
		return nil
	}

	result, err := runtime.plan(state, time.Now().UTC())
	if err != nil {
		return err
	}
	return runtime.proposeEpoch(result.Epoch)
}

func (runtime *routingRuntime) isAutomaticLeader() bool {
	manager := runtime.manager
	height := manager.engine.Height()
	round := manager.engine.CurrentRound()
	leader := manager.engine.Leader(height+1, round)
	return leader.ID != "" && leader.ID == manager.engine.LocalID()
}

func (runtime *routingRuntime) proposeEpoch(epoch link.RoutingEpoch) error {
	manager := runtime.manager
	localID := manager.engine.LocalID()
	keys := manager.engine.RoutingKeySet()
	index, ok := manager.engine.RoutingKeyIndex(localID)
	if keys == nil || !ok {
		return errors.New("local committee routing share is unavailable")
	}
	epoch.ManagerID = localID
	share, err := link.SignRoutingEpochShare(epoch, localID, keys, index)
	if err != nil {
		return err
	}
	pending := &routingEpochPending{
		epoch: share.Epoch, shares: map[int][]byte{index: share.Signature},
		signers: map[int]string{index: localID}, createdAt: runtime.now().UTC(),
	}
	key := routingPendingKey(pending.epoch)
	runtime.mu.Lock()
	runtime.prunePendingLocked(runtime.now().UTC())
	if existing, active := runtime.pending[key]; active {
		proposal := existing.epoch
		shares := len(existing.shares)
		runtime.mu.Unlock()
		runtime.broadcast(routingGossipMessage{Kind: "epoch-proposal", Proposal: &proposal, SignerID: localID})
		if shares >= keys.Threshold {
			return runtime.aggregatePending(key)
		}
		return nil
	}
	runtime.pending[key] = pending
	runtime.mu.Unlock()

	runtime.broadcast(routingGossipMessage{Kind: "epoch-proposal", Proposal: &pending.epoch, SignerID: localID})
	if len(pending.shares) >= keys.Threshold {
		return runtime.aggregatePending(key)
	}
	return nil
}

func (runtime *routingRuntime) signEpochProposal(epoch link.RoutingEpoch, signerID string) error {
	manager := runtime.manager
	localID := manager.engine.LocalID()
	keys := manager.engine.RoutingKeySet()
	index, ok := manager.engine.RoutingKeyIndex(localID)
	if keys == nil || !ok {
		return errors.New("committee routing share is unavailable")
	}
	share, err := link.SignRoutingEpochShare(epoch, localID, keys, index)
	if err != nil {
		return err
	}
	runtime.sendTo(epoch.ManagerID, routingGossipMessage{
		Kind: "epoch-share", Proposal: &share.Epoch, Share: share.Signature, SignerID: localID,
	})
	return nil
}

func (runtime *routingRuntime) recordEpochShare(signerID string, epoch link.RoutingEpoch, signature []byte) error {
	manager := runtime.manager
	keys := manager.engine.RoutingKeySet()
	index, ok := manager.engine.RoutingKeyIndex(signerID)
	if keys == nil || !ok {
		return errors.New("committee routing share is unavailable")
	}
	if err := link.VerifyRoutingEpochShare(epoch, keys, index, signature); err != nil {
		return err
	}
	key := routingPendingKey(epoch)
	runtime.mu.Lock()
	pending, exists := runtime.pending[key]
	if !exists || !sameRoutingEpoch(pending.epoch, epoch) {
		runtime.mu.Unlock()
		return errors.New("routing epoch proposal is not active")
	}
	if _, exists := pending.shares[index]; !exists {
		pending.shares[index] = append([]byte(nil), signature...)
		pending.signers[index] = signerID
	}
	enough := len(pending.shares) >= keys.Threshold
	runtime.mu.Unlock()
	if !enough {
		return nil
	}
	return runtime.aggregatePending(key)
}

func (runtime *routingRuntime) aggregatePending(key string) error {
	runtime.mu.Lock()
	pending, exists := runtime.pending[key]
	if !exists {
		runtime.mu.Unlock()
		return errors.New("routing epoch proposal is not active")
	}
	epoch := pending.epoch
	shares := make(map[int][]byte, len(pending.shares))
	for index, signature := range pending.shares {
		shares[index] = append([]byte(nil), signature...)
	}
	signers := make(map[int]string, len(pending.signers))
	for index, managerID := range pending.signers {
		signers[index] = managerID
	}
	runtime.mu.Unlock()

	keys := runtime.manager.engine.RoutingKeySet()
	if keys == nil {
		return errors.New("committee routing key set is unavailable")
	}
	signed, err := link.AggregateRoutingEpochShares(epoch, shares, signers, keys)
	if err != nil {
		return err
	}
	state := runtime.manager.engine.CurrentState()
	if err := runtime.installEpoch(signed, state, runtime.now().UTC()); err != nil {
		runtime.mu.Lock()
		delete(runtime.pending, key)
		runtime.mu.Unlock()
		return err
	}
	runtime.mu.Lock()
	delete(runtime.pending, key)
	runtime.mu.Unlock()
	runtime.broadcast(routingGossipMessage{
		Kind: "epoch", Epoch: &signed, SignerID: runtime.manager.engine.LocalID(),
	})
	return nil
}

func routingPendingKey(epoch link.RoutingEpoch) string {
	return fmt.Sprintf("%x", epoch.PlannerDigest)
}

func sameRoutingEpoch(left, right link.RoutingEpoch) bool {
	return string(left.PlannerDigest) == string(right.PlannerDigest)
}

func (runtime *routingRuntime) prunePendingLocked(now time.Time) {
	for key, pending := range runtime.pending {
		if now.Sub(pending.createdAt) > routingPendingTTL {
			delete(runtime.pending, key)
		}
	}
}

func (runtime *routingRuntime) activeEpoch(state model.NetworkState, now time.Time) (*link.SignedRoutingEpoch, error) {
	runtime.mu.RLock()
	signed := runtime.epoch
	runtime.mu.RUnlock()
	if signed == nil {
		return nil, errRoutingEpochUnavailable
	}
	epoch := signed.Epoch
	height, snapshotHash, err := managerSnapshotIdentity(runtime.manager)
	if err != nil {
		return nil, err
	}
	if epoch.NetworkID != state.NetworkID {
		return nil, errors.New("active routing epoch network mismatch")
	}
	if epoch.CommitteeEpoch != state.CommitteeConfig.CommitteeEpoch {
		return nil, errors.New("active routing epoch committee mismatch")
	}
	if epoch.SnapshotHeight != height || !bytesEqual(epoch.SnapshotHash, snapshotHash) {
		return nil, errors.New("active routing epoch snapshot mismatch")
	}
	if !now.Before(epoch.ExpiresAt) {
		return nil, errors.New("active routing epoch expired")
	}
	return signed, nil
}

func (runtime *routingRuntime) ensureCertifiedRoutingState(state model.NetworkState) (model.NetworkState, error) {
	families := desiredPathFamilies(managerCommittee(runtime.manager), state.Settings)
	for _, family := range families {
		current, _ := findCertifiedFamily(state, family.ID)
		if sameCertifiedFamily(current, family) {
			continue
		}
		snapshot, err := runtime.manager.SubmitAs(model.StateTransition{
			Type: bft.TransitionUpsertPathFamily, PathFamily: &family,
		}, systemActor("global-routing"))
		if err != nil {
			return state, fmt.Errorf("certify path family %s: %w", family.ID, err)
		}
		state = snapshot.State
	}

	for _, domain := range desiredRoutingDomains(state, managerCommittee(runtime.manager), families) {
		current, _ := findCertifiedDomain(state, domain.ID)
		if sameCertifiedDomain(current, domain) {
			continue
		}
		snapshot, err := runtime.manager.SubmitAs(model.StateTransition{
			Type: bft.TransitionUpsertRoutingDomain, Domain: &domain,
		}, systemActor("global-routing"))
		if err != nil {
			return state, fmt.Errorf("certify routing domain %s: %w", domain.ID, err)
		}
		state = snapshot.State
	}
	return state, nil
}

func managerCommittee(manager *Manager) []model.CommitteeMember {
	return manager.engine.CommitteeMembers()
}

func desiredPathFamilies(committee []model.CommitteeMember, settings model.NetworkSettings) []model.PathFamily {
	classes := model.AllFlowClasses()
	sla := model.PathFamily{
		SourceGroups: []string{"*"}, DestinationScopes: []string{"*"}, FlowClasses: classes,
		MaxRTTMilliseconds: pathSLARTTMS, MaxJitterMilliseconds: pathSLAJitterMS,
		MaxLossPercent: pathSLALossPercent, MinBandwidthMbps: pathSLABandwidthMbps,
	}
	result := make([]model.PathFamily, 0)
	if settings.DirectPathEnabled {
		direct := sla
		direct.ID = "family-global-direct"
		direct.Kind = model.PathKindDirect
		result = append(result, direct.Normalized())
	}
	if !settings.ViaManagerEnabled {
		return result
	}
	forwarding := forwardingCommittee(committee)
	for _, member := range forwarding {
		family := sla
		family.ID = "family-via-" + member.ID
		family.Kind = model.PathKindViaManager
		family.ManagerHops = []string{member.PeerID}
		result = append(result, family.Normalized())
	}
	maxHops := settings.MaxManagerHops
	if maxHops != 2 || len(forwarding) < 2 {
		return result
	}
	for index, first := range forwarding {
		for secondIndex, second := range forwarding {
			if secondIndex <= index {
				continue
			}
			family := sla
			family.ID = pathFamilyID("family-multi-", first.PeerID, second.PeerID)
			family.Kind = model.PathKindMultiHop
			family.ManagerHops = []string{first.PeerID, second.PeerID}
			result = append(result, family.Normalized())
		}
	}
	return result
}

func forwardingCommittee(committee []model.CommitteeMember) []model.CommitteeMember {
	result := make([]model.CommitteeMember, 0, len(committee))
	for _, member := range committee {
		if member.ForwardingEnabled {
			result = append(result, member)
		}
	}
	sort.Slice(result, func(i, j int) bool { return result[i].ID < result[j].ID })
	return result
}

func desiredRoutingDomains(state model.NetworkState, committee []model.CommitteeMember, families []model.PathFamily) []model.RoutingDomainAuthorization {
	defaultClass := state.Settings.DefaultFlowClass
	if defaultClass == "" {
		defaultClass = model.FlowClassLatency
	}
	type domainBuilder struct {
		domain model.RoutingDomainAuthorization
	}
	builders := make(map[string]*domainBuilder)
	sourceManagers := forwardingCommittee(committee)
	for _, item := range state.Policies {
		if item.Effect != model.EffectAllow || len(item.SourceGroups) == 0 || len(item.DestinationGroups) == 0 {
			continue
		}
		class := item.FlowClass
		if class == "" {
			class = defaultClass
		}
		for _, sourceGroup := range item.SourceGroups {
			if !groupExists(state, sourceGroup) {
				continue
			}
			for _, destinationGroup := range item.DestinationGroups {
				if !groupExists(state, destinationGroup) {
					continue
				}
				for _, member := range sourceManagers {
					key := model.RoutingDomainKey{
						SourceManagerID: member.ID, SourceGroupID: sourceGroup,
						DestinationScope: model.DestinationScopeGroup + destinationGroup, FlowClass: class,
					}
					builder := builders[key.ID()]
					if builder == nil {
						builder = &domainBuilder{domain: model.RoutingDomainAuthorization{
							ID: key.ID(), Key: key, MaxHops: state.Settings.MaxManagerHops,
						}}
						builders[key.ID()] = builder
					}
					builder.domain.PathFamilyIDs = append(builder.domain.PathFamilyIDs, familyIDsCovering(families, key)...)
					builder.domain.PolicyIDs = append(builder.domain.PolicyIDs, item.ID)
					builder.domain.Services = append(builder.domain.Services, item.Services...)
					builder.domain.Normalized()
				}
			}
		}
	}
	result := make([]model.RoutingDomainAuthorization, 0, len(builders))
	for _, builder := range builders {
		if len(builder.domain.PathFamilyIDs) == 0 || len(builder.domain.PolicyIDs) == 0 {
			continue
		}
		result = append(result, builder.domain.Normalized())
	}
	sort.Slice(result, func(i, j int) bool { return result[i].ID < result[j].ID })
	return result
}

func familyIDsCovering(families []model.PathFamily, key model.RoutingDomainKey) []string {
	ids := make([]string, 0)
	for _, family := range families {
		if family.Covers(key) {
			ids = append(ids, family.ID)
		}
	}
	return ids
}

func groupExists(state model.NetworkState, groupID string) bool {
	for _, group := range state.Groups {
		if group.ID == groupID {
			return true
		}
	}
	return false
}

func (runtime *routingRuntime) replace(state model.NetworkState) {
	runtime.mu.Lock()
	defer runtime.mu.Unlock()
	height, snapshotHash, err := managerSnapshotIdentity(runtime.manager)
	if runtime.epoch != nil && (err != nil ||
		runtime.epoch.Epoch.SnapshotHeight < height ||
		runtime.epoch.Epoch.CommitteeEpoch != state.CommitteeConfig.CommitteeEpoch ||
		!bytesEqual(runtime.epoch.Epoch.SnapshotHash, snapshotHash)) {
		runtime.epoch = nil
	}
	runtime.prunePendingLocked(runtime.now().UTC())
	if runtime.demandWindow.IsZero() {
		runtime.demandWindow = time.Now().UTC()
	}
	runtime.manager.updateFaceBudgets(state)
	runtime.publishRoutingEpochMetricsLocked()
}

func managerSnapshotHeight(manager *Manager) uint64 {
	if snapshot, ok := manager.engine.LatestSnapshot(); ok {
		return snapshot.Height
	}
	return manager.engine.Height()
}

func managerSnapshotIdentity(manager *Manager) (uint64, []byte, error) {
	snapshot, ok := manager.engine.LatestSnapshot()
	if !ok || len(snapshot.StateHash) == 0 {
		return 0, nil, errors.New("certified snapshot is required for routing epoch")
	}
	return snapshot.Height, append([]byte(nil), snapshot.StateHash...), nil
}

func (runtime *routingRuntime) collectTelemetry() []link.SignedEdgeTelemetry {
	manager := runtime.manager
	now := time.Now().UTC()
	state := manager.engine.CurrentState()
	view := manager.LinkView()
	signer, err := manager.hostSigner()
	if err != nil {
		log.Printf("global routing telemetry signer: %v", err)
		return nil
	}
	telemetry := make([]link.EdgeTelemetry, 0)

	localPeer := manager.node.Host.ID().String()
	queueDepth, queueCapacity := manager.transportQueueStats()
	relayBytes := manager.forwardingRelayStats()
	runtime.mu.Lock()
	previousBytes, previousAt := runtime.lastRelayBytes, runtime.lastRelayAt
	runtime.lastRelayBytes, runtime.lastRelayAt = relayBytes, now
	runtime.mu.Unlock()
	sendBPS := 0.0
	if !previousAt.IsZero() {
		if elapsed := now.Sub(previousAt).Seconds(); elapsed > 0 && relayBytes >= previousBytes {
			sendBPS = float64(relayBytes-previousBytes) / elapsed
		}
	}
	access := aggregateAccessSegments(view, localPeer)
	budget := managerBudget(state, manager.engine.LocalID())
	telemetry = append(telemetry, link.EdgeTelemetry{
		EdgeID: "face:" + manager.engine.LocalID(), ManagerID: manager.engine.LocalID(),
		QueueDepth: float64(queueDepth), QueueDepthEWMA: float64(queueDepth) / float64(max(queueCapacity, 1)),
		SendBytesPerSecond: sendBPS, ActiveFlows: uint64(len(manager.Presence())),
		RTTMilliseconds: access.rtt, JitterMilliseconds: access.jitter, LossPercent: access.loss,
		MeasuredBandwidth: access.bandwidth, MonthlyUsedBytes: budget.UsedMonthlyBytes,
		MonthlyLimitBytes: budget.MonthlyBytes, UpdatedAt: now,
	})
	for _, segment := range view.Segments {
		if segment.From != localPeer {
			continue
		}
		remoteManagerID := managerIDForPeer(managerCommittee(manager), segment.To)
		if remoteManagerID == "" {
			continue
		}
		telemetry = append(telemetry, link.EdgeTelemetry{
			EdgeID:    "mesh:" + manager.engine.LocalID() + ":" + remoteManagerID,
			ManagerID: manager.engine.LocalID(), QueueDepthEWMA: segment.LossPercent / 100,
			RTTMilliseconds: segment.RTTMilliseconds, JitterMilliseconds: segment.JitterMilliseconds,
			LossPercent: segment.LossPercent, MeasuredBandwidth: segment.BandwidthMbps, UpdatedAt: now,
		})
	}

	signed := make([]link.SignedEdgeTelemetry, 0, len(telemetry))
	for _, sample := range telemetry {
		value, err := link.SignEdgeTelemetry(sample, signer)
		if err != nil {
			log.Printf("sign routing telemetry: %v", err)
			continue
		}
		signed = append(signed, value)
	}
	return signed
}

type segmentAggregate struct {
	rtt, jitter, loss, bandwidth float64
}

func aggregateAccessSegments(view link.LinkView, managerPeerID string) segmentAggregate {
	var result segmentAggregate
	count := 0
	for _, segment := range view.AccessSegments {
		if segment.From != managerPeerID {
			continue
		}
		result.rtt += segment.RTTMilliseconds
		result.jitter += segment.JitterMilliseconds
		result.loss += segment.LossPercent
		if segment.BandwidthMbps > 0 && (result.bandwidth == 0 || segment.BandwidthMbps < result.bandwidth) {
			result.bandwidth = segment.BandwidthMbps
		}
		count++
	}
	if count > 0 {
		result.rtt /= float64(count)
		result.jitter /= float64(count)
		result.loss /= float64(count)
	}
	return result
}

func (runtime *routingRuntime) storeTelemetry(samples []link.SignedEdgeTelemetry) {
	runtime.mu.Lock()
	defer runtime.mu.Unlock()
	for _, sample := range samples {
		if runtime.telemetry[sample.Telemetry.EdgeID] == nil {
			runtime.telemetry[sample.Telemetry.EdgeID] = make(map[string]link.SignedEdgeTelemetry)
		}
		runtime.telemetry[sample.Telemetry.EdgeID][sample.Telemetry.ManagerID] = sample
	}
}

func (runtime *routingRuntime) recordScale(envelope forward.ScaleEnvelope) {
	runtime.mu.Lock()
	defer runtime.mu.Unlock()
	if runtime.demand == nil {
		runtime.demand = make(map[string]uint64)
	}
	runtime.demand[envelope.Header.RoutingDomainID] += uint64(len(envelope.Payload))
}

func (runtime *routingRuntime) signedEpoch() *link.SignedRoutingEpoch {
	runtime.mu.RLock()
	defer runtime.mu.RUnlock()
	if runtime.epoch == nil {
		return nil
	}
	signed := *runtime.epoch
	return &signed
}

func (runtime *routingRuntime) publishRoutingEpochMetricsLocked() {
	if runtime.epoch == nil {
		runtime.manager.metrics.ClearRoutingEpoch()
		return
	}
	encoded, err := json.Marshal(*runtime.epoch)
	size := 0
	if err == nil {
		size = len(encoded)
	}
	runtime.manager.metrics.SetRoutingEpoch(
		runtime.epoch.Epoch.Sequence,
		runtime.now().Sub(runtime.epoch.Epoch.GeneratedAt),
		size,
	)
}

func (runtime *routingRuntime) plan(state model.NetworkState, now time.Time) (link.PlannerResult, error) {
	families := plannerFamilies(managerCommittee(runtime.manager), state)
	if len(families) == 0 {
		return link.PlannerResult{}, errors.New("certified path families are required")
	}
	snapshotHeight, snapshotHash, err := managerSnapshotIdentity(runtime.manager)
	if err != nil {
		return link.PlannerResult{}, err
	}
	telemetry := runtime.telemetryList()
	capacities := managerCapacities(state, managerCommittee(runtime.manager), now)
	candidates := link.BuildPlannerCandidates(families, telemetry, capacities, now)
	demand := runtime.demandForDomains(state, now)
	current := make([]link.PathAllocation, 0)
	runtime.mu.RLock()
	if runtime.epoch != nil {
		current = append(current, runtime.epoch.Epoch.Allocations...)
	}
	runtime.mu.RUnlock()
	return link.PlanRoutingEpoch(link.PlannerInput{
		NetworkID: state.NetworkID, SnapshotHeight: snapshotHeight, SnapshotHash: snapshotHash,
		CommitteeEpoch: state.CommitteeConfig.CommitteeEpoch, Round: runtime.manager.engine.CurrentRound(),
		BaseVersion: epochBaseVersion(runtime.epoch), Candidates: candidates, Demand: demand,
		Current: current, Now: now,
	})
}

func (runtime *routingRuntime) demandForDomains(state model.NetworkState, now time.Time) []link.DomainDemand {
	runtime.mu.Lock()
	demand := runtime.demand
	windowStart := runtime.demandWindow
	runtime.demand = make(map[string]uint64)
	runtime.demandWindow = now
	runtime.mu.Unlock()
	elapsed := now.Sub(windowStart).Seconds()
	if elapsed <= 0 {
		elapsed = float64(runtime.interval / time.Second)
	}
	result := make([]link.DomainDemand, 0, len(state.RoutingDomains))
	for _, authorization := range state.RoutingDomains {
		key := modelRoutingKey(authorization.Key)
		bytesPerSecond := float64(baselineDomainDemand)
		if observed := float64(demand[authorization.ID]) / elapsed; observed > bytesPerSecond {
			bytesPerSecond = observed
		}
		result = append(result, link.DomainDemand{Domain: key, BytesPerSecond: bytesPerSecond})
	}
	return result
}

func (runtime *routingRuntime) telemetryList() []link.EdgeTelemetry {
	runtime.mu.RLock()
	defer runtime.mu.RUnlock()
	result := make([]link.EdgeTelemetry, 0)
	edges := make([]string, 0, len(runtime.telemetry))
	for edgeID := range runtime.telemetry {
		edges = append(edges, edgeID)
	}
	sort.Strings(edges)
	for _, edgeID := range edges {
		managers := make([]string, 0, len(runtime.telemetry[edgeID]))
		for managerID := range runtime.telemetry[edgeID] {
			managers = append(managers, managerID)
		}
		sort.Strings(managers)
		for _, managerID := range managers {
			result = append(result, runtime.telemetry[edgeID][managerID].Telemetry)
		}
	}
	return result
}

func (runtime *routingRuntime) installEpoch(signed link.SignedRoutingEpoch, state model.NetworkState, now time.Time) error {
	if err := runtime.validateEpoch(signed, state, now); err != nil {
		runtime.manager.metrics.RecordRoutingEpochInvalid()
		return err
	}
	runtime.mu.Lock()
	defer runtime.mu.Unlock()
	if runtime.epoch != nil && signed.Epoch.Sequence <= runtime.epoch.Epoch.Sequence {
		return errors.New("routing epoch is stale")
	}
	runtime.epoch = &signed
	runtime.publishRoutingEpochMetricsLocked()
	return nil
}

func (runtime *routingRuntime) validateEpoch(signed link.SignedRoutingEpoch, state model.NetworkState, now time.Time) error {
	config := state.CommitteeConfig
	if !signed.ThresholdSigned || signed.Threshold != int(config.Threshold) ||
		len(signed.Signers) < signed.Threshold {
		return errors.New("routing epoch committee binding is invalid")
	}
	if err := link.VerifyRoutingEpoch(
		signed, link.BLSVerifier{GroupPublicKey: config.GroupPublicKey}, now,
	); err != nil {
		return err
	}
	return runtime.validateEpochProposal(signed.Epoch, state, now)
}

func (runtime *routingRuntime) validateEpochProposal(epoch link.RoutingEpoch, state model.NetworkState, now time.Time) error {
	config := state.CommitteeConfig
	if epoch.NetworkID != state.NetworkID {
		return errors.New("routing epoch belongs to another network")
	}
	if epoch.CommitteeEpoch != config.CommitteeEpoch {
		return errors.New("routing epoch belongs to another committee epoch")
	}
	height, snapshotHash, err := managerSnapshotIdentity(runtime.manager)
	if err != nil {
		return err
	}
	if epoch.SnapshotHeight != height || !bytesEqual(epoch.SnapshotHash, snapshotHash) {
		return errors.New("routing epoch does not match the certified snapshot")
	}
	if !now.Before(epoch.ExpiresAt) {
		return errors.New("routing epoch expired")
	}
	if now.Before(epoch.GeneratedAt.Add(-30 * time.Second)) {
		return errors.New("routing epoch generated too far in the future")
	}
	leader := runtime.manager.engine.Leader(epoch.SnapshotHeight+1, epoch.Round)
	if leader.ID == "" || leader.ID != epoch.ManagerID {
		return errors.New("routing epoch proposer is not the round leader")
	}
	if err := runtime.validateAllocations(epoch, state); err != nil {
		return err
	}
	candidates := link.BuildPlannerCandidates(
		plannerFamilies(managerCommittee(runtime.manager), state),
		runtime.telemetryList(), managerCapacities(state, managerCommittee(runtime.manager), now), now,
	)
	digest, err := link.CandidateSetHash(candidates)
	if err != nil {
		return err
	}
	if !bytesEqual(digest, epoch.CandidateSetHash) {
		return errors.New("routing epoch candidate set does not match certified state")
	}
	return nil
}

func (runtime *routingRuntime) validateAllocations(epoch link.RoutingEpoch, state model.NetworkState) error {
	if len(epoch.Allocations) == 0 {
		return errors.New("routing epoch has no allocations")
	}
	for _, allocation := range epoch.Allocations {
		if allocation.PathID == "" || allocation.Weight <= 0 {
			return errors.New("routing epoch has an invalid allocation")
		}
		found := false
		for _, family := range state.PathFamilies {
			if family.ID != allocation.PathID {
				continue
			}
			if family.Kind == model.PathKindDirect || !family.Covers(modelRoutingDomainKey(allocation.Domain)) {
				continue
			}
			found = true
			break
		}
		if !found {
			return fmt.Errorf("routing epoch allocates uncertified path %q", allocation.PathID)
		}
		domainFound := false
		for _, domain := range state.RoutingDomains {
			if domain.Key.SourceManagerID == allocation.Domain.SourceManagerID &&
				domain.Key.SourceGroupID == allocation.Domain.SourceGroupID &&
				domain.Key.DestinationScope == allocation.Domain.DestinationScope &&
				domain.Key.FlowClass == string(allocation.Domain.FlowClass) {
				domainFound = true
				break
			}
		}
		if !domainFound {
			return errors.New("routing epoch allocates an uncertified domain")
		}
	}
	return nil
}

func bytesEqual(left, right []byte) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}

func epochBaseVersion(signed *link.SignedRoutingEpoch) uint64 {
	if signed == nil {
		return 0
	}
	return signed.Epoch.Sequence
}

func plannerFamilies(committee []model.CommitteeMember, state model.NetworkState) []link.PathFamily {
	result := make([]link.PathFamily, 0, len(state.PathFamilies))
	for _, family := range state.PathFamilies {
		// Signed routing epochs select manager-forwarded families. Direct
		// families can remain in certified history after settings change, but
		// they are authorized by peer-pair assignments instead.
		if family.Kind == model.PathKindDirect {
			continue
		}
		result = append(result, link.PathFamily{
			ID: family.ID, Kind: family.Kind, ManagerHops: managerIDsForPeers(committee, family.ManagerHops),
			SourceGroups: family.SourceGroups, DestinationScopes: family.DestinationScopes,
			FlowClasses: flowClasses(family.FlowClasses), MaxRTTMilliseconds: family.MaxRTTMilliseconds,
			MaxJitterMilliseconds: family.MaxJitterMilliseconds, MaxLossPercent: family.MaxLossPercent,
			MinBandwidthMbps: family.MinBandwidthMbps,
		})
	}
	return result
}

func managerIDsForPeers(committee []model.CommitteeMember, peerIDs []string) []string {
	result := make([]string, 0, len(peerIDs))
	for _, peerID := range peerIDs {
		if managerID := managerIDForPeer(committee, peerID); managerID != "" {
			result = append(result, managerID)
		}
	}
	return result
}

func managerIDForPeer(committee []model.CommitteeMember, peerID string) string {
	for _, member := range committee {
		if member.PeerID == peerID {
			return member.ID
		}
	}
	return ""
}

func flowClasses(values []string) []path.FlowClass {
	result := make([]path.FlowClass, 0, len(values))
	for _, value := range values {
		result = append(result, path.FlowClass(value))
	}
	return result
}

func modelRoutingKey(key model.RoutingDomainKey) link.RoutingDomainKey {
	return link.RoutingDomainKey{
		SourceManagerID: key.SourceManagerID, SourceGroupID: key.SourceGroupID,
		DestinationScope: key.DestinationScope, FlowClass: path.FlowClass(key.FlowClass),
	}
}

func managerCapacities(state model.NetworkState, committee []model.CommitteeMember, now time.Time) []link.ManagerCapacityUsage {
	result := make([]link.ManagerCapacityUsage, 0, len(committee))
	for _, member := range committee {
		budget := managerBudget(state, member.ID)
		usage := link.ManagerCapacityUsage{
			ManagerID: member.ID, MonthlyLimitBytes: budget.MonthlyBytes,
			UsedMonthlyBytes: budget.UsedMonthlyBytes, ReserveFraction: .10, SoftThresholdPercent: 90,
			ResetAt: nextMonthStart(now),
		}
		result = append(result, usage)
	}
	return result
}

func managerBudget(state model.NetworkState, managerID string) model.TrafficBudget {
	for _, budget := range state.Budgets {
		if budget.SubjectType == "manager" && budget.SubjectID == managerID {
			return budget
		}
	}
	return model.TrafficBudget{}
}

func nextMonthStart(now time.Time) time.Time {
	year, month, _ := now.UTC().Date()
	return time.Date(year, month+1, 1, 0, 0, 0, 0, time.UTC)
}

func (runtime *routingRuntime) broadcast(message routingGossipMessage) {
	if message.SignerID == "" {
		message.SignerID = runtime.manager.engine.LocalID()
	}
	for _, member := range managerCommittee(runtime.manager) {
		runtime.sendTo(member.ID, message)
	}
}

func (runtime *routingRuntime) sendTo(managerID string, message routingGossipMessage) {
	if message.SignerID == "" {
		message.SignerID = runtime.manager.engine.LocalID()
	}
	if managerID == "" || managerID == runtime.manager.engine.LocalID() {
		return
	}
	remote := peer.ID("")
	for _, member := range managerCommittee(runtime.manager) {
		if member.ID != managerID {
			continue
		}
		decoded, err := peer.Decode(member.PeerID)
		if err != nil {
			return
		}
		remote = decoded
		break
	}
	if remote == "" {
		return
	}
	encoded, err := json.Marshal(message)
	if err != nil {
		log.Printf("encode routing gossip: %v", err)
		return
	}
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), routingGossipTimeout)
		defer cancel()
		stream, err := runtime.manager.node.Host.NewStream(ctx, remote, routingGossipProtocol)
		if err != nil {
			return
		}
		defer stream.Close()
		_ = stream.SetDeadline(time.Now().Add(routingGossipTimeout))
		_, _ = stream.Write(encoded)
	}()
}

func (runtime *routingRuntime) handleGossip(stream network.Stream) {
	defer stream.Close()
	limited := io.LimitReader(stream, maxRoutingGossipBytes+1)
	encoded, err := io.ReadAll(limited)
	if err != nil || len(encoded) > maxRoutingGossipBytes {
		return
	}
	var message routingGossipMessage
	if err := json.Unmarshal(encoded, &message); err != nil || message.SignerID == "" {
		return
	}
	if !runtime.manager.committeePeerMatches(stream.Conn().RemotePeer(), message.SignerID) {
		return
	}
	verifier, err := runtime.manager.signerVerifier(message.SignerID)
	if err != nil {
		return
	}
	now := time.Now().UTC()
	switch message.Kind {
	case "telemetry":
		for _, sample := range message.Telemetry {
			if sample.Telemetry.ManagerID != message.SignerID {
				continue
			}
			if err := link.VerifyEdgeTelemetry(sample, verifier); err != nil {
				continue
			}
			if !sample.Telemetry.Valid(now, 2*routingInterval) {
				continue
			}
			runtime.storeTelemetry([]link.SignedEdgeTelemetry{sample})
		}
	case "epoch":
		if message.Epoch == nil {
			return
		}
		if leader := runtime.manager.engine.Leader(
			message.Epoch.Epoch.SnapshotHeight+1, message.Epoch.Epoch.Round,
		); leader.ID != message.SignerID {
			return
		}
		if err := runtime.installEpoch(*message.Epoch, runtime.manager.engine.CurrentState(), now); err != nil {
			log.Printf("install routing epoch from %s: %v", message.SignerID, err)
			return
		}
	case "epoch-proposal":
		if message.Proposal == nil {
			return
		}
		if leader := runtime.manager.engine.Leader(
			message.Proposal.SnapshotHeight+1, message.Proposal.Round,
		); leader.ID != message.SignerID {
			return
		}
		if err := runtime.validateEpochProposal(
			*message.Proposal, runtime.manager.engine.CurrentState(), now,
		); err != nil {
			log.Printf("validate routing epoch proposal from %s: %v", message.SignerID, err)
			return
		}
		if err := runtime.signEpochProposal(*message.Proposal, message.SignerID); err != nil {
			log.Printf("sign routing epoch proposal from %s: %v", message.SignerID, err)
		}
	case "epoch-share":
		if message.Proposal == nil || len(message.Share) == 0 {
			return
		}
		if err := runtime.recordEpochShare(message.SignerID, *message.Proposal, message.Share); err != nil {
			log.Printf("record routing epoch share from %s: %v", message.SignerID, err)
		}
	}
}

func (manager *Manager) hostSigner() (link.MessageSigner, error) {
	privateKey := manager.node.Host.Peerstore().PrivKey(manager.node.Host.ID())
	if privateKey == nil || privateKey.Type() != hostcrypto.Ed25519 {
		return nil, errors.New("manager host key is not Ed25519")
	}
	raw, err := privateKey.Raw()
	if err != nil || len(raw) != ed25519.PrivateKeySize {
		return nil, errors.New("manager host key is malformed")
	}
	return link.Ed25519Signer{Key: append(ed25519.PrivateKey(nil), raw...)}, nil
}

// RoutingEpoch returns the latest locally validated signed routing epoch. It
// is runtime state, not certified BFT state, and may be absent briefly after a
// restart or committee leadership change.
func (manager *Manager) RoutingEpoch() *link.SignedRoutingEpoch {
	if manager.routing == nil {
		return nil
	}
	return manager.routing.signedEpoch()
}

// SelectRoutingPath applies the signed epoch to one payload and returns the
// certified path family selected for it. The caller still sends through a
// manager; this method never authorizes policy by itself.
func (manager *Manager) SelectRoutingPath(source, destination, routingDomainID, flowClass string, payload []byte) (model.PathFamily, error) {
	if manager.routing == nil {
		return model.PathFamily{}, errRoutingEpochUnavailable
	}
	envelope := forward.ScaleEnvelope{
		Header: forward.ScaleHeader{
			SourcePeerID: source, DestinationPeerID: destination,
			RoutingDomainID: routingDomainID, FlowClass: flowClass, TTL: forward.DefaultTTL,
		},
		Payload: payload,
	}
	if err := manager.routing.applySelection(&envelope); err != nil {
		return model.PathFamily{}, err
	}
	family, ok := findCertifiedFamily(manager.engine.CurrentState(), envelope.Header.PathFamilyID)
	if !ok {
		return model.PathFamily{}, errRoutingEpochUnavailable
	}
	return family, nil
}

func (manager *Manager) signerVerifier(managerID string) (link.MessageVerifier, error) {
	for _, member := range manager.engine.CommitteeMembers() {
		if member.ID != managerID {
			continue
		}
		if len(member.PublicKey) == ed25519.PublicKeySize {
			return link.Ed25519Verifier{Key: append(ed25519.PublicKey(nil), member.PublicKey...)}, nil
		}
		peerID, err := peer.Decode(member.PeerID)
		if err != nil {
			return nil, err
		}
		publicKey, err := peerID.ExtractPublicKey()
		if err != nil {
			return nil, err
		}
		raw, err := publicKey.Raw()
		if err != nil || len(raw) != ed25519.PublicKeySize {
			return nil, errors.New("manager public key is malformed")
		}
		return link.Ed25519Verifier{Key: append(ed25519.PublicKey(nil), raw...)}, nil
	}
	return nil, fmt.Errorf("unknown routing signer %q", managerID)
}

func (manager *Manager) committeePeerMatches(remote peer.ID, managerID string) bool {
	for _, member := range manager.engine.CommitteeMembers() {
		if member.ID == managerID && member.PeerID == remote.String() {
			return true
		}
	}
	return false
}

func (manager *Manager) updateFaceBudgets(state model.NetworkState) {
	if manager.forwarding == nil {
		return
	}
	configs := make([]quota.FaceConfig, 0)
	for _, member := range manager.engine.CommitteeMembers() {
		if !member.ForwardingEnabled {
			continue
		}
		budget := managerBudget(state, member.ID)
		capacity := budget.PeakBPS
		if capacity == 0 && budget.MonthlyBytes > 0 {
			capacity = budget.MonthlyBytes / uint64(30*24*time.Hour/time.Second)
		}
		if capacity == 0 {
			capacity = defaultFaceCapacity
		}
		configs = append(configs, quota.FaceConfig{FaceID: member.ID, CapacityBytesPerSecond: capacity})
	}
	budgets, err := quota.NewFaceBudgetSet(configs)
	if err != nil {
		log.Printf("routing face budgets: %v", err)
		return
	}
	manager.forwarding.SetFaceBudgets(budgets)
}

func (manager *Manager) transportQueueStats() (depth, capacity uint64) {
	if manager.dataTransport == nil {
		return 0, 0
	}
	maxDepth, maxCapacity := uint64(0), uint64(0)
	for _, member := range manager.engine.CommitteeMembers() {
		remote, err := peer.Decode(member.PeerID)
		if err != nil {
			continue
		}
		currentDepth, currentCapacity := manager.dataTransport.QueueStats(remote)
		if currentDepth > maxDepth {
			maxDepth = currentDepth
		}
		if currentCapacity > maxCapacity {
			maxCapacity = currentCapacity
		}
	}
	return maxDepth, maxCapacity
}

func (manager *Manager) forwardingRelayStats() (bytes uint64) {
	if manager.forwarding == nil {
		return 0
	}
	_, _, bytes = manager.forwarding.RelayStats()
	return bytes
}

func (runtime *routingRuntime) applySelection(envelope *forward.ScaleEnvelope) error {
	state := runtime.manager.engine.CurrentState()
	signed, err := runtime.activeEpoch(state, runtime.now().UTC())
	if err != nil {
		return err
	}
	localPeer := runtime.manager.node.Host.ID().String()
	domain, ok := findCertifiedDomain(state, envelope.Header.RoutingDomainID)
	if !ok {
		return errRoutingEpochUnavailable
	}
	flowHash, flowOK := overlayFlowHash(envelope.Payload)
	if !flowOK {
		return errors.New("scale payload is not a valid overlay packet")
	}
	if envelope.Header.PathFamilyID != "" {
		if envelope.Header.PathInstanceID == "" {
			return fmt.Errorf("%w: path instance is missing", forward.ErrScaleUnauthorized)
		}
		family, familyOK := findCertifiedFamily(state, envelope.Header.PathFamilyID)
		if !familyOK || family.Kind == model.PathKindDirect || !family.Covers(domain.Key) ||
			!containsString(family.ManagerHops, localPeer) {
			return fmt.Errorf("%w: path family is not valid for this manager", forward.ErrScaleUnauthorized)
		}
		allocated := false
		for _, allocation := range signed.Epoch.Allocations {
			if allocation.PathID == envelope.Header.PathFamilyID &&
				allocation.Domain.SourceManagerID == domain.Key.SourceManagerID &&
				allocation.Domain.SourceGroupID == domain.Key.SourceGroupID &&
				allocation.Domain.DestinationScope == domain.Key.DestinationScope &&
				string(allocation.Domain.FlowClass) == domain.Key.FlowClass && allocation.Weight > 0 {
				allocated = true
				break
			}
		}
		if !allocated {
			return errRoutingEpochUnavailable
		}
		envelope.Header.FlowHash = flowHash
		return nil
	}
	weights := make([]path.PathWeight, 0)
	for _, allocation := range signed.Epoch.Allocations {
		if allocation.Domain.SourceManagerID != domain.Key.SourceManagerID ||
			allocation.Domain.SourceGroupID != domain.Key.SourceGroupID ||
			allocation.Domain.DestinationScope != domain.Key.DestinationScope ||
			string(allocation.Domain.FlowClass) != domain.Key.FlowClass ||
			string(allocation.Domain.FlowClass) != envelope.Header.FlowClass || allocation.Weight <= 0 {
			continue
		}
		family, ok := findCertifiedFamily(state, allocation.PathID)
		if !ok || family.Kind == model.PathKindDirect || !family.Covers(modelRoutingDomainKey(allocation.Domain)) {
			continue
		}
		if len(family.ManagerHops) == 0 || family.ManagerHops[0] != localPeer {
			continue
		}
		weights = append(weights, path.PathWeight{PathID: allocation.PathID, Weight: allocation.Weight})
	}
	weights = path.NormalizeWeights(weights)
	var flowKey [8]byte
	binary.BigEndian.PutUint64(flowKey[:], flowHash)
	selected, ok := path.WeightedRendezvous(weights, flowKey[:])
	if !ok {
		return errRoutingEpochUnavailable
	}
	envelope.Header.PathFamilyID = selected
	envelope.Header.FlowHash = flowHash
	if family, ok := findCertifiedFamily(state, selected); ok && len(family.ManagerHops) > 0 {
		instance := family.ManagerHops[0]
		if managerID := managerIDForPeer(state.EngineCommittee, family.ManagerHops[0]); managerID != "" {
			instance = managerID
		}
		envelope.Header.PathInstanceID = selected + ":" + instance
	}
	return nil
}

func modelRoutingDomainKey(key link.RoutingDomainKey) model.RoutingDomainKey {
	return model.RoutingDomainKey{
		SourceManagerID: key.SourceManagerID, SourceGroupID: key.SourceGroupID,
		DestinationScope: key.DestinationScope, FlowClass: string(key.FlowClass),
	}
}

func overlayFlowHash(payload []byte) (uint64, bool) {
	return packet.FlowHash(payload)
}

func (manager *Manager) authorizeScale(
	sourcePeerID, destinationPeerID, routingDomainID, pathFamilyID, flowClass string,
) (forward.ScaleAuthorization, error) {
	state := manager.engine.CurrentState()
	domain, ok := findCertifiedDomain(state, routingDomainID)
	if !ok || domain.Key.FlowClass != flowClass {
		return forward.ScaleAuthorization{}, fmt.Errorf("%w: domain or flow class mismatch", forward.ErrScaleUnauthorized)
	}
	family, ok := findCertifiedFamily(state, pathFamilyID)
	if !ok || !family.Covers(domain.Key) || family.Kind == model.PathKindDirect {
		return forward.ScaleAuthorization{}, fmt.Errorf("%w: family does not cover domain", forward.ErrScaleUnauthorized)
	}
	if len(family.ManagerHops) > 0 && family.ManagerHops[0] == manager.node.Host.ID().String() &&
		domain.Key.SourceManagerID != manager.engine.LocalID() {
		return forward.ScaleAuthorization{}, fmt.Errorf("%w: source manager mismatch", forward.ErrScaleUnauthorized)
	}
	if !scalePolicyAllows(state, sourcePeerID, destinationPeerID, domain) {
		return forward.ScaleAuthorization{}, fmt.Errorf(
			"%w: domain policy denies peers (domain=%s source=%s destination=%s policies=%v)",
			forward.ErrScaleUnauthorized, domain.ID, sourcePeerID, destinationPeerID, domain.PolicyIDs,
		)
	}
	localIndex := -1
	localPeer := manager.node.Host.ID().String()
	for index, hop := range family.ManagerHops {
		if hop == localPeer {
			localIndex = index
			break
		}
	}
	if localIndex < 0 {
		return forward.ScaleAuthorization{}, fmt.Errorf("%w: local manager is not on family", forward.ErrScaleUnauthorized)
	}
	expectedPredecessor := sourcePeerID
	if localIndex > 0 {
		expectedPredecessor = family.ManagerHops[localIndex-1]
	}
	nextHop := destinationPeerID
	if localIndex+1 < len(family.ManagerHops) {
		nextHop = family.ManagerHops[localIndex+1]
	}
	return forward.ScaleAuthorization{
		FaceID: manager.engine.LocalID(), NextHop: nextHop, ExpectedPredecessor: expectedPredecessor,
	}, nil
}

func scalePolicyAllows(state model.NetworkState, sourcePeerID, destinationPeerID string, domain model.RoutingDomainAuthorization) bool {
	if !peerInCertifiedGroup(state, domain.Key.SourceGroupID, sourcePeerID) {
		return false
	}
	switch kind, id, _ := model.ParseDestinationScope(domain.Key.DestinationScope); kind {
	case model.DestinationScopeGroup:
		if !peerInCertifiedGroup(state, id, destinationPeerID) {
			return false
		}
	case model.DestinationScopePeer:
		if destinationPeerID != id {
			return false
		}
	case model.DestinationScopeRoute:
		route, ok := findRoute(state, id)
		if !ok || !peerInCertifiedGroup(state, route.RoutingGroup, destinationPeerID) {
			return false
		}
	default:
		return false
	}
	for _, policyID := range domain.PolicyIDs {
		item, ok := findPolicy(state, policyID)
		if !ok || item.Effect != model.EffectAllow {
			continue
		}
		source, sourceOK := findStatePeer(state, sourcePeerID)
		if sourceOK && peerInAnyCertifiedGroup(state, item.SourceGroups, sourcePeerID) &&
			peerInAnyCertifiedGroup(state, item.DestinationGroups, destinationPeerID) &&
			postureSatisfied(item.Posture, source.Posture) {
			return true
		}
	}
	return false
}

func findStatePeer(state model.NetworkState, peerID string) (model.PeerRecord, bool) {
	for _, peer := range state.Peers {
		if peer.PeerID == peerID {
			return peer, true
		}
	}
	return model.PeerRecord{}, false
}

func peerInAnyCertifiedGroup(state model.NetworkState, groupIDs []string, peerID string) bool {
	for _, groupID := range groupIDs {
		if peerInCertifiedGroup(state, groupID, peerID) {
			return true
		}
	}
	return false
}

func postureSatisfied(required, advertised []string) bool {
	available := make(map[string]struct{}, len(advertised))
	for _, label := range advertised {
		available[label] = struct{}{}
	}
	for _, label := range required {
		if _, ok := available[label]; !ok {
			return false
		}
	}
	return true
}

func findRoute(state model.NetworkState, id string) (model.Route, bool) {
	for _, route := range state.Routes {
		if route.ID == id {
			return route, true
		}
	}
	return model.Route{}, false
}

func findPolicy(state model.NetworkState, id string) (model.Policy, bool) {
	for _, item := range state.Policies {
		if item.ID == id {
			return item, true
		}
	}
	return model.Policy{}, false
}

func findCertifiedFamily(state model.NetworkState, id string) (model.PathFamily, bool) {
	for _, family := range state.PathFamilies {
		if family.ID == id {
			return family, true
		}
	}
	return model.PathFamily{}, false
}

func findCertifiedDomain(state model.NetworkState, id string) (model.RoutingDomainAuthorization, bool) {
	for _, domain := range state.RoutingDomains {
		if domain.ID == id {
			return domain, true
		}
	}
	return model.RoutingDomainAuthorization{}, false
}

func sameCertifiedFamily(current, next model.PathFamily) bool {
	return current.ID == next.ID && current.Kind == next.Kind &&
		sameStrings(current.ManagerHops, next.ManagerHops) &&
		sameStrings(current.SourceGroups, next.SourceGroups) &&
		sameStrings(current.DestinationScopes, next.DestinationScopes) &&
		sameStrings(current.FlowClasses, next.FlowClasses) &&
		current.MaxRTTMilliseconds == next.MaxRTTMilliseconds &&
		current.MaxJitterMilliseconds == next.MaxJitterMilliseconds &&
		current.MaxLossPercent == next.MaxLossPercent &&
		current.MinBandwidthMbps == next.MinBandwidthMbps
}

func sameCertifiedDomain(current, next model.RoutingDomainAuthorization) bool {
	return current.ID == next.ID && current.Key == next.Key &&
		sameStrings(current.PathFamilyIDs, next.PathFamilyIDs) &&
		sameStrings(current.PolicyIDs, next.PolicyIDs) &&
		current.MaxHops == next.MaxHops
}

func pathFamilyID(prefix, left, right string) string {
	digest := pathFlowDigest(left, right)
	return prefix + fmt.Sprintf("%x", digest[:8])
}

func pathFlowDigest(left, right string) [32]byte {
	return sha256.Sum256([]byte(strings.Join([]string{left, right}, "\x00")))
}

func containsString(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}
