package link

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"sort"
	"strings"
	"time"

	"github.com/netp2p/netp2p/internal/crypto/bls"
	"github.com/netp2p/netp2p/internal/model"
	"github.com/netp2p/netp2p/internal/path"
)

// RoutingDomainKey identifies an aggregate routing decision. Normal keys are
// manager/group/resource scoped; HotKey is reserved for bounded elephant-flow
// exceptions and must never be populated for every peer pair.
type RoutingDomainKey struct {
	SourceManagerID  string         `json:"sourceManagerId,omitempty"`
	SourceGroupID    string         `json:"sourceGroupId,omitempty"`
	DestinationScope string         `json:"destinationScope"`
	FlowClass        path.FlowClass `json:"flowClass"`
	HotKey           string         `json:"hotKey,omitempty"`
}

func (key RoutingDomainKey) Coarse() RoutingDomainKey {
	key.HotKey = ""
	return key
}

func (key RoutingDomainKey) Less(other RoutingDomainKey) bool {
	switch {
	case key.SourceManagerID != other.SourceManagerID:
		return key.SourceManagerID < other.SourceManagerID
	case key.SourceGroupID != other.SourceGroupID:
		return key.SourceGroupID < other.SourceGroupID
	case key.DestinationScope != other.DestinationScope:
		return key.DestinationScope < other.DestinationScope
	case key.FlowClass != other.FlowClass:
		return key.FlowClass < other.FlowClass
	default:
		return key.HotKey < other.HotKey
	}
}

func (key RoutingDomainKey) ID() string {
	encoded, _ := json.Marshal(key)
	return string(encoded)
}

// PathFamily is the certified identity of a class of paths. It authorizes a
// scope and path shape, but contains no runtime load or weight.
type PathFamily struct {
	ID                    string           `json:"id"`
	Kind                  model.PathKind   `json:"kind"`
	ManagerHops           []string         `json:"managerHops,omitempty"`
	SourceManagerIDs      []string         `json:"sourceManagerIds,omitempty"`
	SourceGroups          []string         `json:"sourceGroups,omitempty"`
	DestinationScopes     []string         `json:"destinationScopes,omitempty"`
	FlowClasses           []path.FlowClass `json:"flowClasses,omitempty"`
	MaxRTTMilliseconds    float64          `json:"maxRttMilliseconds,omitempty"`
	MaxJitterMilliseconds float64          `json:"maxJitterMilliseconds,omitempty"`
	MaxLossPercent        float64          `json:"maxLossPercent,omitempty"`
	MinBandwidthMbps      float64          `json:"minBandwidthMbps,omitempty"`
}

// PathCandidate is a concrete, planner-usable instance of a path family.
type PathCandidate struct {
	Family                 PathFamily       `json:"family"`
	Profile                path.LinkProfile `json:"profile"`
	Edges                  []string         `json:"edges,omitempty"`
	CapacityBytesPerSecond float64          `json:"capacityBytesPerSecond,omitempty"`
	MonthlyPressure        float64          `json:"monthlyPressure,omitempty"`
	ProjectedExhaustion    bool             `json:"projectedExhaustion,omitempty"`
}

// EdgeTelemetry is manager-signed runtime evidence. It is gossiped outside
// BFT and never becomes a certified state transition by itself.
type EdgeTelemetry struct {
	EdgeID             string    `json:"edgeId"`
	ManagerID          string    `json:"managerId"`
	QueueDepth         float64   `json:"queueDepth"`
	QueueDepthEWMA     float64   `json:"queueDepthEwma"`
	SendBytesPerSecond float64   `json:"sendBytesPerSecond"`
	DropRate           float64   `json:"dropRate"`
	ActiveFlows        uint64    `json:"activeFlows"`
	RTTMilliseconds    float64   `json:"rttMilliseconds"`
	JitterMilliseconds float64   `json:"jitterMilliseconds"`
	LossPercent        float64   `json:"lossPercent"`
	MeasuredBandwidth  float64   `json:"measuredBandwidth"`
	MonthlyUsedBytes   uint64    `json:"monthlyUsedBytes"`
	MonthlyLimitBytes  uint64    `json:"monthlyLimitBytes"`
	UpdatedAt          time.Time `json:"updatedAt"`
}

func (telemetry EdgeTelemetry) Valid(now time.Time, ttl time.Duration) bool {
	return telemetry.EdgeID != "" && telemetry.ManagerID != "" &&
		telemetry.QueueDepth >= 0 && telemetry.QueueDepthEWMA >= 0 &&
		telemetry.SendBytesPerSecond >= 0 && telemetry.DropRate >= 0 && telemetry.DropRate <= 1 &&
		telemetry.RTTMilliseconds >= 0 && telemetry.JitterMilliseconds >= 0 &&
		telemetry.LossPercent >= 0 && telemetry.LossPercent <= 100 &&
		telemetry.MeasuredBandwidth >= 0 && !telemetry.UpdatedAt.IsZero() &&
		now.Sub(telemetry.UpdatedAt) >= 0 && now.Sub(telemetry.UpdatedAt) <= ttl
}

type SignedEdgeTelemetry struct {
	Telemetry EdgeTelemetry `json:"telemetry"`
	Signature []byte        `json:"signature"`
}

// ManagerCapacityUsage is runtime monthly-capacity state. The certified
// object defines the limit; this value carries usage and burn rate without
// forcing consensus churn on every counter update.
type ManagerCapacityUsage struct {
	ManagerID              string    `json:"managerId"`
	MonthlyLimitBytes      uint64    `json:"monthlyLimitBytes"`
	UsedMonthlyBytes       uint64    `json:"usedMonthlyBytes"`
	BurnRateBytesPerSecond float64   `json:"burnRateBytesPerSecond"`
	ResetAt                time.Time `json:"resetAt"`
	ReserveFraction        float64   `json:"reserveFraction"`
	SoftThresholdPercent   int       `json:"softThresholdPercent"`
}

// DemandSample is one client's aggregated outbound usage. It describes only
// the reporting peer and never measures another peer's link quality.
type DemandSample struct {
	PeerID           string         `json:"peerId"`
	SourceManagerID  string         `json:"sourceManagerId,omitempty"`
	SourceGroupID    string         `json:"sourceGroupId,omitempty"`
	DestinationScope string         `json:"destinationScope"`
	FlowClass        path.FlowClass `json:"flowClass"`
	PathID           string         `json:"pathId"`
	Bytes            uint64         `json:"bytes"`
	DurationMS       uint64         `json:"durationMs"`
	ObservedAt       time.Time      `json:"observedAt"`
}

type DemandReport struct {
	PeerID      string         `json:"peerId"`
	WindowStart time.Time      `json:"windowStart"`
	WindowEnd   time.Time      `json:"windowEnd"`
	Samples     []DemandSample `json:"samples"`
}

type SignedDemandReport struct {
	Report    DemandReport `json:"report"`
	Signature []byte       `json:"signature"`
}

type DemandReportVerifier func(report DemandReport) (MessageVerifier, error)

func (usage ManagerCapacityUsage) Pressure() float64 {
	if usage.MonthlyLimitBytes == 0 {
		return 0
	}
	return math.Max(0, math.Min(1, float64(usage.UsedMonthlyBytes)/float64(usage.MonthlyLimitBytes)))
}

func (usage ManagerCapacityUsage) ProjectedExhaustion(now time.Time) bool {
	if usage.MonthlyLimitBytes == 0 || usage.ResetAt.IsZero() || !now.Before(usage.ResetAt) {
		return false
	}
	projected := float64(usage.UsedMonthlyBytes) + usage.BurnRateBytesPerSecond*usage.ResetAt.Sub(now).Seconds()
	threshold := float64(usage.MonthlyLimitBytes) * (1 - usage.ReserveFraction)
	if usage.SoftThresholdPercent > 0 {
		soft := float64(usage.MonthlyLimitBytes) * float64(usage.SoftThresholdPercent) / 100
		threshold = math.Min(threshold, soft)
	}
	return projected >= threshold
}

// DomainDemand is aggregated bytes per second for one routing domain. It can
// originate from manager forwarding counters or signed client reports.
type DomainDemand struct {
	Domain         RoutingDomainKey `json:"domain"`
	BytesPerSecond float64          `json:"bytesPerSecond"`
	CurrentPathID  string           `json:"currentPathId,omitempty"`
	Elephant       bool             `json:"elephant,omitempty"`
	FailedPathIDs  []string         `json:"failedPathIds,omitempty"`
}

type PathAllocation struct {
	Domain RoutingDomainKey `json:"domain"`
	PathID string           `json:"pathId"`
	Weight float64          `json:"weight"`
	Score  float64          `json:"score,omitempty"`
	FEC    bool             `json:"fec,omitempty"`
}

type MigrationCandidate struct {
	Domain          RoutingDomainKey `json:"domain"`
	FromPathID      string           `json:"fromPathId"`
	ToPathID        string           `json:"toPathId"`
	Reason          string           `json:"reason"`
	ExpectedBenefit float64          `json:"expectedBenefit"`
	BytesPerSecond  float64          `json:"bytesPerSecond"`
}

type RoutingEpoch struct {
	NetworkID        string           `json:"networkId"`
	SnapshotHeight   uint64           `json:"snapshotHeight"`
	SnapshotHash     []byte           `json:"snapshotHash"`
	CommitteeEpoch   uint64           `json:"committeeEpoch"`
	Round            uint64           `json:"round"`
	CandidateSetHash []byte           `json:"candidateSetHash"`
	Version          uint64           `json:"version"`
	Sequence         uint64           `json:"sequence"`
	GeneratedAt      time.Time        `json:"generatedAt"`
	ExpiresAt        time.Time        `json:"expiresAt"`
	Allocations      []PathAllocation `json:"allocations"`
	PlannerDigest    []byte           `json:"plannerDigest"`
	ManagerID        string           `json:"managerId,omitempty"`
}

type SignedRoutingEpoch struct {
	Epoch           RoutingEpoch `json:"epoch"`
	Signature       []byte       `json:"signature"`
	ThresholdSigned bool         `json:"thresholdSigned,omitempty"`
	Threshold       int          `json:"threshold,omitempty"`
	Signers         []string     `json:"signers,omitempty"`
}

type MessageSigner interface {
	Sign(message []byte) ([]byte, error)
}

type MessageVerifier interface {
	Verify(message, signature []byte) error
}

type Ed25519Signer struct {
	Key ed25519.PrivateKey
}

func (signer Ed25519Signer) Sign(message []byte) ([]byte, error) {
	if len(signer.Key) != ed25519.PrivateKeySize {
		return nil, errors.New("invalid Ed25519 private key")
	}
	return ed25519.Sign(signer.Key, message), nil
}

type Ed25519Verifier struct {
	Key ed25519.PublicKey
}

func (verifier Ed25519Verifier) Verify(message, signature []byte) error {
	if len(verifier.Key) != ed25519.PublicKeySize {
		return errors.New("invalid Ed25519 public key")
	}
	if !ed25519.Verify(verifier.Key, message, signature) {
		return errors.New("invalid signature")
	}
	return nil
}

// BLSVerifier verifies a threshold-aggregated routing epoch against the
// committee group public key. Partial signatures are never accepted here.
type BLSVerifier struct {
	GroupPublicKey []byte
}

func (verifier BLSVerifier) Verify(message, signature []byte) error {
	if !bls.Verify(verifier.GroupPublicKey, message, signature) {
		return errors.New("invalid threshold signature")
	}
	return nil
}

func canonicalMessage(value any) ([]byte, error) {
	return json.Marshal(value)
}

func SignEdgeTelemetry(telemetry EdgeTelemetry, signer MessageSigner) (SignedEdgeTelemetry, error) {
	message, err := canonicalMessage(telemetry)
	if err != nil {
		return SignedEdgeTelemetry{}, err
	}
	signature, err := signer.Sign(message)
	if err != nil {
		return SignedEdgeTelemetry{}, err
	}
	return SignedEdgeTelemetry{Telemetry: telemetry, Signature: signature}, nil
}

func VerifyEdgeTelemetry(signed SignedEdgeTelemetry, verifier MessageVerifier) error {
	message, err := canonicalMessage(signed.Telemetry)
	if err != nil {
		return err
	}
	return verifier.Verify(message, signed.Signature)
}

func SignDemandReport(report DemandReport, signer MessageSigner) (SignedDemandReport, error) {
	if report.PeerID == "" || len(report.Samples) == 0 {
		return SignedDemandReport{}, errors.New("demand report is incomplete")
	}
	message, err := canonicalMessage(report)
	if err != nil {
		return SignedDemandReport{}, err
	}
	signature, err := signer.Sign(message)
	if err != nil {
		return SignedDemandReport{}, err
	}
	return SignedDemandReport{Report: report, Signature: signature}, nil
}

func VerifyDemandReport(signed SignedDemandReport, verifier MessageVerifier) error {
	message, err := canonicalMessage(signed.Report)
	if err != nil {
		return err
	}
	return verifier.Verify(message, signed.Signature)
}

func SignRoutingEpoch(epoch RoutingEpoch, managerID string, signer MessageSigner) (SignedRoutingEpoch, error) {
	if managerID == "" {
		return SignedRoutingEpoch{}, errors.New("manager id is required")
	}
	if epoch.NetworkID == "" {
		return SignedRoutingEpoch{}, errors.New("network id is required")
	}
	epoch.ManagerID = managerID
	digest, err := routingEpochDigest(epoch)
	if err != nil {
		return SignedRoutingEpoch{}, err
	}
	epoch.PlannerDigest = digest
	message, err := canonicalMessage(epoch)
	if err != nil {
		return SignedRoutingEpoch{}, err
	}
	signature, err := signer.Sign(message)
	if err != nil {
		return SignedRoutingEpoch{}, err
	}
	return SignedRoutingEpoch{
		Epoch: epoch, Signature: signature, Threshold: 1, Signers: []string{managerID},
	}, nil
}

func VerifyRoutingEpoch(signed SignedRoutingEpoch, verifier MessageVerifier, now time.Time) error {
	if !signed.ThresholdSigned {
		return errors.New("routing epoch must be committee threshold signed")
	}
	if signed.Epoch.ManagerID == "" || len(signed.Epoch.PlannerDigest) == 0 ||
		len(signed.Epoch.SnapshotHash) == 0 || signed.Epoch.Sequence == 0 {
		return errors.New("routing epoch is incomplete")
	}
	if signed.Threshold < 1 || len(signed.Signers) < signed.Threshold {
		return errors.New("routing epoch threshold is incomplete")
	}
	if signed.Epoch.GeneratedAt.IsZero() || signed.Epoch.ExpiresAt.IsZero() ||
		!signed.Epoch.ExpiresAt.After(signed.Epoch.GeneratedAt) {
		return errors.New("routing epoch lifetime is invalid")
	}
	seen := make(map[string]struct{}, len(signed.Signers))
	for _, managerID := range signed.Signers {
		if managerID == "" {
			return errors.New("routing epoch has an empty signer")
		}
		if _, exists := seen[managerID]; exists {
			return errors.New("routing epoch has duplicate signers")
		}
		seen[managerID] = struct{}{}
	}
	for _, allocation := range signed.Epoch.Allocations {
		if allocation.PathID == "" || allocation.Weight <= 0 ||
			math.IsInf(allocation.Weight, 0) || math.IsNaN(allocation.Weight) {
			return errors.New("routing epoch has an invalid allocation")
		}
	}
	message, err := canonicalMessage(signed.Epoch)
	if err != nil {
		return err
	}
	if err := verifier.Verify(message, signed.Signature); err != nil {
		return err
	}
	digest, err := routingEpochDigest(signed.Epoch)
	if err != nil {
		return err
	}
	if !bytes.Equal(digest, signed.Epoch.PlannerDigest) {
		return errors.New("routing epoch digest mismatch")
	}
	if !signed.Epoch.ExpiresAt.IsZero() && now.After(signed.Epoch.ExpiresAt) {
		return errors.New("routing epoch expired")
	}
	return nil
}

// SignRoutingEpochShare produces one BLS partial signature. The result is not
// valid for client distribution until AggregateRoutingEpochShares combines a
// threshold of shares.
func SignRoutingEpochShare(epoch RoutingEpoch, managerID string, keys *bls.KeySet, index int) (SignedRoutingEpoch, error) {
	if keys == nil {
		return SignedRoutingEpoch{}, errors.New("threshold key set is required")
	}
	if managerID == "" {
		return SignedRoutingEpoch{}, errors.New("manager id is required")
	}
	digest, err := routingEpochDigest(epoch)
	if err != nil {
		return SignedRoutingEpoch{}, err
	}
	epoch.PlannerDigest = digest
	message, err := canonicalMessage(epoch)
	if err != nil {
		return SignedRoutingEpoch{}, err
	}
	signature, err := keys.SignShare(index, message)
	if err != nil {
		return SignedRoutingEpoch{}, err
	}
	return SignedRoutingEpoch{Epoch: epoch, Signature: signature, Signers: []string{managerID}}, nil
}

func VerifyRoutingEpochShare(epoch RoutingEpoch, keys *bls.KeySet, index int, signature []byte) error {
	if keys == nil {
		return errors.New("threshold key set is required")
	}
	digest, err := routingEpochDigest(epoch)
	if err != nil {
		return err
	}
	epoch.PlannerDigest = digest
	message, err := canonicalMessage(epoch)
	if err != nil {
		return err
	}
	if !bls.Verify(keys.PublicKeyShare(index), message, signature) {
		return errors.New("invalid routing epoch share")
	}
	return nil
}

func AggregateRoutingEpochShares(epoch RoutingEpoch, shares map[int][]byte, signers map[int]string, keys *bls.KeySet) (SignedRoutingEpoch, error) {
	if keys == nil {
		return SignedRoutingEpoch{}, errors.New("threshold key set is required")
	}
	if len(shares) != len(signers) || len(shares) < keys.Threshold {
		return SignedRoutingEpoch{}, errors.New("not enough routing epoch shares")
	}
	digest, err := routingEpochDigest(epoch)
	if err != nil {
		return SignedRoutingEpoch{}, err
	}
	epoch.PlannerDigest = digest
	for index, signature := range shares {
		if _, ok := signers[index]; !ok {
			return SignedRoutingEpoch{}, errors.New("share has no attributed manager")
		}
		if err := VerifyRoutingEpochShare(epoch, keys, index, signature); err != nil {
			return SignedRoutingEpoch{}, err
		}
	}
	aggregate, err := keys.Aggregate(shares)
	if err != nil {
		return SignedRoutingEpoch{}, err
	}
	ids := make([]string, 0, len(signers))
	for _, managerID := range signers {
		ids = append(ids, managerID)
	}
	sort.Strings(ids)
	return SignedRoutingEpoch{
		Epoch: epoch, Signature: aggregate, ThresholdSigned: true,
		Threshold: keys.Threshold, Signers: ids,
	}, nil
}

func routingEpochDigest(epoch RoutingEpoch) ([]byte, error) {
	epoch.PlannerDigest = nil
	message, err := canonicalMessage(epoch)
	if err != nil {
		return nil, err
	}
	digest := sha256.Sum256(message)
	return digest[:], nil
}

func CandidateSetHash(candidates []PathCandidate) ([]byte, error) {
	digest := sha256.New()
	sorted := append([]PathCandidate(nil), candidates...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].Family.ID < sorted[j].Family.ID })
	for _, candidate := range sorted {
		if candidate.Family.ID == "" {
			return nil, errors.New("candidate path id is required")
		}
		encoded, err := canonicalMessage(candidate.Family)
		if err != nil {
			return nil, err
		}
		_, _ = digest.Write(encoded)
		_, _ = digest.Write([]byte{0})
	}
	return digest.Sum(nil), nil
}

func BuildPathFamilies(committee []model.CommitteeMember, settings model.NetworkSettings) []PathFamily {
	classes := allFlowClasses()
	result := make([]PathFamily, 0, len(committee)+1)
	if settings.DirectPathEnabled {
		result = append(result, PathFamily{
			ID: "family-direct", Kind: model.PathKindDirect, FlowClasses: classes,
			MinBandwidthMbps: settings.LinkMinBandwidthMbps,
		})
	}
	if !settings.ViaManagerEnabled {
		return result
	}
	forwarding := forwardingManagers(committee)
	for _, manager := range forwarding {
		result = append(result, PathFamily{
			ID: "family-via-" + manager.ID, Kind: model.PathKindViaManager, ManagerHops: []string{manager.ID},
			FlowClasses: classes, MinBandwidthMbps: settings.LinkMinBandwidthMbps,
		})
	}
	maxHops := settings.MaxManagerHops
	if maxHops > 2 {
		maxHops = 2
	}
	if maxHops < 2 || len(forwarding) < 2 {
		return result
	}
	for first := 0; first < len(forwarding); first++ {
		for second := 0; second < len(forwarding); second++ {
			if first == second {
				continue
			}
			hops := []string{forwarding[first].ID, forwarding[second].ID}
			hash := sha256.Sum256([]byte(strings.Join(hops, "\x00")))
			result = append(result, PathFamily{
				ID:   "family-multi-" + strings.ToLower(fmt.Sprintf("%x", hash[:8])),
				Kind: model.PathKindMultiHop, ManagerHops: hops, FlowClasses: classes,
				MinBandwidthMbps: settings.LinkMinBandwidthMbps,
			})
		}
	}
	return result
}

func allFlowClasses() []path.FlowClass {
	return []path.FlowClass{path.FlowLatency, path.FlowThroughput, path.FlowCost, path.FlowReliability, path.FlowRealtime}
}

func BuildPlannerCandidates(families []PathFamily, telemetry []EdgeTelemetry, capacities []ManagerCapacityUsage, now time.Time) []PathCandidate {
	edges := make(map[string]EdgeTelemetry, len(telemetry))
	for _, sample := range telemetry {
		edges[sample.EdgeID] = sample
	}
	usage := make(map[string]ManagerCapacityUsage, len(capacities))
	for _, capacity := range capacities {
		usage[capacity.ManagerID] = capacity
	}
	now = now.UTC()
	result := make([]PathCandidate, 0, len(families))
	for _, family := range families {
		candidate := PathCandidate{Family: family, Profile: path.LinkProfile{
			PathID: family.ID, Type: pathTypeForFamily(family.Kind), Stability: 1,
		}}
		if family.Kind == model.PathKindDirect {
			result = append(result, candidate)
			continue
		}
		profile := path.LinkProfile{
			PathID: family.ID, Type: pathTypeForFamily(family.Kind), Stability: 1,
			ForwardingCost: float64(len(family.ManagerHops)),
		}
		previous := ""
		for _, managerID := range family.ManagerHops {
			faceID := "face:" + managerID
			candidate.Edges = append(candidate.Edges, faceID)
			if edge, ok := edges[faceID]; ok {
				profile.RTTMilliseconds += edge.RTTMilliseconds
				profile.JitterMilliseconds = math.Max(profile.JitterMilliseconds, edge.JitterMilliseconds)
				profile.LossPercent = math.Max(profile.LossPercent, edge.LossPercent)
				profile.Congestion = math.Max(profile.Congestion, edge.QueueDepthEWMA)
				if edge.MeasuredBandwidth > 0 && (profile.BandwidthMbps == 0 || edge.MeasuredBandwidth < profile.BandwidthMbps) {
					profile.BandwidthMbps = edge.MeasuredBandwidth
				}
				if edge.MeasuredBandwidth*125000 > candidate.CapacityBytesPerSecond {
					candidate.CapacityBytesPerSecond = edge.MeasuredBandwidth * 125000
				}
			}
			if previous != "" {
				meshID := "mesh:" + previous + ":" + managerID
				candidate.Edges = append(candidate.Edges, meshID)
				if edge, ok := edges[meshID]; ok {
					profile.RTTMilliseconds += edge.RTTMilliseconds
					profile.JitterMilliseconds = math.Max(profile.JitterMilliseconds, edge.JitterMilliseconds)
					profile.LossPercent = math.Max(profile.LossPercent, edge.LossPercent)
					profile.Congestion = math.Max(profile.Congestion, edge.QueueDepthEWMA)
				}
			}
			if capacity, ok := usage[managerID]; ok {
				candidate.MonthlyPressure = math.Max(candidate.MonthlyPressure, capacity.Pressure())
				candidate.ProjectedExhaustion = candidate.ProjectedExhaustion || capacity.ProjectedExhaustion(now)
			}
			previous = managerID
		}
		candidate.Profile = profile
		result = append(result, candidate)
	}
	return result
}

func pathTypeForFamily(kind model.PathKind) path.PathType {
	switch kind {
	case model.PathKindDirect:
		return path.PathDirect
	case model.PathKindMultiHop:
		return path.PathMultiHop
	default:
		return path.PathViaManager
	}
}

func BuildRoutingDomains(state model.NetworkState) []RoutingDomainKey {
	classes := map[path.FlowClass]struct{}{}
	if state.Settings.DefaultFlowClass != "" {
		classes[path.FlowClass(state.Settings.DefaultFlowClass)] = struct{}{}
	} else {
		classes[path.FlowLatency] = struct{}{}
	}
	for _, item := range state.Policies {
		class := path.FlowClass(item.FlowClass)
		if class == "" {
			class = path.FlowClass(state.Settings.DefaultFlowClass)
		}
		if class == "" {
			class = path.FlowLatency
		}
		classes[class] = struct{}{}
	}
	for _, item := range state.Routes {
		class := path.FlowClass(item.FlowClass)
		if class == "" {
			class = path.FlowClass(state.Settings.DefaultFlowClass)
		}
		if class == "" {
			class = path.FlowLatency
		}
		classes[class] = struct{}{}
	}

	keys := make(map[RoutingDomainKey]struct{})
	for class := range classes {
		keys[RoutingDomainKey{DestinationScope: "*", FlowClass: class}] = struct{}{}
	}
	for _, item := range state.Policies {
		class := path.FlowClass(item.FlowClass)
		if class == "" {
			class = path.FlowClass(state.Settings.DefaultFlowClass)
		}
		if class == "" {
			class = path.FlowLatency
		}
		sources := item.SourceGroups
		if len(sources) == 0 {
			sources = []string{"*"}
		}
		destinations := item.DestinationGroups
		if len(destinations) == 0 {
			destinations = []string{"*"}
		}
		for _, source := range sources {
			for _, destination := range destinations {
				keys[RoutingDomainKey{SourceGroupID: source, DestinationScope: "group:" + destination, FlowClass: class}] = struct{}{}
			}
		}
	}
	for _, item := range state.Routes {
		class := path.FlowClass(item.FlowClass)
		if class == "" {
			class = path.FlowClass(state.Settings.DefaultFlowClass)
		}
		if class == "" {
			class = path.FlowLatency
		}
		sources := item.DistributionGroup
		if len(sources) == 0 {
			sources = []string{"*"}
		}
		for _, source := range sources {
			keys[RoutingDomainKey{SourceGroupID: source, DestinationScope: "route:" + item.ID, FlowClass: class}] = struct{}{}
		}
	}
	result := make([]RoutingDomainKey, 0, len(keys))
	for key := range keys {
		result = append(result, key)
	}
	sort.Slice(result, func(i, j int) bool { return result[i].Less(result[j]) })
	return result
}

type PlannerConfig struct {
	Iterations            int
	Alpha                 float64
	Beta                  float64
	MinimumShare          float64
	MaximumShare          float64
	Smoothing             float64
	WeightChangeThreshold float64
	MaxHotDomains         int
	MaxMigrations         int
	MigrationBenefit      float64
	TTL                   time.Duration
}

func DefaultPlannerConfig() PlannerConfig {
	return PlannerConfig{
		Iterations: 20, Alpha: 4, Beta: 2, MinimumShare: 0.02, MaximumShare: 0.90,
		Smoothing: 0.25, WeightChangeThreshold: 0.03, MaxHotDomains: 1024,
		MaxMigrations: 1024, MigrationBenefit: 0.10, TTL: 30 * time.Second,
	}
}

func (config *PlannerConfig) applyDefaults() {
	defaults := DefaultPlannerConfig()
	if config.Iterations <= 0 {
		config.Iterations = defaults.Iterations
	}
	if config.Alpha <= 0 {
		config.Alpha = defaults.Alpha
	}
	if config.Beta <= 0 {
		config.Beta = defaults.Beta
	}
	if config.MinimumShare <= 0 {
		config.MinimumShare = defaults.MinimumShare
	}
	if config.MaximumShare <= 0 || config.MaximumShare >= 1 {
		config.MaximumShare = defaults.MaximumShare
	}
	if config.Smoothing <= 0 || config.Smoothing > 1 {
		config.Smoothing = defaults.Smoothing
	}
	if config.WeightChangeThreshold <= 0 {
		config.WeightChangeThreshold = defaults.WeightChangeThreshold
	}
	if config.MaxHotDomains <= 0 {
		config.MaxHotDomains = defaults.MaxHotDomains
	}
	if config.MaxMigrations <= 0 {
		config.MaxMigrations = defaults.MaxMigrations
	}
	if config.MigrationBenefit <= 0 {
		config.MigrationBenefit = defaults.MigrationBenefit
	}
	if config.TTL <= 0 {
		config.TTL = defaults.TTL
	}
}

type PlannerInput struct {
	NetworkID      string
	SnapshotHeight uint64
	SnapshotHash   []byte
	CommitteeEpoch uint64
	Round          uint64
	BaseVersion    uint64
	Candidates     []PathCandidate
	Demand         []DomainDemand
	Current        []PathAllocation
	Now            time.Time
	Config         PlannerConfig
}

type EdgeLoad struct {
	EdgeID      string  `json:"edgeId"`
	Load        float64 `json:"load"`
	Capacity    float64 `json:"capacity"`
	Utilization float64 `json:"utilization"`
}

type DomainAggregate struct {
	Key            RoutingDomainKey `json:"key"`
	Domains        int              `json:"domains"`
	BytesPerSecond float64          `json:"bytesPerSecond"`
	Hot            bool             `json:"hot"`
}

type PlannerResult struct {
	Epoch        RoutingEpoch         `json:"epoch"`
	EdgeLoads    []EdgeLoad           `json:"edgeLoads"`
	Aggregations []DomainAggregate    `json:"aggregations"`
	Migrations   []MigrationCandidate `json:"migrations"`
}

type planningDomain struct {
	key         RoutingDomainKey
	demand      float64
	currentPath string
	elephant    bool
	failed      map[string]struct{}
	candidates  []int
	scores      []float64
	weights     []float64
}

func PlanRoutingEpoch(input PlannerInput) (PlannerResult, error) {
	if input.NetworkID == "" {
		return PlannerResult{}, errors.New("network id is required")
	}
	if len(input.SnapshotHash) == 0 {
		return PlannerResult{}, errors.New("certified snapshot hash is required")
	}
	if len(input.Candidates) == 0 {
		return PlannerResult{}, errors.New("routing epoch requires candidates")
	}
	now := input.Now.UTC()
	if now.IsZero() {
		now = time.Now().UTC()
	}
	config := input.Config
	if config == (PlannerConfig{}) {
		config = DefaultPlannerConfig()
	} else {
		config.applyDefaults()
	}

	candidates := append([]PathCandidate(nil), input.Candidates...)
	sort.Slice(candidates, func(i, j int) bool { return candidates[i].Family.ID < candidates[j].Family.ID })
	seen := make(map[string]struct{}, len(candidates))
	for _, candidate := range candidates {
		if candidate.Family.ID == "" {
			return PlannerResult{}, errors.New("candidate path id is required")
		}
		if _, exists := seen[candidate.Family.ID]; exists {
			return PlannerResult{}, fmt.Errorf("duplicate candidate path id %q", candidate.Family.ID)
		}
		seen[candidate.Family.ID] = struct{}{}
	}

	domains, aggregations, err := aggregateDemand(input.Demand, config.MaxHotDomains)
	if err != nil {
		return PlannerResult{}, err
	}
	current := currentAllocationIndex(input.Current)
	edgeCapacity := candidateEdgeCapacity(candidates)
	initializeDomains(domains, candidates, current)
	runIterativeSolver(domains, candidates, config, edgeCapacity)
	stabilizeRealtimeDomains(domains, candidates)
	applyAllocationHysteresis(domains, candidates, current, config.WeightChangeThreshold)
	loads := calculateEdgeLoads(domains, candidates, edgeCapacity)
	migrations := migrationCandidates(domains, candidates, loads, config)

	allocations := make([]PathAllocation, 0, len(domains)*2)
	for _, domain := range domains {
		for index, candidateIndex := range domain.candidates {
			if domain.weights[index] <= 0 {
				continue
			}
			allocations = append(allocations, PathAllocation{
				Domain: domain.key,
				PathID: candidates[candidateIndex].Family.ID,
				Weight: roundWeight(domain.weights[index]),
				Score:  roundScore(domain.scores[index]),
				FEC:    domain.key.FlowClass == path.FlowRealtime,
			})
		}
	}
	sort.Slice(allocations, func(i, j int) bool {
		if allocations[i].Domain.Less(allocations[j].Domain) {
			return true
		}
		if allocations[j].Domain.Less(allocations[i].Domain) {
			return false
		}
		return allocations[i].PathID < allocations[j].PathID
	})

	candidateHash, err := CandidateSetHash(candidates)
	if err != nil {
		return PlannerResult{}, err
	}
	epoch := RoutingEpoch{
		NetworkID: input.NetworkID, SnapshotHeight: input.SnapshotHeight,
		SnapshotHash:   append([]byte(nil), input.SnapshotHash...),
		CommitteeEpoch: input.CommitteeEpoch, Round: input.Round,
		CandidateSetHash: candidateHash, Version: input.BaseVersion + 1,
		Sequence:    input.BaseVersion + 1,
		GeneratedAt: now, ExpiresAt: now.Add(config.TTL), Allocations: allocations,
	}
	digest, err := routingEpochDigest(epoch)
	if err != nil {
		return PlannerResult{}, err
	}
	epoch.PlannerDigest = digest
	return PlannerResult{Epoch: epoch, EdgeLoads: loads, Aggregations: aggregations, Migrations: migrations}, nil
}

func aggregateDemand(demand []DomainDemand, maxHot int) ([]*planningDomain, []DomainAggregate, error) {
	demand = append([]DomainDemand(nil), demand...)
	hot := make([]DomainDemand, 0)
	for _, sample := range demand {
		if sample.Domain.HotKey != "" {
			hot = append(hot, sample)
		}
	}
	if len(hot) > maxHot {
		sort.Slice(hot, func(i, j int) bool {
			if hot[i].BytesPerSecond != hot[j].BytesPerSecond {
				return hot[i].BytesPerSecond > hot[j].BytesPerSecond
			}
			return hot[i].Domain.ID() < hot[j].Domain.ID()
		})
		retained := make(map[string]struct{}, maxHot)
		for index := 0; index < maxHot; index++ {
			retained[hot[index].Domain.ID()] = struct{}{}
		}
		for index := range demand {
			if demand[index].Domain.HotKey == "" {
				continue
			}
			if _, ok := retained[demand[index].Domain.ID()]; !ok {
				demand[index].Domain = demand[index].Domain.Coarse()
			}
		}
	}

	aggregated := make(map[RoutingDomainKey]*planningDomain)
	for _, sample := range demand {
		if sample.BytesPerSecond < 0 {
			return nil, nil, errors.New("demand cannot be negative")
		}
		if sample.BytesPerSecond == 0 {
			continue
		}
		domain, ok := aggregated[sample.Domain]
		if !ok {
			domain = &planningDomain{key: sample.Domain, failed: make(map[string]struct{})}
			aggregated[sample.Domain] = domain
		}
		domain.demand += sample.BytesPerSecond
		domain.elephant = domain.elephant || sample.Elephant
		if sample.CurrentPathID != "" {
			domain.currentPath = sample.CurrentPathID
		}
		for _, failed := range sample.FailedPathIDs {
			domain.failed[failed] = struct{}{}
		}
	}
	result := make([]*planningDomain, 0, len(aggregated))
	for _, domain := range aggregated {
		result = append(result, domain)
	}
	sort.Slice(result, func(i, j int) bool { return result[i].key.Less(result[j].key) })

	aggregates := make(map[RoutingDomainKey]*DomainAggregate)
	for _, domain := range result {
		coarse := domain.key.Coarse()
		aggregate, ok := aggregates[coarse]
		if !ok {
			aggregate = &DomainAggregate{Key: coarse}
			aggregates[coarse] = aggregate
		}
		aggregate.Domains++
		aggregate.BytesPerSecond += domain.demand
		if domain.key.HotKey != "" {
			aggregate.Hot = true
		}
	}
	aggregateList := make([]DomainAggregate, 0, len(aggregates))
	for _, aggregate := range aggregates {
		aggregateList = append(aggregateList, *aggregate)
	}
	sort.Slice(aggregateList, func(i, j int) bool { return aggregateList[i].Key.Less(aggregateList[j].Key) })
	return result, aggregateList, nil
}

type reportedDemand struct {
	bytesPerSecond float64
	paths          map[string]float64
}

// AggregateDemandReports converts verified client reports into planner demand.
// Reports are estimates from the reporting client; they cannot override link
// telemetry or authorize a path.
func StaticDemandReportVerifier(verifier MessageVerifier) DemandReportVerifier {
	return func(DemandReport) (MessageVerifier, error) { return verifier, nil }
}

func AggregateDemandReports(reports []SignedDemandReport, verifierFor DemandReportVerifier, now time.Time, ttl time.Duration) ([]DomainDemand, error) {
	if verifierFor == nil {
		return nil, errors.New("demand report verifier is required")
	}
	now = now.UTC()
	aggregate := make(map[RoutingDomainKey]*reportedDemand)
	for _, signed := range reports {
		verifier, err := verifierFor(signed.Report)
		if err != nil {
			return nil, err
		}
		if err := VerifyDemandReport(signed, verifier); err != nil {
			return nil, err
		}
		report := signed.Report
		if report.WindowStart.IsZero() || report.WindowEnd.IsZero() || !report.WindowStart.Before(report.WindowEnd) {
			return nil, errors.New("invalid demand report window")
		}
		age := now.Sub(report.WindowEnd)
		if age < 0 || age > ttl {
			return nil, errors.New("stale demand report")
		}
		for _, sample := range report.Samples {
			if sample.PeerID != report.PeerID || sample.DestinationScope == "" || sample.PathID == "" ||
				sample.DurationMS == 0 || sample.Bytes == 0 || !validFlowClass(sample.FlowClass) {
				return nil, errors.New("invalid demand report sample")
			}
			if sample.ObservedAt.Before(report.WindowStart) || sample.ObservedAt.After(report.WindowEnd) {
				return nil, errors.New("demand sample is outside its report window")
			}
			key := RoutingDomainKey{
				SourceManagerID: sample.SourceManagerID, SourceGroupID: sample.SourceGroupID,
				DestinationScope: sample.DestinationScope, FlowClass: sample.FlowClass,
			}
			demand, ok := aggregate[key]
			if !ok {
				demand = &reportedDemand{paths: make(map[string]float64)}
				aggregate[key] = demand
			}
			rate := float64(sample.Bytes) / (float64(sample.DurationMS) / 1000)
			demand.bytesPerSecond += rate
			demand.paths[sample.PathID] += rate
		}
	}
	result := make([]DomainDemand, 0, len(aggregate))
	for key, demand := range aggregate {
		currentPath := ""
		currentRate := 0.0
		paths := make([]string, 0, len(demand.paths))
		for pathID := range demand.paths {
			paths = append(paths, pathID)
		}
		sort.Strings(paths)
		for _, pathID := range paths {
			if demand.paths[pathID] > currentRate {
				currentPath = pathID
				currentRate = demand.paths[pathID]
			}
		}
		result = append(result, DomainDemand{Domain: key, BytesPerSecond: demand.bytesPerSecond, CurrentPathID: currentPath})
	}
	sort.Slice(result, func(i, j int) bool { return result[i].Domain.Less(result[j].Domain) })
	return result, nil
}

func validFlowClass(class path.FlowClass) bool {
	switch class {
	case path.FlowLatency, path.FlowThroughput, path.FlowCost, path.FlowReliability, path.FlowRealtime:
		return true
	default:
		return false
	}
}

func currentAllocationIndex(allocations []PathAllocation) map[string]map[string]float64 {
	result := make(map[string]map[string]float64, len(allocations))
	for _, allocation := range allocations {
		if allocation.Weight <= 0 {
			continue
		}
		domain, ok := result[allocation.Domain.ID()]
		if !ok {
			domain = make(map[string]float64)
			result[allocation.Domain.ID()] = domain
		}
		domain[allocation.PathID] = allocation.Weight
	}
	return result
}

func candidateEdgeCapacity(candidates []PathCandidate) map[string]float64 {
	result := make(map[string]float64)
	for _, candidate := range candidates {
		capacity := candidate.CapacityBytesPerSecond
		for _, edge := range candidate.Edges {
			if capacity > 0 {
				if existing, ok := result[edge]; !ok || capacity < existing {
					result[edge] = capacity
				}
			} else if _, ok := result[edge]; !ok {
				result[edge] = 0
			}
		}
	}
	return result
}

func initializeDomains(domains []*planningDomain, candidates []PathCandidate, current map[string]map[string]float64) {
	for _, domain := range domains {
		currentWeights := current[domain.key.ID()]
		nonExhausted := make([]int, 0)
		for index, candidate := range candidates {
			if !familyAllows(domain.key, candidate.Family) {
				continue
			}
			if _, failed := domain.failed[candidate.Family.ID]; failed {
				continue
			}
			score := path.Score(candidate.Profile, familyConstraints(candidate.Family, domain.key.FlowClass))
			if score <= 0 {
				continue
			}
			domain.candidates = append(domain.candidates, index)
			domain.scores = append(domain.scores, score/100)
			if !candidate.ProjectedExhaustion {
				nonExhausted = append(nonExhausted, index)
			}
		}
		if len(nonExhausted) > 0 && len(nonExhausted) < len(domain.candidates) {
			keep := make(map[int]struct{}, len(nonExhausted))
			for _, index := range nonExhausted {
				keep[index] = struct{}{}
			}
			filteredCandidates := make([]int, 0, len(nonExhausted))
			filteredScores := make([]float64, 0, len(nonExhausted))
			for index, candidateIndex := range domain.candidates {
				if _, ok := keep[candidateIndex]; !ok {
					continue
				}
				filteredCandidates = append(filteredCandidates, candidateIndex)
				filteredScores = append(filteredScores, domain.scores[index])
			}
			domain.candidates = filteredCandidates
			domain.scores = filteredScores
		}
		if len(domain.candidates) == 0 {
			continue
		}
		domain.weights = make([]float64, len(domain.candidates))
		total := 0.0
		for index, candidateIndex := range domain.candidates {
			weight := domain.scores[index]
			if currentWeights != nil {
				if current, ok := currentWeights[candidates[candidateIndex].Family.ID]; ok && current > 0 {
					weight = current
				}
			}
			domain.weights[index] = weight
			total += weight
		}
		if total <= 0 {
			domain.weights[0] = 1
		} else {
			for index := range domain.weights {
				domain.weights[index] /= total
			}
		}
	}
}

func familyAllows(domain RoutingDomainKey, family PathFamily) bool {
	if len(family.FlowClasses) > 0 && !containsFlowClass(family.FlowClasses, domain.FlowClass) {
		return false
	}
	if !scopeAllows(family.SourceManagerIDs, domain.SourceManagerID) {
		return false
	}
	if !scopeAllows(family.SourceGroups, domain.SourceGroupID) {
		return false
	}
	if !scopeAllows(family.DestinationScopes, domain.DestinationScope) {
		return false
	}
	return true
}

func scopeAllows(values []string, wanted string) bool {
	return len(values) == 0 || wanted == "" || wanted == "*" ||
		containsString(values, "*") || containsString(values, wanted)
}

func familyConstraints(family PathFamily, class path.FlowClass) path.Constraints {
	var pathType path.PathType
	switch family.Kind {
	case model.PathKindDirect:
		pathType = path.PathDirect
	case model.PathKindMultiHop:
		pathType = path.PathMultiHop
	default:
		pathType = path.PathViaManager
	}
	return path.Constraints{
		FlowClass: class, AllowedTypes: []path.PathType{pathType},
		MaxRTTMilliseconds: family.MaxRTTMilliseconds, MaxJitterMilliseconds: family.MaxJitterMilliseconds,
		MaxLossPercent: family.MaxLossPercent, MinBandwidthMbps: family.MinBandwidthMbps,
	}
}

func runIterativeSolver(domains []*planningDomain, candidates []PathCandidate, config PlannerConfig, edgeCapacity map[string]float64) {
	for iteration := 0; iteration < config.Iterations; iteration++ {
		loads := make(map[string]float64)
		for _, domain := range domains {
			for index, candidateIndex := range domain.candidates {
				for _, edge := range candidates[candidateIndex].Edges {
					loads[edge] += domain.demand * domain.weights[index]
				}
			}
		}
		edgeCost := make(map[string]float64, len(loads))
		for edge, load := range loads {
			capacity := edgeCapacity[edge]
			utilization := 0.0
			if capacity > 0 {
				utilization = load / capacity
			} else if load > 0 {
				utilization = 10
			}
			edgeCost[edge] = 1 + config.Alpha*math.Pow(utilization, config.Beta)
		}

		for _, domain := range domains {
			if len(domain.candidates) == 0 {
				continue
			}
			next := make([]float64, len(domain.weights))
			total := 0.0
			for index, candidateIndex := range domain.candidates {
				candidate := candidates[candidateIndex]
				cost := 1.0
				for _, edge := range candidate.Edges {
					cost *= edgeCost[edge]
				}
				cost *= 1 + candidate.MonthlyPressure*monthlyPressureFactor(domain.key.FlowClass)
				cost *= 1 + candidate.Profile.Congestion
				next[index] = domain.scores[index] / cost
				total += next[index]
			}
			if total <= 0 {
				next[0] = 1
				total = 1
			}
			for index := range next {
				next[index] /= total
			}
			smoothed := make([]float64, len(next))
			for index := range next {
				smoothed[index] = (1-config.Smoothing)*domain.weights[index] + config.Smoothing*next[index]
			}
			domain.weights = clampWeights(smoothed, config.MinimumShare, config.MaximumShare)
		}
	}
}

func monthlyPressureFactor(class path.FlowClass) float64 {
	switch class {
	case path.FlowCost:
		return 8
	case path.FlowThroughput:
		return 3
	case path.FlowReliability:
		return 1
	case path.FlowRealtime:
		return 0.25
	default:
		return 0.5
	}
}

func clampWeights(weights []float64, minimum, maximum float64) []float64 {
	if len(weights) == 0 {
		return weights
	}
	total := 0.0
	for _, weight := range weights {
		total += weight
	}
	if total <= 0 {
		for index := range weights {
			weights[index] = 1 / float64(len(weights))
		}
		return weights
	}
	for index := range weights {
		weights[index] /= total
	}
	if len(weights) == 1 {
		weights[0] = 1
		return weights
	}
	if minimum*float64(len(weights)) > 1 {
		for index := range weights {
			weights[index] = 1 / float64(len(weights))
		}
		return weights
	}
	for index := range weights {
		if weights[index] < minimum {
			weights[index] = minimum
		}
		if weights[index] > maximum {
			weights[index] = maximum
		}
	}
	total = 0
	for _, weight := range weights {
		total += weight
	}
	for index := range weights {
		weights[index] /= total
	}
	return weights
}

func stabilizeRealtimeDomains(domains []*planningDomain, candidates []PathCandidate) {
	for _, domain := range domains {
		if domain.key.FlowClass != path.FlowRealtime || domain.currentPath == "" || len(domain.weights) == 0 {
			continue
		}
		for index, candidateIndex := range domain.candidates {
			if candidates[candidateIndex].Family.ID == domain.currentPath {
				domain.weights = make([]float64, len(domain.weights))
				domain.weights[index] = 1
				break
			}
		}
	}
}

func applyAllocationHysteresis(domains []*planningDomain, candidates []PathCandidate, current map[string]map[string]float64, threshold float64) {
	for _, domain := range domains {
		weights := current[domain.key.ID()]
		if weights == nil || len(domain.weights) == 0 {
			continue
		}
		for index, candidateIndex := range domain.candidates {
			currentWeight, ok := weights[candidates[candidateIndex].Family.ID]
			if !ok || currentWeight <= 0 {
				continue
			}
			if math.Abs(domain.weights[index]-currentWeight) < threshold {
				domain.weights[index] = currentWeight
			}
		}
		normalizePlanningWeights(domain.weights)
	}
}

func normalizePlanningWeights(weights []float64) {
	total := 0.0
	for _, weight := range weights {
		if weight > 0 {
			total += weight
		}
	}
	if total <= 0 {
		return
	}
	for index := range weights {
		if weights[index] > 0 {
			weights[index] /= total
		}
	}
}

func calculateEdgeLoads(domains []*planningDomain, candidates []PathCandidate, edgeCapacity map[string]float64) []EdgeLoad {
	loads := make(map[string]float64)
	for _, domain := range domains {
		for index, candidateIndex := range domain.candidates {
			for _, edge := range candidates[candidateIndex].Edges {
				loads[edge] += domain.demand * domain.weights[index]
			}
		}
	}
	result := make([]EdgeLoad, 0, len(loads))
	for edge, load := range loads {
		capacity := edgeCapacity[edge]
		utilization := 0.0
		if capacity > 0 {
			utilization = load / capacity
		} else if load > 0 {
			utilization = 10
		}
		result = append(result, EdgeLoad{EdgeID: edge, Load: load, Capacity: capacity, Utilization: utilization})
	}
	sort.Slice(result, func(i, j int) bool { return result[i].EdgeID < result[j].EdgeID })
	return result
}

func migrationCandidates(domains []*planningDomain, candidates []PathCandidate, loads []EdgeLoad, config PlannerConfig) []MigrationCandidate {
	utilizationByEdge := make(map[string]float64, len(loads))
	for _, load := range loads {
		utilizationByEdge[load.EdgeID] = load.Utilization
	}
	result := make([]MigrationCandidate, 0)
	for _, domain := range domains {
		if domain.currentPath == "" || domain.key.FlowClass == path.FlowRealtime || len(domain.weights) < 2 {
			continue
		}
		currentIndex := -1
		for index, candidateIndex := range domain.candidates {
			if candidates[candidateIndex].Family.ID == domain.currentPath {
				currentIndex = index
				break
			}
		}
		if currentIndex < 0 {
			if len(domain.candidates) > 0 {
				result = append(result, MigrationCandidate{
					Domain: domain.key, FromPathID: domain.currentPath,
					ToPathID: candidates[domain.candidates[0]].Family.ID,
					Reason:   "hard-failure", ExpectedBenefit: 1, BytesPerSecond: domain.demand,
				})
			}
			continue
		}
		currentUtilization := pathUtilization(candidates[domain.candidates[currentIndex]], utilizationByEdge)
		bestIndex := -1
		bestBenefit := 0.0
		for index, candidateIndex := range domain.candidates {
			if index == currentIndex {
				continue
			}
			benefit := currentUtilization - pathUtilization(candidates[candidateIndex], utilizationByEdge)
			if benefit > bestBenefit {
				bestBenefit = benefit
				bestIndex = index
			}
		}
		if bestIndex >= 0 && (bestBenefit >= config.MigrationBenefit || (domain.elephant && bestBenefit > 0)) {
			result = append(result, MigrationCandidate{
				Domain: domain.key, FromPathID: domain.currentPath,
				ToPathID: candidates[domain.candidates[bestIndex]].Family.ID,
				Reason:   "congestion", ExpectedBenefit: bestBenefit, BytesPerSecond: domain.demand,
			})
		}
		if len(result) >= config.MaxMigrations {
			break
		}
	}
	sort.Slice(result, func(i, j int) bool {
		if result[i].ExpectedBenefit != result[j].ExpectedBenefit {
			return result[i].ExpectedBenefit > result[j].ExpectedBenefit
		}
		return result[i].Domain.ID() < result[j].Domain.ID()
	})
	if len(result) > config.MaxMigrations {
		result = result[:config.MaxMigrations]
	}
	return result
}

func pathUtilization(candidate PathCandidate, utilizationByEdge map[string]float64) float64 {
	if len(candidate.Edges) == 0 {
		return 0
	}
	total := 0.0
	for _, edge := range candidate.Edges {
		total += utilizationByEdge[edge]
	}
	return total / float64(len(candidate.Edges))
}

func containsFlowClass(values []path.FlowClass, target path.FlowClass) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}

func containsString(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}

func roundWeight(value float64) float64 { return math.Round(value*1e6) / 1e6 }

func roundScore(value float64) float64 { return math.Round(value*1e4) / 1e4 }
