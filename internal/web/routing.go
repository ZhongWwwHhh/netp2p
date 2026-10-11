package web

import (
	"sort"
	"strings"
	"time"

	"github.com/netp2p/netp2p/internal/link"
	"github.com/netp2p/netp2p/internal/model"
)

var routingFlowClasses = model.AllFlowClasses()

// RoutingStatusFunc supplies runtime optimizer state from the manager runtime.
// Keeping this as a configuration hook lets the web package expose a stable API
// without importing planner or forwarding internals.
type RoutingStatusFunc func() RoutingStatus

type RoutingStatus struct {
	NetworkID            string                             `json:"networkId"`
	SnapshotHeight       uint64                             `json:"snapshotHeight"`
	GeneratedAt          time.Time                          `json:"generatedAt"`
	Mode                 string                             `json:"mode"`
	SupportedFlowClasses []string                           `json:"supportedFlowClasses"`
	Domains              []model.RoutingDomainAuthorization `json:"domains"`
	PathFamilies         []model.PathFamily                 `json:"pathFamilies"`
	Epoch                *RoutingEpoch                      `json:"epoch,omitempty"`
	ManagerCapacity      []ManagerCapacityStatus            `json:"managerCapacity"`
	Telemetry            []EdgeTelemetry                    `json:"telemetry"`
	Demand               []DemandSample                     `json:"demand"`
	Fec                  FECDiagnostics                     `json:"fec"`
	Problems             []string                           `json:"problems"`
}

type RoutingEpoch struct {
	NetworkID          string           `json:"networkId"`
	SnapshotHeight     uint64           `json:"snapshotHeight"`
	Version            uint64           `json:"version"`
	GeneratedAt        time.Time        `json:"generatedAt"`
	ExpiresAt          time.Time        `json:"expiresAt"`
	CandidateSetDigest string           `json:"candidateSetDigest"`
	PlannerDigest      string           `json:"plannerDigest"`
	ManagerID          string           `json:"managerId"`
	SignatureVerified  bool             `json:"signatureVerified"`
	ThresholdSigned    bool             `json:"thresholdSigned"`
	Allocations        []PathAllocation `json:"allocations"`
}

type PathAllocation struct {
	Key   RoutingAllocationKey `json:"key"`
	Paths []PathWeight         `json:"paths"`
}

type RoutingAllocationKey struct {
	SourceManagerID  string `json:"sourceManagerId"`
	SourceGroupID    string `json:"sourceGroupId"`
	DestinationScope string `json:"destinationScope"`
	FlowClass        string `json:"flowClass"`
}

type PathWeight struct {
	PathID string  `json:"pathId"`
	Weight float64 `json:"weight"`
	Reason string  `json:"reason,omitempty"`
}

type ManagerCapacityStatus struct {
	ManagerID                  string    `json:"managerId"`
	Configured                 bool      `json:"configured"`
	MonthlyBytes               uint64    `json:"monthlyBytes"`
	UsedBytes                  uint64    `json:"usedBytes"`
	RemainingBytes             uint64    `json:"remainingBytes"`
	ReserveBytes               uint64    `json:"reserveBytes"`
	CountMode                  string    `json:"countMode"`
	ResetDayUTC                int       `json:"resetDayUtc"`
	SoftThresholdPercent       int       `json:"softThresholdPercent"`
	Pressure                   float64   `json:"pressure"`
	BurnRateBytesPerSecond     float64   `json:"burnRateBytesPerSecond"`
	ProjectedExhaustionSeconds float64   `json:"projectedExhaustionSeconds"`
	State                      string    `json:"state"`
	UpdatedAt                  time.Time `json:"updatedAt"`
}

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
	MeasuredBandwidth  float64   `json:"measuredBandwidthMbps"`
	MonthlyUsedBytes   uint64    `json:"monthlyUsedBytes"`
	MonthlyLimitBytes  uint64    `json:"monthlyLimitBytes"`
	UpdatedAt          time.Time `json:"updatedAt"`
	Source             string    `json:"source"`
}

type DemandSample struct {
	PeerID           string    `json:"peerId"`
	SourceGroupID    string    `json:"sourceGroupId"`
	DestinationScope string    `json:"destinationScope"`
	FlowClass        string    `json:"flowClass"`
	PathID           string    `json:"pathId"`
	Bytes            uint64    `json:"bytes"`
	DurationMS       uint64    `json:"durationMs"`
	ObservedAt       time.Time `json:"observedAt"`
}

type FECDiagnostics struct {
	Enabled              bool                  `json:"enabled"`
	DefaultCodec         string                `json:"defaultCodec"`
	MaxRedundancyPercent int                   `json:"maxRedundancyPercent"`
	Classes              []FECClassDiagnostics `json:"classes"`
}

type FECClassDiagnostics struct {
	FlowClass                  string  `json:"flowClass"`
	Enabled                    bool    `json:"enabled"`
	Packets                    uint64  `json:"packets"`
	RecoveredPackets           uint64  `json:"recoveredPackets"`
	GeneratedRedundancyPackets uint64  `json:"generatedRedundancyPackets"`
	OverheadRatio              float64 `json:"overheadRatio"`
	RecoveredRatio             float64 `json:"recoveredRatio"`
	LastError                  string  `json:"lastError,omitempty"`
}

func (server *Server) routingStatus() RoutingStatus {
	now := time.Now().UTC()
	if server.config.RoutingStatus != nil {
		status := server.config.RoutingStatus()
		if status.GeneratedAt.IsZero() {
			status.GeneratedAt = now
		}
		normalizeRoutingStatus(&status)
		return status
	}
	if server.manager == nil {
		status := RoutingStatus{GeneratedAt: now, Mode: "unavailable"}
		normalizeRoutingStatus(&status)
		status.Problems = append(status.Problems, "manager runtime is unavailable")
		return status
	}
	return server.derivedRoutingStatus(now)
}

func (server *Server) derivedRoutingStatus(now time.Time) RoutingStatus {
	snapshot := server.manager.Snapshot()
	state := snapshot.State
	status := RoutingStatus{
		NetworkID:            state.NetworkID,
		SnapshotHeight:       snapshot.Height,
		GeneratedAt:          now,
		Mode:                 "derived",
		SupportedFlowClasses: routingFlowClasses,
		Problems:             []string{},
	}
	status.PathFamilies = copyPathFamilies(state.PathFamilies)
	if len(status.PathFamilies) == 0 {
		status.PathFamilies = pathFamiliesFromAssignments(state.Assignments)
	}
	status.Domains = copyRoutingDomains(state.RoutingDomains)
	if len(status.Domains) == 0 {
		status.Domains = routingDomainsFromState(state, server.manager.LocalID(), status.PathFamilies)
	}
	status.ManagerCapacity = managerCapacityFromState(server.manager.Committee(), state.Budgets, now)
	status.Telemetry = edgeTelemetryFromLinkView(server.manager.LinkView())
	status.Fec = disabledFECDiagnostics()
	status.Problems = append(
		status.Problems,
		"routing epoch producer is not configured",
		"client demand aggregation is not configured",
		"FEC counters are not configured",
	)
	normalizeRoutingStatus(&status)
	return status
}

func pathFamiliesFromAssignments(assignments []model.RouteAssignment) []model.PathFamily {
	byID := make(map[string]model.PathFamily)
	for _, assignment := range assignments {
		for _, path := range assignment.Paths() {
			if path.ID == "" {
				continue
			}
			if _, exists := byID[path.ID]; exists {
				continue
			}
			byID[path.ID] = model.PathFamily{
				ID: path.ID, Kind: path.Kind, ManagerHops: path.ManagerHops,
				SourceGroups: []string{"*"}, DestinationScopes: []string{"*"},
				FlowClasses:           routingFlowClasses,
				MaxRTTMilliseconds:    path.RTTMilliseconds,
				MaxJitterMilliseconds: path.JitterMilliseconds,
				MaxLossPercent:        path.LossPercent,
				MinBandwidthMbps:      path.BandwidthMbps,
			}.Normalized()
		}
	}
	families := make([]model.PathFamily, 0, len(byID))
	for _, family := range byID {
		families = append(families, family)
	}
	sort.Slice(families, func(i, j int) bool { return families[i].ID < families[j].ID })
	return families
}

func copyPathFamilies(families []model.PathFamily) []model.PathFamily {
	result := make([]model.PathFamily, 0, len(families))
	for _, family := range families {
		result = append(result, family.Normalized())
	}
	sort.Slice(result, func(i, j int) bool { return result[i].ID < result[j].ID })
	return result
}

func copyRoutingDomains(domains []model.RoutingDomainAuthorization) []model.RoutingDomainAuthorization {
	result := make([]model.RoutingDomainAuthorization, 0, len(domains))
	for _, domain := range domains {
		result = append(result, domain.Normalized())
	}
	sort.Slice(result, func(i, j int) bool { return result[i].ID < result[j].ID })
	return result
}

func routingDomainsFromState(
	state model.NetworkState, sourceManagerID string, families []model.PathFamily,
) []model.RoutingDomainAuthorization {
	defaultFlowClass := state.Settings.DefaultFlowClass
	if defaultFlowClass == "" {
		defaultFlowClass = model.FlowClassLatency
	}
	domains := make(map[model.RoutingDomainKey]model.RoutingDomainAuthorization)
	addDomain := func(sourceGroups []string, destinationScope, flowClass, policyID string, services []model.Service) {
		if len(sourceGroups) == 0 {
			sourceGroups = []string{"*"}
		}
		if flowClass == "" {
			flowClass = defaultFlowClass
		}
		for _, sourceGroup := range sourceGroups {
			key := model.RoutingDomainKey{
				SourceManagerID: sourceManagerID, SourceGroupID: sourceGroup,
				DestinationScope: destinationScope, FlowClass: flowClass,
			}
			domain := domains[key]
			domain.Key = key
			domain.PathFamilyIDs = append(domain.PathFamilyIDs, familyIDsCovering(families, key)...)
			if policyID != "" {
				domain.PolicyIDs = append(domain.PolicyIDs, policyID)
			}
			domain.Services = append(domain.Services, services...)
			domains[key] = domain.Normalized()
		}
	}
	for _, policy := range state.Policies {
		if policy.Effect != model.EffectAllow {
			continue
		}
		destinations := policy.DestinationGroups
		if len(destinations) == 0 {
			destinations = []string{"*"}
		}
		for _, destination := range destinations {
			addDomain(policy.SourceGroups, "group:"+destination, policy.FlowClass, policy.ID, policy.Services)
		}
	}
	for _, route := range state.Routes {
		addDomain(route.DistributionGroup, "route:"+route.ID, route.FlowClass, "", nil)
	}
	result := make([]model.RoutingDomainAuthorization, 0, len(domains))
	for _, domain := range domains {
		domain.ID = routingDomainID(domain.Key)
		result = append(result, domain)
	}
	sort.Slice(result, func(i, j int) bool {
		left, right := result[i].Key, result[j].Key
		return routingDomainID(left) < routingDomainID(right)
	})
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

func routingDomainID(key model.RoutingDomainKey) string {
	return strings.Join([]string{
		key.SourceManagerID, key.SourceGroupID, key.DestinationScope, key.FlowClass,
	}, "/")
}

func managerCapacityFromState(
	committee []model.CommitteeMember, budgets []model.TrafficBudget, now time.Time,
) []ManagerCapacityStatus {
	result := make([]ManagerCapacityStatus, 0, len(committee))
	for _, member := range committee {
		status := ManagerCapacityStatus{
			ManagerID: member.ID, State: "unconfigured", UpdatedAt: now,
		}
		for _, budget := range budgets {
			if budget.SubjectType != "manager" || budget.SubjectID != member.ID {
				continue
			}
			status.Configured = true
			status.MonthlyBytes = budget.MonthlyBytes
			status.UsedBytes = budget.UsedMonthlyBytes
			status.CountMode = "total"
			if budget.MonthlyBytes > status.UsedBytes {
				status.RemainingBytes = budget.MonthlyBytes - status.UsedBytes
			}
			if budget.MonthlyBytes > 0 {
				status.Pressure = float64(budget.UsedMonthlyBytes) / float64(budget.MonthlyBytes)
			}
			status.State = capacityState(status.Pressure)
			break
		}
		result = append(result, status)
	}
	return result
}

func capacityState(pressure float64) string {
	switch {
	case pressure >= 1:
		return "exhausted"
	case pressure >= .9:
		return "projected-exhaustion"
	case pressure >= .7:
		return "pressure"
	default:
		return "normal"
	}
}

func edgeTelemetryFromLinkView(view link.LinkView) []EdgeTelemetry {
	segments := make([]link.SegmentView, 0, len(view.Segments)+len(view.AccessSegments))
	segments = append(segments, view.Segments...)
	segments = append(segments, view.AccessSegments...)
	telemetry := make([]EdgeTelemetry, 0, len(segments))
	for _, segment := range segments {
		telemetry = append(telemetry, EdgeTelemetry{
			EdgeID:             segment.From + "->" + segment.To,
			ManagerID:          segment.From,
			RTTMilliseconds:    segment.RTTMilliseconds,
			JitterMilliseconds: segment.JitterMilliseconds,
			LossPercent:        segment.LossPercent,
			MeasuredBandwidth:  segment.BandwidthMbps,
			UpdatedAt:          segment.UpdatedAt,
			Source:             "link-view",
		})
	}
	sort.Slice(telemetry, func(i, j int) bool { return telemetry[i].EdgeID < telemetry[j].EdgeID })
	return telemetry
}

func disabledFECDiagnostics() FECDiagnostics {
	classes := make([]FECClassDiagnostics, 0, len(routingFlowClasses))
	for _, flowClass := range routingFlowClasses {
		classes = append(classes, FECClassDiagnostics{FlowClass: flowClass})
	}
	return FECDiagnostics{Classes: classes}
}

func normalizeRoutingStatus(status *RoutingStatus) {
	if status.Mode == "" {
		status.Mode = "runtime"
	}
	if status.SupportedFlowClasses == nil {
		status.SupportedFlowClasses = routingFlowClasses
	}
	if status.Domains == nil {
		status.Domains = []model.RoutingDomainAuthorization{}
	}
	if status.PathFamilies == nil {
		status.PathFamilies = []model.PathFamily{}
	}
	if status.ManagerCapacity == nil {
		status.ManagerCapacity = []ManagerCapacityStatus{}
	}
	if status.Telemetry == nil {
		status.Telemetry = []EdgeTelemetry{}
	}
	if status.Demand == nil {
		status.Demand = []DemandSample{}
	}
	if status.Fec.Classes == nil {
		status.Fec.Classes = []FECClassDiagnostics{}
	}
	if status.Problems == nil {
		status.Problems = []string{}
	}
	if status.Epoch != nil && status.Epoch.Allocations == nil {
		status.Epoch.Allocations = []PathAllocation{}
	}
}
