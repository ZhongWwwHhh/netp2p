package link

import (
	"net/netip"
	"sort"
	"strings"

	"github.com/netp2p/netp2p/internal/model"
	"github.com/netp2p/netp2p/internal/path"
	"github.com/netp2p/netp2p/internal/protocol"
)

// accessConfidenceFactor discounts manager-observed client links relative to
// the manager mesh: they are useful for estimating the first and last hop of a
// via-manager path, but they are a single-observer estimate.
const accessConfidenceFactor = 0.6

// AssignmentInput is the certified state needed by the planner.
type AssignmentInput struct {
	State      model.NetworkState
	Committee  []model.CommitteeMember
	View       LinkView
	Admissions map[string]map[string]protocol.AdmissionReport
	Allowed    map[string]map[string][]model.Service
}

// AssignmentFor returns a certified-style assignment for a policy-allowed peer
// pair. Candidates are scored with the shared path.Score function, so the
// scoring rules (FlowClass weights, hard constraints, via-manager advantage
// window, switch penalty) live in exactly one place. Existing assignments are
// kept as long as the new primary is within switchThreshold of the best score.
func AssignmentFor(input AssignmentInput, sourcePeerID, destinationPeerID string, switchThreshold float64) (model.RouteAssignment, bool) {
	source := findPeer(input.State, sourcePeerID)
	destination := findPeer(input.State, destinationPeerID)
	if source.PeerID == "" || destination.PeerID == "" {
		return model.RouteAssignment{}, false
	}
	settings := input.State.Settings
	route, hasRoute := routeFor(input.State, source, destination)
	options := pathOptions{Settings: settings, Admissions: input.Admissions}
	if hasRoute {
		options.Route = &route
		options.BudgetLimits = forwardingCostLimits(input.State, route.BudgetIDs)
	}
	forwarding := forwardingManagers(input.Committee)
	candidates := candidatePaths(source.PeerID, destination.PeerID, forwarding, input.View, options)
	if len(candidates) == 0 {
		return model.RouteAssignment{}, false
	}
	sort.SliceStable(candidates, func(i, j int) bool {
		if candidates[i].Score != candidates[j].Score {
			return candidates[i].Score > candidates[j].Score
		}
		if candidates[i].Centrality != candidates[j].Centrality {
			return candidates[i].Centrality > candidates[j].Centrality
		}
		// Lower metric wins a remaining tie, then a stable path id keeps the
		// ordering deterministic across managers.
		if candidates[i].Metric != candidates[j].Metric {
			return candidates[i].Metric < candidates[j].Metric
		}
		return candidates[i].Spec.ID < candidates[j].Spec.ID
	})

	assignment := model.RouteAssignment{
		ID:                AssignmentID(sourcePeerID, destinationPeerID),
		NetworkID:         input.State.NetworkID,
		SourcePeerID:      sourcePeerID,
		DestinationPeerID: destinationPeerID,
		Epoch:             maxEpoch(input.State, sourcePeerID, destinationPeerID),
		RequiresAdmission: true,
		MaxHops:           effectiveMaxHops(settings),
	}
	assignment.UpdatedAt = input.View.GeneratedAt
	assignment.Primary = candidates[0].Spec
	bestScore := candidates[0].Score
	for _, candidate := range candidates[1:] {
		if candidate.Score > 0 && candidate.Score >= bestScore-switchThreshold {
			assignment.Fallbacks = append(assignment.Fallbacks, candidate.Spec)
		}
	}
	if len(assignment.Fallbacks) == 0 {
		for _, candidate := range candidates[1:] {
			if candidate.Score > 0 {
				assignment.Fallbacks = append(assignment.Fallbacks, candidate.Spec)
				break
			}
		}
	}
	return assignment, true
}

type scoredPath struct {
	Spec       model.PathSpec
	Score      float64
	Centrality float64
	Metric     int
}

// pathOptions carries the certified settings plus the route (if any) that
// scopes the current peer pair. A route overrides the network defaults for
// allowed path types, hop ceiling and flow class.
type pathOptions struct {
	Settings     model.NetworkSettings
	Route        *model.Route
	BudgetLimits []uint64
	Admissions   map[string]map[string]protocol.AdmissionReport
}

func candidatePaths(source, destination string, managers []model.CommitteeMember, view LinkView, options pathOptions) []scoredPath {
	constraints := scoringConstraints(options)
	result := make([]scoredPath, 0)
	metric := 0
	if options.Route != nil {
		metric = options.Route.Metric
	}
	if options.Settings.DirectPathEnabled {
		spec := model.PathSpec{Kind: model.PathKindDirect, Confidence: 0.5}
		spec.ID = AssignmentID(source, destination) + "-direct"
		// The manager mesh cannot measure the peer-to-peer direct link, so an
		// unobserved direct candidate keeps its previous optimistic profile.
		// Client admission is authoritative: a failed probe removes the
		// candidate, while a successful probe confirms it.
		stability := 1.0
		includeDirect := true
		if confirmed, ok := latestAdmission(options.Admissions, source, destination, spec.ID); ok {
			if !confirmed.OK {
				includeDirect = false
			}
			spec.Confidence = 1
		}
		if includeDirect {
			profile := path.LinkProfile{PathID: spec.ID, Type: path.PathDirect, Stability: stability}
			// A direct path has no forwarding cost, so budget limits never
			// exclude it; it still honours an AllowedTypes filter through
			// path.Score.
			result = append(result, scoredPath{Spec: spec, Score: path.Score(profile, constraints), Metric: metric})
		}
	}
	if !options.Settings.ViaManagerEnabled {
		return result
	}
	for _, hops := range enumerateManagerPaths(managers, maxHopsFor(options)) {
		appendViaManagerPath(&result, source, destination, hops, view, constraints, options.BudgetLimits, metric)
	}
	return result
}

// latestAdmission reports the newest client observation for a path. Managers
// retain one report per source/path; the timestamp tie-break keeps restarts
// deterministic when clock precision is coarse.
func latestAdmission(admissions map[string]map[string]protocol.AdmissionReport, source, destination, pathID string) (protocol.AdmissionReport, bool) {
	paths, ok := admissions[source]
	if !ok {
		return protocol.AdmissionReport{}, false
	}
	report, ok := paths[pathID]
	return report, ok
}

// maxCandidatePaths bounds path enumeration so a large committee cannot blow up
// the planner.
const maxCandidatePaths = 128

// enumerateManagerPaths lists every simple manager path (no repeated hop) with
// length 1..maxHops. Hops are PeerIDs so the output matches certified state.
func enumerateManagerPaths(managers []model.CommitteeMember, maxHops int) [][]string {
	if maxHops < 1 {
		maxHops = 1
	}
	var paths [][]string
	var walk func(current []string, remaining int)
	walk = func(current []string, remaining int) {
		if len(paths) >= maxCandidatePaths {
			return
		}
		if len(current) > 0 {
			paths = append(paths, append([]string(nil), current...))
		}
		if remaining == 0 {
			return
		}
		for _, manager := range managers {
			if containsHop(current, manager.PeerID) {
				continue
			}
			walk(append(current, manager.PeerID), remaining-1)
			if len(paths) >= maxCandidatePaths {
				return
			}
		}
	}
	walk(nil, maxHops)
	return paths
}

func containsHop(hops []string, hop string) bool {
	for _, existing := range hops {
		if existing == hop {
			return true
		}
	}
	return false
}

func effectiveMaxHops(settings model.NetworkSettings) int {
	if settings.MaxManagerHops > 0 {
		return settings.MaxManagerHops
	}
	return 2
}

// maxHopsFor returns the certified hop ceiling, preferring a route-level
// override when one is present.
func maxHopsFor(options pathOptions) int {
	if options.Route != nil && options.Route.MaxHops > 0 {
		return options.Route.MaxHops
	}
	return effectiveMaxHops(options.Settings)
}

// forwardingCostLimits collects the cost ceilings of the budgets attached to a
// route so the planner can hard-exclude paths that exceed them.
func forwardingCostLimits(state model.NetworkState, budgetIDs []string) []uint64 {
	if len(budgetIDs) == 0 {
		return nil
	}
	limits := make([]uint64, 0, len(budgetIDs))
	for _, id := range budgetIDs {
		for _, budget := range state.Budgets {
			if budget.ID == id {
				limits = append(limits, budget.ForwardingCostLimit)
				break
			}
		}
	}
	return limits
}

func appendViaManagerPath(result *[]scoredPath, source, destination string, hops []string, view LinkView, constraints path.Constraints, budgetLimits []uint64, metric int) {
	// A single manager hop is a via-manager path; two or more is multi-hop. The
	// distinction lets a route allow one without the other.
	kind := model.PathKindViaManager
	pathType := path.PathViaManager
	if len(hops) >= 2 {
		kind = model.PathKindMultiHop
		pathType = path.PathMultiHop
	}
	spec := model.PathSpec{Kind: kind, ManagerHops: hops, Confidence: 0.6}
	spec.ID = AssignmentID(source, destination) + "-via-" + hops[0]
	for _, hop := range hops {
		spec.ID += "-" + hop
	}
	metrics, ok := composeHops(hops, view, source, destination)
	if !ok {
		return
	}
	spec.RTTMilliseconds = metrics.rtt
	spec.JitterMilliseconds = metrics.jitter
	spec.LossPercent = metrics.loss
	spec.BandwidthMbps = metrics.bandwidth
	spec.Confidence = metrics.confidence
	// Cost is the number of forwarding hops; with equal measurements a shorter
	// path always breaks the tie.
	spec.Cost = uint64(len(hops))
	profile := path.LinkProfile{
		PathID:             spec.ID,
		Type:               pathType,
		RTTMilliseconds:    metrics.rtt,
		LossPercent:        metrics.loss,
		JitterMilliseconds: metrics.jitter,
		BandwidthMbps:      metrics.bandwidth,
		Stability:          metrics.stability,
		ForwardingCost:     float64(len(hops)),
	}
	score := path.Score(profile, constraints)
	for _, limit := range budgetLimits {
		if limit > 0 && spec.Cost > limit {
			score = 0
			break
		}
	}
	*result = append(*result, scoredPath{
		Spec: spec, Score: score, Centrality: hopCentrality(view, hops), Metric: metric,
	})
}

func scoringConstraints(options pathOptions) path.Constraints {
	settings := options.Settings
	flowClass := path.FlowClass(settings.DefaultFlowClass)
	if options.Route != nil && options.Route.FlowClass != "" {
		flowClass = path.FlowClass(options.Route.FlowClass)
	}
	if flowClass == "" {
		flowClass = path.FlowLatency
	}
	constraints := path.Constraints{
		FlowClass:                    flowClass,
		MinBandwidthMbps:             settings.LinkMinBandwidthMbps,
		ViaManagerLatencyAdvantageMs: settings.ViaManagerLatencyAdvantageMs,
		ViaManagerLossAdvantagePct:   settings.ViaManagerLossAdvantagePct,
	}
	if options.Route != nil {
		constraints.AllowedTypes = mapAllowedPathTypes(options.Route.AllowedPathTypes)
	}
	return constraints
}

// mapAllowedPathTypes translates the certified route vocabulary
// (direct/via_manager/multi-hop) into the planner's PathType constants. An
// empty result means "any".
func mapAllowedPathTypes(values []string) []path.PathType {
	if len(values) == 0 {
		return nil
	}
	seen := make(map[path.PathType]struct{}, len(values))
	result := make([]path.PathType, 0, len(values))
	for _, value := range values {
		var pathType path.PathType
		switch strings.TrimSpace(value) {
		case "direct":
			pathType = path.PathDirect
		case "via_manager":
			pathType = path.PathViaManager
		case "multi-hop", "multi_hop":
			pathType = path.PathMultiHop
		default:
			continue
		}
		if _, exists := seen[pathType]; exists {
			continue
		}
		seen[pathType] = struct{}{}
		result = append(result, pathType)
	}
	return result
}

// routeFor returns the certified route that covers a source->destination peer
// pair. Destination matching is by CIDR against the destination overlay IP;
// source matching requires membership in the route's distribution groups
// (empty means every peer). Multiple matches resolve by metric then route id so
// every manager agrees.
func routeFor(state model.NetworkState, source, destination model.PeerRecord) (model.Route, bool) {
	address, err := netip.ParseAddr(destination.OverlayIP)
	if err != nil {
		return model.Route{}, false
	}
	address = address.Unmap()
	matches := make([]model.Route, 0)
	for _, route := range state.Routes {
		prefix, err := netip.ParsePrefix(route.Destination)
		if err != nil || !prefix.Contains(address) {
			continue
		}
		if !sourceInRoute(state, route, source.PeerID) {
			continue
		}
		matches = append(matches, route)
	}
	if len(matches) == 0 {
		return model.Route{}, false
	}
	sort.SliceStable(matches, func(i, j int) bool {
		if matches[i].Metric != matches[j].Metric {
			return matches[i].Metric < matches[j].Metric
		}
		return matches[i].ID < matches[j].ID
	})
	return matches[0], true
}

func sourceInRoute(state model.NetworkState, route model.Route, peerID string) bool {
	if len(route.DistributionGroup) == 0 {
		return true
	}
	for _, groupID := range route.DistributionGroup {
		for _, group := range state.Groups {
			if group.ID != groupID {
				continue
			}
			for _, member := range group.PeerIDs {
				if member == peerID {
					return true
				}
			}
		}
	}
	return false
}

// hopCentrality sums the EigenSpeed score of a path's managers. It is only used
// to break ties between otherwise equally scored candidates.
func hopCentrality(view LinkView, hops []string) float64 {
	if len(view.Centrality) == 0 {
		return 0
	}
	scores := make(map[string]float64, len(view.Centrality))
	for _, entry := range view.Centrality {
		scores[entry.PeerID] = entry.Score
	}
	total := 0.0
	for _, hop := range hops {
		total += scores[hop]
	}
	return total
}

type pathMetrics struct {
	rtt        float64
	loss       float64
	jitter     float64
	bandwidth  float64
	stability  float64
	confidence float64
}

// composeHops combines the per-segment estimates along a via-manager path.
// Every segment, including the final manager-to-destination access link, must
// have been measured; otherwise the path is not yet usable and the planner
// simply omits it.
func composeHops(hops []string, view LinkView, source, destination string) (pathMetrics, bool) {
	previous := source
	metrics := pathMetrics{stability: 1, confidence: 1}
	for _, hop := range hops {
		segment, ok := segmentFor(view, previous, hop)
		if !ok {
			return pathMetrics{}, false
		}
		metrics.accumulate(segment)
		previous = hop
	}
	finalSegment, ok := segmentFor(view, hops[len(hops)-1], destination)
	if !ok {
		return pathMetrics{}, false
	}
	metrics.accumulate(finalSegment)
	return metrics, true
}

func (metrics *pathMetrics) accumulate(segment SegmentView) {
	metrics.rtt += segment.RTTMilliseconds
	metrics.loss = worstLoss(metrics.loss, segment.LossPercent)
	metrics.jitter = worstJitter(metrics.jitter, segment.JitterMilliseconds)
	if segment.BandwidthMbps > 0 && (metrics.bandwidth == 0 || segment.BandwidthMbps < metrics.bandwidth) {
		metrics.bandwidth = segment.BandwidthMbps
	}
	if segment.Stability < metrics.stability {
		metrics.stability = segment.Stability
	}
	metrics.confidence *= segment.Confidence
}

func segmentFor(view LinkView, from, to string) (SegmentView, bool) {
	if segment, ok := findSegment(view.Segments, from, to); ok {
		return segment, true
	}
	if segment, ok := findSegmentReverse(view.Segments, from, to); ok {
		return segment, true
	}
	if segment, ok := findSegment(view.AccessSegments, from, to); ok {
		segment.Confidence *= accessConfidenceFactor
		return segment, true
	}
	if segment, ok := findSegmentReverse(view.AccessSegments, from, to); ok {
		segment.Confidence *= accessConfidenceFactor
		return segment, true
	}
	return SegmentView{}, false
}

func findSegment(segments []SegmentView, from, to string) (SegmentView, bool) {
	for _, segment := range segments {
		if segment.From == from && segment.To == to {
			return segment, true
		}
	}
	return SegmentView{}, false
}

// findSegmentReverse accepts a segment that was measured in the opposite
// direction and reorients it so the caller sees traffic flowing from -> to.
func findSegmentReverse(segments []SegmentView, from, to string) (SegmentView, bool) {
	for _, segment := range segments {
		if segment.From == to && segment.To == from {
			segment.From, segment.To = from, to
			return segment, true
		}
	}
	return SegmentView{}, false
}

func worstLoss(current, next float64) float64 {
	if next > current {
		return next
	}
	return current
}

func worstJitter(current, next float64) float64 {
	if next > current {
		return next
	}
	return current
}

func forwardingManagers(committee []model.CommitteeMember) []model.CommitteeMember {
	result := make([]model.CommitteeMember, 0, len(committee))
	for _, member := range committee {
		if member.ForwardingEnabled {
			result = append(result, member)
		}
	}
	sort.Slice(result, func(i, j int) bool { return result[i].ID < result[j].ID })
	return result
}

func findPeer(state model.NetworkState, peerID string) model.PeerRecord {
	for _, peer := range state.Peers {
		if peer.PeerID == peerID {
			return peer
		}
	}
	return model.PeerRecord{}
}

func maxEpoch(state model.NetworkState, source, destination string) uint64 {
	var epoch uint64
	for _, assignment := range state.Assignments {
		if assignment.SourcePeerID == source && assignment.DestinationPeerID == destination && assignment.Epoch > epoch {
			epoch = assignment.Epoch
		}
	}
	return epoch + 1
}
