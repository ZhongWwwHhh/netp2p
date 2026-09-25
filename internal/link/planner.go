package link

import (
	"sort"

	"github.com/netp2p/netp2p/internal/model"
	"github.com/netp2p/netp2p/internal/path"
)

// accessConfidenceFactor discounts manager-observed client links relative to
// the manager mesh: they are useful for estimating the first and last hop of a
// via-manager path, but they are a single-observer estimate.
const accessConfidenceFactor = 0.6

// AssignmentInput is the certified state needed by the planner.
type AssignmentInput struct {
	State     model.NetworkState
	Committee []model.CommitteeMember
	View      LinkView
	Allowed   map[string]map[string][]model.Service
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
	forwarding := forwardingManagers(input.Committee)
	candidates := candidatePaths(source.PeerID, destination.PeerID, forwarding, input.View, settings)
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
}

func candidatePaths(source, destination string, managers []model.CommitteeMember, view LinkView, settings model.NetworkSettings) []scoredPath {
	constraints := scoringConstraints(settings)
	result := make([]scoredPath, 0)
	if settings.DirectPathEnabled {
		spec := model.PathSpec{Kind: model.PathKindDirect, Confidence: 0.5}
		spec.ID = AssignmentID(source, destination) + "-direct"
		// The manager mesh cannot measure the peer-to-peer direct link, so the
		// direct candidate is scored with unknown metrics: bandwidth stays
		// unknown (not zero, which would trip the minimum-bandwidth constraint)
		// and stability is assumed healthy. Direct therefore wins by default,
		// and only loses when it is disabled or when a via-manager path's
		// measured advantage clears the scoring window and switch penalty.
		profile := path.LinkProfile{PathID: spec.ID, Type: path.PathDirect, Stability: 1}
		result = append(result, scoredPath{Spec: spec, Score: path.Score(profile, constraints)})
	}
	if !settings.ViaManagerEnabled {
		return result
	}
	for _, hops := range enumerateManagerPaths(managers, effectiveMaxHops(settings)) {
		appendViaManagerPath(&result, source, destination, hops, view, constraints)
	}
	return result
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

func appendViaManagerPath(result *[]scoredPath, source, destination string, hops []string, view LinkView, constraints path.Constraints) {
	spec := model.PathSpec{Kind: model.PathKindViaManager, ManagerHops: hops, Confidence: 0.6}
	spec.ID = AssignmentID(source, destination) + "-via-" + hops[0]
	for _, hop := range hops {
		spec.ID += "-" + hop
	}
	metrics, ok := composeHops(hops, view, source, destination)
	if !ok {
		return
	}
	spec.RTTMilliseconds = metrics.rtt
	spec.LossPercent = metrics.loss
	spec.BandwidthMbps = metrics.bandwidth
	spec.Confidence = metrics.confidence
	// Cost is the number of forwarding hops; with equal measurements a shorter
	// path always breaks the tie.
	spec.Cost = uint64(len(hops))
	profile := path.LinkProfile{
		PathID:             spec.ID,
		Type:               path.PathViaManager,
		RTTMilliseconds:    metrics.rtt,
		LossPercent:        metrics.loss,
		JitterMilliseconds: metrics.jitter,
		BandwidthMbps:      metrics.bandwidth,
		Stability:          metrics.stability,
		ForwardingCost:     float64(len(hops)),
	}
	*result = append(*result, scoredPath{
		Spec: spec, Score: path.Score(profile, constraints), Centrality: hopCentrality(view, hops),
	})
}

func scoringConstraints(settings model.NetworkSettings) path.Constraints {
	flowClass := path.FlowClass(settings.DefaultFlowClass)
	if flowClass == "" {
		flowClass = path.FlowLatency
	}
	return path.Constraints{
		FlowClass:                    flowClass,
		MinBandwidthMbps:             settings.LinkMinBandwidthMbps,
		ViaManagerLatencyAdvantageMs: settings.ViaManagerLatencyAdvantageMs,
		ViaManagerLossAdvantagePct:   settings.ViaManagerLossAdvantagePct,
	}
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
