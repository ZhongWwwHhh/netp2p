package link

import (
	"sort"

	"github.com/netp2p/netp2p/internal/model"
)

// AssignmentInput is the certified state needed by the planner.
type AssignmentInput struct {
	State     model.NetworkState
	Committee []model.CommitteeMember
	View      LinkView
	Allowed   map[string]map[string][]model.Service
}

// AssignmentFor returns a certified-style assignment for a policy-allowed
// peer pair. It prefers direct, then single-hop managers, then multi-hop paths
// up to the certified maximum. Existing assignments are retained if their
// primary score is within switchThreshold of the best new score.
func AssignmentFor(input AssignmentInput, sourcePeerID, destinationPeerID string, switchThreshold float64) (model.RouteAssignment, bool) {
	source := findPeer(input.State, sourcePeerID)
	destination := findPeer(input.State, destinationPeerID)
	if source.PeerID == "" || destination.PeerID == "" {
		return model.RouteAssignment{}, false
	}
	settings := input.State.Settings
	maxHops := settings.MaxManagerHops
	if maxHops <= 0 {
		maxHops = 2
	}
	forwarding := forwardingManagers(input.Committee)
	candidates := candidatePaths(source.PeerID, destination.PeerID, forwarding, input.View, settings)
	if len(candidates) == 0 {
		return model.RouteAssignment{}, false
	}
	sort.Slice(candidates, func(i, j int) bool { return candidates[i].Score > candidates[j].Score })

	assignment := model.RouteAssignment{
		ID:                AssignmentID(sourcePeerID, destinationPeerID),
		NetworkID:         input.State.NetworkID,
		SourcePeerID:      sourcePeerID,
		DestinationPeerID: destinationPeerID,
		Epoch:             maxEpoch(input.State, sourcePeerID, destinationPeerID),
		RequiresAdmission: true,
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
	Spec  model.PathSpec
	Score float64
}

func candidatePaths(source, destination string, managers []model.CommitteeMember, view LinkView, settings model.NetworkSettings) []scoredPath {
	result := make([]scoredPath, 0)
	if settings.DirectPathEnabled {
		direct := model.PathSpec{Kind: model.PathKindDirect, Confidence: 0.5}
		direct.ID = AssignmentID(source, destination) + "-direct"
		result = append(result, scoredPath{direct, directScore(direct, settings)})
	}
	if !settings.ViaManagerEnabled {
		return result
	}
	maxHops := settings.MaxManagerHops
	if maxHops <= 0 {
		maxHops = 2
	}
	for _, first := range managers {
		appendViaManagerPath(&result, source, destination, []string{first.PeerID}, view, settings)
		if maxHops < 2 {
			continue
		}
		for _, second := range managers {
			if first.PeerID == second.PeerID {
				continue
			}
			appendViaManagerPath(&result, source, destination, []string{first.PeerID, second.PeerID}, view, settings)
		}
	}
	return result
}

func appendViaManagerPath(result *[]scoredPath, source, destination string, hops []string, view LinkView, settings model.NetworkSettings) {
	spec := model.PathSpec{Kind: model.PathKindViaManager, ManagerHops: hops, Confidence: 0.6}
	spec.ID = AssignmentID(source, destination) + "-via-" + hops[0]
	for _, hop := range hops {
		spec.ID += "-" + hop
	}
	rtt, loss, bandwidth, confidence := composeHops(hops, view, source, destination)
	if rtt < 0 {
		return
	}
	spec.RTTMilliseconds = rtt
	spec.LossPercent = loss
	spec.BandwidthMbps = bandwidth
	spec.Confidence = confidence
	*result = append(*result, scoredPath{spec, directScore(spec, settings)})
}

func composeHops(hops []string, view LinkView, source, destination string) (float64, float64, float64, float64) {
	previous := source
	rtt := 0.0
	loss := 0.0
	bandwidth := 0.0
	confidence := 1.0
	for _, hop := range hops {
		segment, ok := segmentFor(view, previous, hop)
		if !ok {
			return -1, 0, 0, 0
		}
		rtt += segment.RTTMilliseconds
		loss = worstLoss(loss, segment.LossPercent)
		if bandwidth == 0 || segment.BandwidthMbps < bandwidth {
			bandwidth = segment.BandwidthMbps
		}
		confidence *= segment.Confidence
		previous = hop
	}
	if finalSegment, ok := segmentFor(view, hops[len(hops)-1], destination); ok {
		rtt += finalSegment.RTTMilliseconds
		loss = worstLoss(loss, finalSegment.LossPercent)
		if bandwidth == 0 || finalSegment.BandwidthMbps < bandwidth {
			bandwidth = finalSegment.BandwidthMbps
		}
		confidence *= finalSegment.Confidence
	}
	return rtt, loss, bandwidth, confidence
}

func segmentFor(view LinkView, from, to string) (SegmentView, bool) {
	for _, segment := range view.Segments {
		if segment.From == from && segment.To == to {
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

func directScore(spec model.PathSpec, settings model.NetworkSettings) float64 {
	minimum := settings.LinkMinBandwidthMbps
	if minimum <= 0 {
		minimum = 10
	}
	if spec.BandwidthMbps > 0 && spec.BandwidthMbps < minimum {
		return 0
	}
	score := 100 - spec.RTTMilliseconds*0.2 - spec.LossPercent*5 + spec.Confidence*10
	if spec.Kind == model.PathKindDirect {
		score += 10
	}
	if score < 0 {
		return 0
	}
	return score
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
