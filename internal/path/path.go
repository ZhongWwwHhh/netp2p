// Package path scores libp2p path candidates from local link measurements.
package path

import (
	"math"
	"sort"
)

type PathType string

const (
	PathDirect     PathType = "direct"
	PathViaManager PathType = "via-manager"
	PathMultiHop   PathType = "multi-hop"
)

type FlowClass string

const (
	FlowLatency     FlowClass = "latency"
	FlowThroughput  FlowClass = "throughput"
	FlowCost        FlowClass = "cost"
	FlowReliability FlowClass = "reliability"
	FlowRealtime    FlowClass = "realtime"
)

type LinkProfile struct {
	PathID             string   `json:"pathId"`
	Type               PathType `json:"type"`
	NextPeer           string   `json:"nextPeer"`
	RTTMilliseconds    float64  `json:"rttMilliseconds"`
	LossPercent        float64  `json:"lossPercent"`
	JitterMilliseconds float64  `json:"jitterMilliseconds"`
	BandwidthMbps      float64  `json:"bandwidthMbps"`
	Stability          float64  `json:"stability"`
	Congestion         float64  `json:"congestion"`
	ForwardingCost     float64  `json:"forwardingCost"`
}

type Constraints struct {
	FlowClass             FlowClass  `json:"flowClass"`
	AllowedTypes          []PathType `json:"allowedTypes"`
	MaxRTTMilliseconds    float64    `json:"maxRttMilliseconds"`
	MaxJitterMilliseconds float64    `json:"maxJitterMilliseconds"`
	MaxLossPercent        float64    `json:"maxLossPercent"`
	MinBandwidthMbps      float64    `json:"minBandwidthMbps"`
	MaxForwardingCost     float64    `json:"maxForwardingCost"`
	SwitchLatencyPenalty  float64    `json:"switchLatencyPenalty"`
	// ViaManagerLatencyAdvantageMs and ViaManagerLossAdvantagePct define the
	// normalisation window: a via-manager path must be measurably better than
	// direct within these thresholds before the score favours it.
	ViaManagerLatencyAdvantageMs float64 `json:"viaManagerLatencyAdvantageMs,omitempty"`
	ViaManagerLossAdvantagePct   float64 `json:"viaManagerLossAdvantagePct,omitempty"`
}

func typeAllowed(candidate LinkProfile, constraints Constraints) bool {
	if len(constraints.AllowedTypes) == 0 {
		return true
	}
	for _, pathType := range constraints.AllowedTypes {
		if candidate.Type == pathType {
			return true
		}
	}
	return false
}

func normalize(value, good, bad float64) float64 {
	if bad <= good {
		return 1
	}
	ratio := (value - good) / (bad - good)
	return math.Max(0, math.Min(1, ratio))
}

func weights(class FlowClass) (latency, throughput, reliability, cost float64) {
	switch class {
	case FlowThroughput:
		return .15, .55, .2, .1
	case FlowCost:
		return .2, .15, .15, .5
	case FlowReliability:
		return .25, .2, .4, .15
	case FlowRealtime:
		return .55, .05, .3, .1
	default:
		return .5, .15, .25, .1
	}
}

// Score returns 0..100. A candidate failing a hard constraint scores zero.
//
// A zero BandwidthMbps means "not measured yet" rather than "no bandwidth":
// unknown bandwidth neither trips the minimum-bandwidth constraint nor zeroes
// the throughput dimension, it just contributes a neutral score.
func Score(candidate LinkProfile, constraints Constraints) float64 {
	if !typeAllowed(candidate, constraints) ||
		(constraints.MaxRTTMilliseconds > 0 && candidate.RTTMilliseconds > constraints.MaxRTTMilliseconds) ||
		(constraints.MaxJitterMilliseconds > 0 && candidate.JitterMilliseconds > constraints.MaxJitterMilliseconds) ||
		(constraints.MaxLossPercent > 0 && candidate.LossPercent > constraints.MaxLossPercent) ||
		(constraints.MinBandwidthMbps > 0 && candidate.BandwidthMbps > 0 && candidate.BandwidthMbps < constraints.MinBandwidthMbps) ||
		(constraints.MaxForwardingCost > 0 && candidate.ForwardingCost > constraints.MaxForwardingCost) {
		return 0
	}

	minBW := constraints.MinBandwidthMbps
	if minBW <= 0 {
		minBW = 10
	}
	latencyGood := 10.0
	latencyAdvantage := constraints.ViaManagerLatencyAdvantageMs
	if latencyAdvantage <= 0 {
		latencyAdvantage = 50
	}
	lossAdvantage := constraints.ViaManagerLossAdvantagePct
	if lossAdvantage <= 0 {
		lossAdvantage = 5
	}
	latencyScore := 1 - normalize(candidate.RTTMilliseconds, latencyGood, 300)
	jitterScore := 1 - normalize(candidate.JitterMilliseconds, 2, 60)
	bandwidthScore := 0.5
	if candidate.BandwidthMbps > 0 {
		bandwidthScore = normalize(candidate.BandwidthMbps, minBW, 500)
	}
	reliabilityScore := candidate.Stability * (1 - normalize(candidate.LossPercent, 0, 15)) * (1 - normalize(candidate.Congestion, 0, 1))
	costScore := 1 - normalize(candidate.ForwardingCost, 0, 100)
	switchPenalty := constraints.SwitchLatencyPenalty
	if switchPenalty <= 0 {
		switchPenalty = 0.15
	}
	latencyWeight, throughputWeight, reliabilityWeight, costWeight := weights(constraints.FlowClass)
	score := latencyWeight*(latencyScore*.7+jitterScore*.3) +
		throughputWeight*bandwidthScore +
		reliabilityWeight*reliabilityScore +
		costWeight*costScore
	if candidate.Type != PathDirect {
		score -= switchPenalty
	}
	// The via-manager advantage is modelled as a bonus: if a via-manager path is
	// measurably better than direct on latency or loss (within the
	// normalisation window), it earns extra score that offsets the default
	// preference for direct. This ensures via-manager wins when the user's
	// threshold conditions are satisfied.
	if candidate.Type == PathViaManager || candidate.Type == PathMultiHop {
		latencyBonus := normalize(candidate.RTTMilliseconds, latencyGood, latencyGood+latencyAdvantage)
		lossBonus := normalize(candidate.LossPercent, 0, lossAdvantage)
		score += 0.23 * math.Max(latencyBonus, lossBonus)
	}
	return math.Max(0, score*100)
}

type Decision struct {
	Path     LinkProfile  `json:"path"`
	Score    float64      `json:"score"`
	Fallback *LinkProfile `json:"fallback,omitempty"`
}

// Select returns the best eligible path and optionally a distinct fallback.
func Select(candidates []LinkProfile, constraints Constraints, currentPathID string) Decision {
	type ranked struct {
		path  LinkProfile
		score float64
	}
	eligible := make([]ranked, 0, len(candidates))
	for _, candidate := range candidates {
		score := Score(candidate, constraints)
		if score > 0 {
			eligible = append(eligible, ranked{candidate, score})
		}
	}
	sort.Slice(eligible, func(i, j int) bool {
		if eligible[i].score == eligible[j].score {
			return eligible[i].path.PathID < eligible[j].path.PathID
		}
		return eligible[i].score > eligible[j].score
	})
	if len(eligible) == 0 {
		return Decision{}
	}
	decision := Decision{Path: eligible[0].path, Score: eligible[0].score}
	for _, item := range eligible[1:] {
		if item.path.PathID != decision.Path.PathID && item.path.NextPeer != decision.Path.NextPeer {
			fallback := item.path
			decision.Fallback = &fallback
			break
		}
	}
	if currentPathID == decision.Path.PathID {
		decision.Score += constraints.SwitchLatencyPenalty * 100
	}
	return decision
}
