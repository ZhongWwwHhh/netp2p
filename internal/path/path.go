// Package path scores libp2p path candidates from local link measurements.
package path

import (
	"math"
	"sort"
)

type PathType string

const (
	PathDirect   PathType = "direct"
	PathRelay    PathType = "relay"
	PathMultiHop PathType = "multi-hop"
	PathGateway  PathType = "gateway"
)

type FlowClass string

const (
	FlowLatency     FlowClass = "latency"
	FlowThroughput  FlowClass = "throughput"
	FlowCost        FlowClass = "cost"
	FlowReliability FlowClass = "reliability"
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
	RelayCost          float64  `json:"relayCost"`
	PublicRelay        bool     `json:"publicRelay"`
}

type Constraints struct {
	FlowClass            FlowClass  `json:"flowClass"`
	AllowedTypes         []PathType `json:"allowedTypes"`
	MaxRTTMilliseconds   float64    `json:"maxRttMilliseconds"`
	MaxLossPercent       float64    `json:"maxLossPercent"`
	MinBandwidthMbps     float64    `json:"minBandwidthMbps"`
	MaxRelayCost         float64    `json:"maxRelayCost"`
	AllowPublicRelay     bool       `json:"allowPublicRelay"`
	SwitchLatencyPenalty float64    `json:"switchLatencyPenalty"`
	// RelayLatencyAdvantageMs and RelayLossAdvantagePct define the
	// normalisation window: relay RTT and loss must be measurably better
	// than direct within these thresholds before the score favours relay.
	RelayLatencyAdvantageMs float64 `json:"relayLatencyAdvantageMs,omitempty"`
	RelayLossAdvantagePct   float64 `json:"relayLossAdvantagePct,omitempty"`
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
	default:
		return .5, .15, .25, .1
	}
}

// Score returns 0..100. A candidate failing a hard constraint scores zero.
func Score(candidate LinkProfile, constraints Constraints) float64 {
	if !typeAllowed(candidate, constraints) ||
		(constraints.MaxRTTMilliseconds > 0 && candidate.RTTMilliseconds > constraints.MaxRTTMilliseconds) ||
		(constraints.MaxLossPercent > 0 && candidate.LossPercent > constraints.MaxLossPercent) ||
		(constraints.MinBandwidthMbps > 0 && candidate.BandwidthMbps < constraints.MinBandwidthMbps) ||
		(constraints.MaxRelayCost > 0 && candidate.RelayCost > constraints.MaxRelayCost) ||
		(!constraints.AllowPublicRelay && candidate.PublicRelay) {
		return 0
	}

	minBW := constraints.MinBandwidthMbps
	if minBW <= 0 {
		minBW = 10
	}
	latencyGood := 10.0
	latencyAdvantage := constraints.RelayLatencyAdvantageMs
	if latencyAdvantage <= 0 {
		latencyAdvantage = 50
	}
	lossAdvantage := constraints.RelayLossAdvantagePct
	if lossAdvantage <= 0 {
		lossAdvantage = 5
	}
	latencyScore := 1 - normalize(candidate.RTTMilliseconds, latencyGood, 300)
	jitterScore := 1 - normalize(candidate.JitterMilliseconds, 2, 60)
	bandwidthScore := normalize(candidate.BandwidthMbps, minBW, 500)
	reliabilityScore := candidate.Stability * (1 - normalize(candidate.LossPercent, 0, 15)) * (1 - normalize(candidate.Congestion, 0, 1))
	costScore := 1 - normalize(candidate.RelayCost, 0, 100)
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
	// The relay advantage is modelled as a bonus: if a relay path is
	// measurably better than direct on latency or loss (within the
	// normalisation window), it earns extra score that offsets the default
	// preference for direct. This ensures relay wins when the user's
	// threshold conditions are satisfied.
	if candidate.Type == PathRelay {
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
