// Package link aggregates signed link observations from the manager mesh.
//
// Clients are deliberately outside this model. Their reports are never merged
// here, so a malicious client cannot affect another peer's view of the network.
package link

import (
	"crypto/sha256"
	"encoding/json"
	"math"
	"sort"
	"time"
)

type Scope string

const (
	ScopeManagerMesh Scope = "manager_mesh"
	ScopeAccess      Scope = "access"
	ScopePeerDirect  Scope = "peer_direct"
)

type Direction string

const (
	DirectionOutbound  Direction = "outbound"
	DirectionInbound   Direction = "inbound"
	DirectionRoundTrip Direction = "roundtrip"
)

type Observation struct {
	ObserverID         string    `json:"observerId"`
	SubjectID          string    `json:"subjectId"`
	Scope              Scope     `json:"scope"`
	Direction          Direction `json:"direction"`
	RTTMilliseconds    float64   `json:"rttMilliseconds"`
	LossPercent        float64   `json:"lossPercent"`
	JitterMilliseconds float64   `json:"jitterMilliseconds"`
	BandwidthMbps      float64   `json:"bandwidthMbps"`
	Samples            int       `json:"samples"`
	MeasuredAt         time.Time `json:"measuredAt"`
	Sequence           uint64    `json:"sequence"`
	Signature          []byte    `json:"signature,omitempty"`
}

func (observation Observation) Valid(now time.Time, ttl time.Duration) bool {
	return observation.ObserverID != "" && observation.SubjectID != "" &&
		observation.ObserverID != observation.SubjectID &&
		observation.Samples > 0 && observation.RTTMilliseconds >= 0 &&
		observation.LossPercent >= 0 && observation.LossPercent <= 100 &&
		observation.BandwidthMbps >= 0 &&
		!observation.MeasuredAt.IsZero() &&
		now.Sub(observation.MeasuredAt) >= 0 && now.Sub(observation.MeasuredAt) <= ttl
}

// fresh reports whether the observation is still inside its TTL. It is used to
// prune the gossip cache and does not require the observation to be fully
// populated.
func (observation Observation) fresh(now time.Time, ttl time.Duration) bool {
	if observation.MeasuredAt.IsZero() {
		return false
	}
	age := now.Sub(observation.MeasuredAt)
	return age >= 0 && age <= ttl
}

type SegmentView struct {
	From               string    `json:"from"`
	To                 string    `json:"to"`
	RTTMilliseconds    float64   `json:"rttMilliseconds"`
	LossPercent        float64   `json:"lossPercent"`
	JitterMilliseconds float64   `json:"jitterMilliseconds"`
	BandwidthMbps      float64   `json:"bandwidthMbps"`
	Stability          float64   `json:"stability"`
	Confidence         float64   `json:"confidence"`
	SampleCount        int       `json:"sampleCount"`
	Observers          []string  `json:"observers"`
	UpdatedAt          time.Time `json:"updatedAt"`
}

// NodeCentrality is the EigenSpeed power-iteration score of a manager-mesh
// node. It is a deterministic function of the observed edge weights and is
// used to break score ties in favour of better-connected managers.
type NodeCentrality struct {
	PeerID string  `json:"peerId"`
	Score  float64 `json:"score"`
}

type LinkView struct {
	GeneratedAt    time.Time        `json:"generatedAt"`
	Segments       []SegmentView    `json:"segments"`
	AccessSegments []SegmentView    `json:"accessSegments"`
	Centrality     []NodeCentrality `json:"centrality"`
	Hash           []byte           `json:"hash"`
}

// AssignmentID derives a stable, deterministic ID for a directed peer pair.
func AssignmentID(sourcePeerID, destinationPeerID string) string {
	hash := sha256.Sum256([]byte(sourcePeerID + "\x00" + destinationPeerID))
	return "assignment-" + encodeHexPrefix(hash[:])
}

func encodeHexPrefix(raw []byte) string {
	const hexDigits = "0123456789abcdef"
	result := make([]byte, 0, 12)
	for index := 0; index < 6 && index < len(raw); index++ {
		result = append(result, hexDigits[raw[index]>>4], hexDigits[raw[index]&0x0f])
	}
	return string(result)
}

const (
	confidenceSingleObserver = 0.4
	confidenceTwoObservers   = 0.8
	confidenceManyObservers  = 0.9
	accessConfidenceCap      = 0.5
	outlierRatio             = 3.0
	outlierWeight            = 0.25
	eigenIterations          = 100
	eigenTolerance           = 1e-9
)

type pairKey struct{ from, to string }

func newPairKey(a, b string) pairKey {
	if a <= b {
		return pairKey{a, b}
	}
	return pairKey{b, a}
}

// Aggregate builds a deterministic view of the manager mesh. Observations are
// grouped into unordered segments; each segment is reduced with a weighted
// trimmed median and the resulting bandwidth graph is scored with an EigenSpeed
// power iteration. Access observations (manager -> client) are kept apart so a
// client can never contribute to the manager mesh matrix.
func Aggregate(observations []Observation, now time.Time, ttl time.Duration, maxRTT float64) LinkView {
	meshPairs := make(map[pairKey][]Observation)
	accessPairs := make(map[pairKey][]Observation)
	for _, observation := range observations {
		if !observation.Valid(now, ttl) {
			continue
		}
		if maxRTT > 0 && observation.RTTMilliseconds > maxRTT {
			continue
		}
		key := newPairKey(observation.ObserverID, observation.SubjectID)
		switch observation.Scope {
		case ScopeManagerMesh:
			meshPairs[key] = append(meshPairs[key], observation)
		case ScopeAccess:
			accessPairs[key] = append(accessPairs[key], observation)
		}
	}

	segments, weights := buildSegments(meshPairs)
	accessSegments := buildAccessSegments(accessPairs)
	centrality := eigenCentrality(weights)

	hash := sha256.Sum256(canonicalJSON(struct {
		Segments       []SegmentView    `json:"segments"`
		AccessSegments []SegmentView    `json:"accessSegments"`
		Centrality     []NodeCentrality `json:"centrality"`
	}{segments, accessSegments, centrality}))
	return LinkView{
		GeneratedAt:    now.UTC(),
		Segments:       segments,
		AccessSegments: accessSegments,
		Centrality:     centrality,
		Hash:           hash[:],
	}
}

type pairStat struct {
	key         pairKey
	rtt         float64
	loss        float64
	jitter      float64
	bandwidth   float64
	stability   float64
	confidence  float64
	sampleCount int
	observers   []string
	updatedAt   time.Time
}

// buildSegments reduces each unordered pair to a single segment and returns the
// edge weights for the EigenSpeed matrix (bandwidth when measured, otherwise a
// latency-derived proxy).
func buildSegments(pairs map[pairKey][]Observation) ([]SegmentView, map[pairKey]float64) {
	stats := make([]pairStat, 0, len(pairs))
	weights := make(map[pairKey]float64, len(pairs))
	for key, group := range pairs {
		stat := summarizePair(key, group)
		stats = append(stats, stat)
		if stat.bandwidth > 0 {
			weights[key] = stat.bandwidth
			continue
		}
		weights[key] = 1000 / (stat.rtt + 1)
	}
	sort.Slice(stats, func(i, j int) bool {
		if stats[i].key.from != stats[j].key.from {
			return stats[i].key.from < stats[j].key.from
		}
		return stats[i].key.to < stats[j].key.to
	})
	segments := make([]SegmentView, 0, len(stats))
	for _, stat := range stats {
		segments = append(segments, stat.view())
	}
	return segments, weights
}

func buildAccessSegments(pairs map[pairKey][]Observation) []SegmentView {
	segments, _ := buildSegments(pairs)
	for index := range segments {
		if segments[index].Confidence > accessConfidenceCap {
			segments[index].Confidence = accessConfidenceCap
		}
	}
	return segments
}

func (stat pairStat) view() SegmentView {
	return SegmentView{
		From:               stat.key.from,
		To:                 stat.key.to,
		RTTMilliseconds:    stat.rtt,
		LossPercent:        stat.loss,
		JitterMilliseconds: stat.jitter,
		BandwidthMbps:      stat.bandwidth,
		Stability:          stat.stability,
		Confidence:         stat.confidence,
		SampleCount:        stat.sampleCount,
		Observers:          stat.observers,
		UpdatedAt:          stat.updatedAt,
	}
}

// summarizePair turns a set of observations about one segment into a single
// estimate. Observations that deviate more than outlierRatio from the trimmed
// median are counted with a reduced weight before the final medians are taken,
// so one manager reporting an implausible number cannot move the segment much.
func summarizePair(key pairKey, group []Observation) pairStat {
	sorted := append([]Observation{}, group...)
	sort.Slice(sorted, func(i, j int) bool {
		if sorted[i].ObserverID != sorted[j].ObserverID {
			return sorted[i].ObserverID < sorted[j].ObserverID
		}
		if !sorted[i].MeasuredAt.Equal(sorted[j].MeasuredAt) {
			return sorted[i].MeasuredAt.Before(sorted[j].MeasuredAt)
		}
		return sorted[i].Sequence < sorted[j].Sequence
	})

	bandwidths := make([]float64, 0, len(sorted))
	rtts := make([]float64, 0, len(sorted))
	losses := make([]float64, 0, len(sorted))
	jitters := make([]float64, 0, len(sorted))
	for _, observation := range sorted {
		bandwidths = append(bandwidths, observation.BandwidthMbps)
		rtts = append(rtts, observation.RTTMilliseconds)
		losses = append(losses, observation.LossPercent)
		jitters = append(jitters, observation.JitterMilliseconds)
	}

	weights := outlierWeights(bandwidths, rtts)
	stat := pairStat{
		key:       key,
		rtt:       weightedMedian(rtts, weights),
		loss:      weightedMedian(losses, weights),
		jitter:    weightedMedian(jitters, weights),
		bandwidth: weightedMedian(bandwidths, weights),
	}
	stat.stability = clamp01(1 - stat.loss/100)
	stat.confidence = observerConfidence(sorted)
	stat.observers = distinctObservers(sorted)
	for _, observation := range sorted {
		stat.sampleCount += observation.Samples
		if observation.MeasuredAt.After(stat.updatedAt) {
			stat.updatedAt = observation.MeasuredAt
		}
	}
	return stat
}

// outlierWeights marks observations whose bandwidth (or, when no bandwidth has
// been measured, latency) deviates by more than outlierRatio from the trimmed
// median of the segment.
func outlierWeights(bandwidths, rtts []float64) []float64 {
	weights := make([]float64, len(bandwidths))
	for index := range weights {
		weights[index] = 1
	}
	// With fewer than three samples there is no majority to compare against,
	// so nothing can be classified as an outlier without guessing.
	if len(bandwidths) < 3 {
		return weights
	}
	reference := trimmedMedian(bandwidths)
	metric := bandwidths
	lowerIsBetter := false
	if reference <= 0 {
		reference = trimmedMedian(rtts)
		metric = rtts
		lowerIsBetter = true
	}
	if reference <= 0 {
		return weights
	}
	for index, value := range metric {
		ratio := value / reference
		outlier := ratio > outlierRatio || (!lowerIsBetter && ratio < 1/outlierRatio)
		if outlier {
			weights[index] = outlierWeight
		}
	}
	return weights
}

func observerConfidence(observations []Observation) float64 {
	switch len(distinctObservers(observations)) {
	case 0:
		return 0
	case 1:
		return confidenceSingleObserver
	case 2:
		return confidenceTwoObservers
	default:
		return confidenceManyObservers
	}
}

func distinctObservers(observations []Observation) []string {
	seen := make(map[string]struct{}, len(observations))
	result := make([]string, 0, len(observations))
	for _, observation := range observations {
		if _, exists := seen[observation.ObserverID]; exists {
			continue
		}
		seen[observation.ObserverID] = struct{}{}
		result = append(result, observation.ObserverID)
	}
	sort.Strings(result)
	return result
}

// trimmedMedian drops the single highest and lowest sample when at least three
// are present, which makes the estimate robust to one outlier.
func trimmedMedian(values []float64) float64 {
	if len(values) == 0 {
		return 0
	}
	sorted := append([]float64{}, values...)
	sort.Float64s(sorted)
	if len(sorted) >= 3 {
		sorted = sorted[1 : len(sorted)-1]
	}
	size := len(sorted)
	if size%2 == 1 {
		return sorted[size/2]
	}
	return (sorted[size/2-1] + sorted[size/2]) / 2
}

func weightedMedian(values, weights []float64) float64 {
	if len(values) == 0 {
		return 0
	}
	indexes := make([]int, len(values))
	for index := range indexes {
		indexes[index] = index
	}
	sort.Slice(indexes, func(i, j int) bool { return values[indexes[i]] < values[indexes[j]] })
	total := 0.0
	for _, weight := range weights {
		total += weight
	}
	if total <= 0 {
		return trimmedMedian(values)
	}
	half := total / 2
	cumulative := 0.0
	for _, index := range indexes {
		cumulative += weights[index]
		if cumulative >= half {
			return values[index]
		}
	}
	return values[indexes[len(indexes)-1]]
}

func clamp01(value float64) float64 {
	return math.Max(0, math.Min(1, value))
}

// eigenCentrality runs a deterministic power iteration over the band-symmetric
// manager mesh weight matrix. The principal eigenvector is the EigenSpeed score
// of each manager; identical inputs always produce identical scores.
func eigenCentrality(weights map[pairKey]float64) []NodeCentrality {
	nodeSet := make(map[string]struct{}, len(weights)*2)
	for key := range weights {
		nodeSet[key.from] = struct{}{}
		nodeSet[key.to] = struct{}{}
	}
	nodes := make([]string, 0, len(nodeSet))
	for node := range nodeSet {
		nodes = append(nodes, node)
	}
	sort.Strings(nodes)
	if len(nodes) == 0 {
		return []NodeCentrality{}
	}
	scores := make([]float64, len(nodes))
	for index := range scores {
		scores[index] = 1
	}
	for iteration := 0; iteration < eigenIterations; iteration++ {
		next := make([]float64, len(nodes))
		for i := range nodes {
			for j := range nodes {
				if i == j {
					continue
				}
				weight, ok := weights[newPairKey(nodes[i], nodes[j])]
				if !ok || weight <= 0 {
					continue
				}
				next[i] += weight * scores[j]
			}
		}
		norm := 0.0
		for _, value := range next {
			norm += value * value
		}
		norm = math.Sqrt(norm)
		if norm == 0 {
			break
		}
		delta := 0.0
		for index := range next {
			next[index] /= norm
			delta += math.Abs(next[index] - scores[index])
		}
		scores = next
		if delta < eigenTolerance {
			break
		}
	}
	result := make([]NodeCentrality, 0, len(nodes))
	for index, node := range nodes {
		result = append(result, NodeCentrality{PeerID: node, Score: scores[index]})
	}
	return result
}

func canonicalJSON(value any) []byte {
	encoded, _ := json.Marshal(value)
	return encoded
}
