package loadtest

import (
	"errors"
	"fmt"
	"math"
	"sort"
	"time"
)

type OptimizerConfig struct {
	Iterations  int
	Alpha       float64
	Beta        float64
	MinShare    float64
	MaxShare    float64
	Smoothing   float64
	HotKeyLimit int
}

func DefaultOptimizerConfig() OptimizerConfig {
	return OptimizerConfig{
		Iterations:  20,
		Alpha:       4,
		Beta:        2,
		MinShare:    0.02,
		MaxShare:    0.90,
		Smoothing:   0.25,
		HotKeyLimit: 1024,
	}
}

type PathRuntime struct {
	PathID             string
	Edges              []string
	RTTMilliseconds    float64
	JitterMilliseconds float64
	LossPercent        float64
	BandwidthMbps      float64
	Stability          float64
	Congestion         float64
	ForwardingCost     float64
	MonthlyPressure    float64
	Healthy            bool
}

func (runtime PathRuntime) baseScore(class FlowClass) float64 {
	if !runtime.Healthy {
		return 0
	}
	latencyScore := 1 - normalizeRange(runtime.RTTMilliseconds, 10, 300)
	jitterScore := 1 - normalizeRange(runtime.JitterMilliseconds, 2, 60)
	bandwidthScore := 0.5
	if runtime.BandwidthMbps > 0 {
		bandwidthScore = normalizeRange(runtime.BandwidthMbps, 10, 500)
	}
	reliabilityScore := runtime.Stability *
		(1 - normalizeRange(runtime.LossPercent, 0, 15)) *
		(1 - normalizeRange(runtime.Congestion, 0, 1))
	costScore := 1 - normalizeRange(runtime.ForwardingCost, 0, 100)
	monthlyPenalty := 1 + 10*math.Max(0, math.Min(1, runtime.MonthlyPressure))*math.Max(0, math.Min(1, runtime.MonthlyPressure))

	var latencyWeight, throughputWeight, reliabilityWeight, costWeight float64
	switch class {
	case FlowThroughput:
		latencyWeight, throughputWeight, reliabilityWeight, costWeight = .15, .55, .2, .1
	case FlowCost:
		latencyWeight, throughputWeight, reliabilityWeight, costWeight = .2, .15, .15, .5
	case FlowReliability:
		latencyWeight, throughputWeight, reliabilityWeight, costWeight = .25, .2, .4, .15
	case FlowRealtime:
		latencyWeight, throughputWeight, reliabilityWeight, costWeight = .45, .1, .4, .05
	default:
		latencyWeight, throughputWeight, reliabilityWeight, costWeight = .5, .15, .25, .1
	}
	score := latencyWeight*(latencyScore*.7+jitterScore*.3) +
		throughputWeight*bandwidthScore +
		reliabilityWeight*reliabilityScore +
		costWeight*costScore
	return math.Max(0.000001, score/monthlyPenalty)
}

func normalizeRange(value, good, bad float64) float64 {
	if bad <= good {
		return 1
	}
	return math.Max(0, math.Min(1, (value-good)/(bad-good)))
}

type Demand struct {
	Key            RoutingDomainKey
	BytesPerSecond float64
	EligiblePaths  []int
}

type OptimizerInput struct {
	NetworkID       string
	SnapshotHeight  uint64
	Version         uint64
	ManagerID       string
	GeneratedAt     time.Time
	ExpiresAt       time.Time
	Paths           []PathRuntime
	Demands         []Demand
	EdgeCapacity    map[string]float64
	CandidateHash   []byte
	PreviousWeights map[RoutingDomainKey]map[string]float64
}

type OptimizerMetrics struct {
	Iterations     int
	Domains        int
	Allocations    int
	MaxUtilization float64
	Objective      float64
	WeightChangeL1 float64
	Duration       time.Duration
}

func Optimize(input OptimizerInput, config OptimizerConfig) (RoutingEpoch, OptimizerMetrics, error) {
	if config.Iterations <= 0 {
		return RoutingEpoch{}, OptimizerMetrics{}, errors.New("optimizer iterations must be positive")
	}
	if len(input.Paths) == 0 || len(input.Demands) == 0 {
		return RoutingEpoch{}, OptimizerMetrics{}, errors.New("optimizer requires paths and demand")
	}
	for _, demand := range input.Demands {
		if !ValidFlowClass(demand.Key.FlowClass) {
			return RoutingEpoch{}, OptimizerMetrics{}, fmt.Errorf("invalid flow class %q", demand.Key.FlowClass)
		}
		if len(demand.EligiblePaths) == 0 {
			return RoutingEpoch{}, OptimizerMetrics{}, fmt.Errorf("domain %s has no eligible paths", demand.Key)
		}
	}

	started := time.Now()
	edgeIndex := make(map[string]int, len(input.EdgeCapacity))
	pathEdges := make([][]int, len(input.Paths))
	for pathIndex, path := range input.Paths {
		pathEdges[pathIndex] = make([]int, len(path.Edges))
		for edgePosition, edge := range path.Edges {
			index, exists := edgeIndex[edge]
			if !exists {
				index = len(edgeIndex)
				edgeIndex[edge] = index
			}
			pathEdges[pathIndex][edgePosition] = index
		}
	}
	edgeCapacities := make([]float64, len(edgeIndex))
	for edge, capacity := range input.EdgeCapacity {
		if index, exists := edgeIndex[edge]; exists {
			edgeCapacities[index] = capacity
		}
	}
	classIndexes := make(map[FlowClass]int, len(AllFlowClasses))
	for index, class := range AllFlowClasses {
		classIndexes[class] = index
	}
	pathScores := make([][]float64, len(input.Paths))
	for pathIndex := range input.Paths {
		pathScores[pathIndex] = make([]float64, len(AllFlowClasses))
		for _, class := range AllFlowClasses {
			pathScores[pathIndex][classIndexes[class]] = input.Paths[pathIndex].baseScore(class)
		}
	}
	weights := make([][]float64, len(input.Demands))
	for domainIndex, demand := range input.Demands {
		weights[domainIndex] = make([]float64, len(demand.EligiblePaths))
		total := 0.0
		for pathPosition, pathIndex := range demand.EligiblePaths {
			if pathIndex < 0 || pathIndex >= len(input.Paths) {
				return RoutingEpoch{}, OptimizerMetrics{}, fmt.Errorf("invalid path index %d", pathIndex)
			}
			score := pathScores[pathIndex][classIndexes[demand.Key.FlowClass]]
			weights[domainIndex][pathPosition] = score
			total += score
		}
		if total <= 0 {
			return RoutingEpoch{}, OptimizerMetrics{}, fmt.Errorf("domain %s has no positive path score", demand.Key)
		}
		for pathPosition := range weights[domainIndex] {
			weights[domainIndex][pathPosition] /= total
		}
	}

	edgeLoad := make([]float64, len(edgeIndex))
	edgeCost := make([]float64, len(edgeIndex))
	nextWeights := make([]float64, 8)
	for iteration := 0; iteration < config.Iterations; iteration++ {
		for edge := range edgeLoad {
			edgeLoad[edge] = 0
		}
		for domainIndex, demand := range input.Demands {
			for pathPosition, pathIndex := range demand.EligiblePaths {
				share := demand.BytesPerSecond * weights[domainIndex][pathPosition]
				for _, edge := range pathEdges[pathIndex] {
					edgeLoad[edge] += share
				}
			}
		}
		for edge, load := range edgeLoad {
			capacity := edgeCapacities[edge]
			if capacity <= 0 {
				edgeCost[edge] = math.Inf(1)
				continue
			}
			utilization := load / capacity
			edgeCost[edge] = 1 + config.Alpha*math.Pow(utilization, config.Beta)
		}
		for domainIndex, demand := range input.Demands {
			if cap(nextWeights) < len(demand.EligiblePaths) {
				nextWeights = make([]float64, len(demand.EligiblePaths))
			}
			next := nextWeights[:len(demand.EligiblePaths)]
			total := 0.0
			for pathPosition, pathIndex := range demand.EligiblePaths {
				cost := 1.0
				for _, edge := range pathEdges[pathIndex] {
					cost *= edgeCost[edge]
				}
				if math.IsInf(cost, 1) || cost <= 0 {
					next[pathPosition] = 0
					continue
				}
				next[pathPosition] = pathScores[pathIndex][classIndexes[demand.Key.FlowClass]] / cost
				total += next[pathPosition]
			}
			if total <= 0 {
				return RoutingEpoch{}, OptimizerMetrics{}, fmt.Errorf("domain %s became unroutable", demand.Key)
			}
			for pathPosition := range next {
				next[pathPosition] /= total
				smoothed := (1-config.Smoothing)*weights[domainIndex][pathPosition] + config.Smoothing*next[pathPosition]
				weights[domainIndex][pathPosition] = smoothed
			}
			normalizeWeights(weights[domainIndex])
			clampWeights(weights[domainIndex], config.MinShare, config.MaxShare)
		}
	}

	epoch := RoutingEpoch{
		NetworkID:        input.NetworkID,
		SnapshotHeight:   input.SnapshotHeight,
		CandidateSetHash: append([]byte(nil), input.CandidateHash...),
		Version:          input.Version,
		GeneratedAt:      input.GeneratedAt,
		ExpiresAt:        input.ExpiresAt,
		Allocations:      make([]PathAllocation, len(input.Demands)),
		ManagerID:        input.ManagerID,
	}
	maxUtilization := 0.0
	objective := 0.0
	weightChange := 0.0
	for domainIndex, demand := range input.Demands {
		if demand.BytesPerSecond > 0 {
			maxShares := make([]float64, len(demand.EligiblePaths))
			for pathPosition, pathIndex := range demand.EligiblePaths {
				maxShare := 1.0
				for _, edge := range pathEdges[pathIndex] {
					if capacity := edgeCapacities[edge]; capacity > 0 {
						maxShare = math.Min(maxShare, capacity/demand.BytesPerSecond)
					}
				}
				maxShares[pathPosition] = maxShare
			}
			capWeights(weights[domainIndex], maxShares)
		} else {
			normalizeWeights(weights[domainIndex])
		}
	}
	for domainIndex, demand := range input.Demands {
		allocation := PathAllocation{Key: demand.Key, Paths: make([]PathWeight, len(demand.EligiblePaths))}
		for pathPosition, pathIndex := range demand.EligiblePaths {
			path := input.Paths[pathIndex]
			weight := weights[domainIndex][pathPosition]
			reason := "global-load"
			if path.MonthlyPressure >= .8 {
				reason = "monthly-capacity-pressure"
			}
			allocation.Paths[pathPosition] = PathWeight{PathID: path.PathID, Weight: weight, Reason: reason}
			previous := input.PreviousWeights[demand.Key][path.PathID]
			weightChange += math.Abs(weight - previous)
			for _, edge := range pathEdges[pathIndex] {
				capacity := edgeCapacities[edge]
				if capacity > 0 {
					utilization := demand.BytesPerSecond * weight / capacity
					maxUtilization = math.Max(maxUtilization, utilization)
					objective += utilization * utilization
				}
			}
		}
		epoch.Allocations[domainIndex] = allocation
	}
	epoch.PlannerDigest = PlannerDigest(epoch)
	metrics := OptimizerMetrics{
		Iterations:     config.Iterations,
		Domains:        len(input.Demands),
		Allocations:    len(epoch.Allocations),
		MaxUtilization: maxUtilization,
		Objective:      objective,
		WeightChangeL1: weightChange,
		Duration:       time.Since(started),
	}
	return epoch, metrics, nil
}

func normalizeWeights(values []float64) {
	total := 0.0
	for _, value := range values {
		total += value
	}
	if total <= 0 {
		return
	}
	for index := range values {
		values[index] /= total
	}
}

func clampWeights(values []float64, minimum, maximum float64) {
	if len(values) == 0 {
		return
	}
	if len(values) == 1 {
		values[0] = 1
		return
	}
	for index := range values {
		values[index] = math.Max(minimum, math.Min(maximum, values[index]))
	}
	normalizeWeights(values)
}

func capWeights(values []float64, maximums []float64) {
	if len(values) == 0 || len(values) != len(maximums) {
		return
	}
	capped := make([]bool, len(values))
	cappedTotal := 0.0
	uncappedTotal := 0.0
	for index, maximum := range maximums {
		if maximum < 0 {
			maximum = 0
		}
		if values[index] > maximum {
			values[index] = maximum
			capped[index] = true
		}
		if capped[index] {
			cappedTotal += values[index]
		} else {
			uncappedTotal += values[index]
		}
	}
	remaining := 1 - cappedTotal
	if remaining < 0 || uncappedTotal <= 0 {
		normalizeWeights(values)
		return
	}
	for index := range values {
		if !capped[index] {
			values[index] *= remaining / uncappedTotal
		}
	}
}

func AggregateDemand(samples []FlowDemandSample) []Demand {
	index := make(map[RoutingDomainKey]int)
	result := make([]Demand, 0, len(samples))
	for _, sample := range samples {
		key := RoutingDomainKey{
			SourceManagerID:  "aggregated",
			SourceGroupID:    sample.SourceGroupID,
			DestinationScope: sample.DestinationScope,
			FlowClass:        sample.FlowClass,
		}
		position, exists := index[key]
		if !exists {
			position = len(result)
			index[key] = position
			result = append(result, Demand{Key: key})
		}
		if sample.DurationMS > 0 {
			result[position].BytesPerSecond += float64(sample.Bytes) / (float64(sample.DurationMS) / 1000)
		}
	}
	sort.Slice(result, func(i, j int) bool { return result[i].Key.String() < result[j].Key.String() })
	return result
}
