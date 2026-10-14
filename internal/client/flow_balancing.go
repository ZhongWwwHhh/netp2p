package client

import (
	"github.com/netp2p/netp2p/internal/conntrack"
	"github.com/netp2p/netp2p/internal/model"
)

const (
	realtimeMaxRTTMilliseconds = 150
	realtimeMaxLossPercent     = 2
)

// certifiedPathRendezvous gives each stable flow a deterministic path
// within the certified candidate set. The hash carries no routing policy
// and cannot promote an uncertified path.
func certifiedPathRendezvous(key conntrack.Key, candidates []model.PathSpec) (model.PathSpec, bool) {
	if len(candidates) == 0 {
		return model.PathSpec{}, false
	}
	bestIndex := 0
	bestScore := uint64(0)
	for index, candidate := range candidates {
		score := flowHash(key, candidate.ID)
		if score > bestScore || (score == bestScore && candidate.ID < candidates[bestIndex].ID) {
			bestIndex = index
			bestScore = score
		}
	}
	return candidates[bestIndex], true
}

func realtimeSLAViolated(path model.PathSpec) bool {
	return (path.RTTMilliseconds > 0 && path.RTTMilliseconds > realtimeMaxRTTMilliseconds) ||
		(path.LossPercent > 0 && path.LossPercent > realtimeMaxLossPercent)
}
