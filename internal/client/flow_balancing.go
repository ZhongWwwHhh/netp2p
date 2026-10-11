package client

import (
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"time"

	"github.com/netp2p/netp2p/internal/conntrack"
	"github.com/netp2p/netp2p/internal/model"
	pathscore "github.com/netp2p/netp2p/internal/path"
)

const (
	realtimeMaxRTTMilliseconds = 150
	realtimeMaxLossPercent     = 2
	elephantMigrationBytes     = 64 << 20
)

var (
	ErrInvalidRoutingEpoch = errors.New("invalid routing epoch")
	ErrStaleRoutingEpoch   = errors.New("stale routing epoch")
)

// RoutingEpoch is the runtime allocation produced by the global optimizer.
// It never authorizes a path; every path ID must already exist in a certified
// assignment. Its only job is to spread flows over certified path families.
type RoutingEpoch struct {
	NetworkID   string                        `json:"networkId"`
	Sequence    uint64                        `json:"sequence"`
	GeneratedAt time.Time                     `json:"generatedAt"`
	Weights     map[string]map[string]float64 `json:"weights"`
}

type SignedRoutingEpoch struct {
	Payload   json.RawMessage `json:"payload"`
	Signature []byte          `json:"signature"`
}

func SignRoutingEpoch(epoch RoutingEpoch, signer ed25519.PrivateKey) (SignedRoutingEpoch, error) {
	if len(signer) != ed25519.PrivateKeySize {
		return SignedRoutingEpoch{}, fmt.Errorf("%w: signer must be Ed25519", ErrInvalidRoutingEpoch)
	}
	payload, err := json.Marshal(epoch)
	if err != nil {
		return SignedRoutingEpoch{}, fmt.Errorf("%w: encode: %w", ErrInvalidRoutingEpoch, err)
	}
	return SignedRoutingEpoch{Payload: payload, Signature: ed25519.Sign(signer, payload)}, nil
}

func VerifyRoutingEpoch(signed SignedRoutingEpoch, verifier ed25519.PublicKey) (RoutingEpoch, error) {
	if len(verifier) != ed25519.PublicKeySize {
		return RoutingEpoch{}, fmt.Errorf("%w: verifier must be Ed25519", ErrInvalidRoutingEpoch)
	}
	if len(signed.Signature) != ed25519.SignatureSize || len(signed.Payload) == 0 {
		return RoutingEpoch{}, fmt.Errorf("%w: malformed signature", ErrInvalidRoutingEpoch)
	}
	if !ed25519.Verify(verifier, signed.Payload, signed.Signature) {
		return RoutingEpoch{}, fmt.Errorf("%w: signature mismatch", ErrInvalidRoutingEpoch)
	}
	var epoch RoutingEpoch
	if err := json.Unmarshal(signed.Payload, &epoch); err != nil {
		return RoutingEpoch{}, fmt.Errorf("%w: decode: %w", ErrInvalidRoutingEpoch, err)
	}
	if epoch.NetworkID == "" || epoch.Sequence == 0 || !epoch.GeneratedAt.After(time.Time{}) {
		return RoutingEpoch{}, fmt.Errorf("%w: network, sequence, and timestamp are required", ErrInvalidRoutingEpoch)
	}
	for assignmentID, paths := range epoch.Weights {
		if assignmentID == "" || len(paths) == 0 {
			return RoutingEpoch{}, fmt.Errorf("%w: assignment %q has no weights", ErrInvalidRoutingEpoch, assignmentID)
		}
		for pathID, weight := range paths {
			if pathID == "" || math.IsInf(weight, 0) || math.IsNaN(weight) || weight <= 0 {
				return RoutingEpoch{}, fmt.Errorf("%w: assignment %q path %q has invalid weight", ErrInvalidRoutingEpoch, assignmentID, pathID)
			}
		}
	}
	return epoch, nil
}

type weightedPath struct {
	path   model.PathSpec
	weight float64
}

// weightedRendezvous implements weighted highest-random-weight hashing. It
// gives each stable flow a deterministic path while making selection
// probability proportional to the optimizer's allocation.
func weightedRendezvous(key conntrack.Key, candidates []weightedPath) (model.PathSpec, bool) {
	if len(candidates) == 0 {
		return model.PathSpec{}, false
	}
	best := candidates[0]
	bestScore := -math.MaxFloat64
	for _, candidate := range candidates {
		unit := (float64(flowHash(key, candidate.path.ID)) + 0.5) / float64(math.MaxUint64)
		score := -math.Log(unit) / candidate.weight
		if score > bestScore || (score == bestScore && candidate.path.ID < best.path.ID) {
			best = candidate
			bestScore = score
		}
	}
	return best.path, true
}

func realtimeSLAViolated(path model.PathSpec) bool {
	return (path.RTTMilliseconds > 0 && path.RTTMilliseconds > realtimeMaxRTTMilliseconds) ||
		(path.LossPercent > 0 && path.LossPercent > realtimeMaxLossPercent)
}

func pathProfile(spec model.PathSpec) pathscore.LinkProfile {
	var pathType pathscore.PathType
	switch spec.Kind {
	case model.PathKindViaManager:
		pathType = pathscore.PathViaManager
	case model.PathKindMultiHop:
		pathType = pathscore.PathMultiHop
	default:
		pathType = pathscore.PathDirect
	}
	return pathscore.LinkProfile{
		PathID: spec.ID, Type: pathType,
		RTTMilliseconds: spec.RTTMilliseconds, LossPercent: spec.LossPercent,
		BandwidthMbps: spec.BandwidthMbps, Stability: spec.Confidence,
		Congestion: spec.LossPercent / 100, ForwardingCost: float64(spec.Cost),
	}
}

func scoringClass(class FlowClass) pathscore.FlowClass {
	if class == FlowClassRealtime {
		return pathscore.FlowLatency
	}
	return pathscore.FlowClass(class)
}

func derivedPathWeight(spec model.PathSpec, class FlowClass, settings model.NetworkSettings) float64 {
	constraints := pathscore.Constraints{
		FlowClass:                    scoringClass(class),
		MinBandwidthMbps:             settings.LinkMinBandwidthMbps,
		ViaManagerLatencyAdvantageMs: settings.ViaManagerLatencyAdvantageMs,
		ViaManagerLossAdvantagePct:   settings.ViaManagerLossAdvantagePct,
	}
	if class == FlowClassRealtime {
		constraints.MaxRTTMilliseconds = realtimeMaxRTTMilliseconds
		constraints.MaxLossPercent = realtimeMaxLossPercent
	}
	score := pathscore.Score(pathProfile(spec), constraints)
	if score <= 0 {
		return 0.01
	}
	return (score / 100) * (score / 100)
}
