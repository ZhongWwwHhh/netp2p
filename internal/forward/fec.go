package forward

import (
	"errors"
	"fmt"

	"github.com/netp2p/netp2p/internal/path"
)

const (
	FECParityXOR      = "xor-v1"
	maxFECGroupSize   = 255
	maxFECPayloadSize = MaxFrameSize
)

var (
	ErrInvalidFECGroup  = errors.New("invalid FEC group")
	ErrFECUnrecoverable = errors.New("FEC group is unrecoverable")
)

type FECPolicy struct {
	Enabled       bool
	GroupSize     int
	MaxRedundancy int
	Codec         string
}

// AdaptiveFECPolicy keeps redundancy bounded. Realtime uses FEC when measured
// loss or jitter makes tail latency vulnerable; reliability uses it only when
// explicitly enabled by policy. TCP-like traffic is never sprayed.
func AdaptiveFECPolicy(class path.FlowClass, lossPercent, jitterMilliseconds float64, reliabilityEnabled bool) FECPolicy {
	policy := FECPolicy{GroupSize: 4, MaxRedundancy: 1, Codec: FECParityXOR}
	switch class {
	case path.FlowRealtime:
		policy.Enabled = lossPercent > 0 || jitterMilliseconds > 0
	case path.FlowReliability:
		policy.Enabled = reliabilityEnabled && lossPercent >= 2
	default:
		policy.Enabled = false
	}
	if policy.Enabled && (lossPercent >= 5 || jitterMilliseconds >= 30) {
		policy.GroupSize = 2
	}
	return policy
}

func (policy FECPolicy) RedundancyForLoss(lossPercent float64) int {
	if !policy.Enabled || policy.MaxRedundancy <= 0 || lossPercent <= 0 {
		return 0
	}
	if lossPercent >= 1 || policy.GroupSize <= 2 {
		return 1
	}
	return 0
}

type FECFrame struct {
	GroupID         uint64
	GroupSize       int
	Index           int
	RedundancyCount int
	Codec           string
	Payload         []byte
}

func BuildFECGroup(groupID uint64, payloads [][]byte, policy FECPolicy, lossPercent float64) ([]FECFrame, error) {
	if len(payloads) == 0 || len(payloads) > maxFECGroupSize {
		return nil, ErrInvalidFECGroup
	}
	if policy.GroupSize <= 0 || policy.GroupSize > maxFECGroupSize {
		return nil, ErrInvalidFECGroup
	}
	if policy.Codec == "" {
		policy.Codec = FECParityXOR
	}
	if policy.Codec != FECParityXOR {
		return nil, fmt.Errorf("unsupported FEC codec %q", policy.Codec)
	}
	redundancy := policy.RedundancyForLoss(lossPercent)
	if redundancy > policy.MaxRedundancy || redundancy < 0 {
		return nil, ErrInvalidFECGroup
	}

	frames := make([]FECFrame, 0, len(payloads)+redundancy)
	for index, payload := range payloads {
		if len(payload) == 0 || len(payload) > maxFECPayloadSize {
			return nil, ErrInvalidFECGroup
		}
		frames = append(frames, FECFrame{
			GroupID: groupID, GroupSize: len(payloads), Index: index,
			RedundancyCount: redundancy, Codec: policy.Codec, Payload: append([]byte(nil), payload...),
		})
	}
	if redundancy == 0 {
		return frames, nil
	}
	parity := make([]byte, len(payloads[0]))
	copy(parity, payloads[0])
	for _, payload := range payloads[1:] {
		if len(payload) != len(parity) {
			return nil, ErrInvalidFECGroup
		}
		for index := range parity {
			parity[index] ^= payload[index]
		}
	}
	frames = append(frames, FECFrame{
		GroupID: groupID, GroupSize: len(payloads), Index: len(payloads),
		RedundancyCount: redundancy, Codec: policy.Codec, Payload: parity,
	})
	return frames, nil
}

func RecoverFECGroup(frames []FECFrame) ([][]byte, int, error) {
	if len(frames) == 0 {
		return nil, 0, ErrInvalidFECGroup
	}
	groupID := frames[0].GroupID
	groupSize := frames[0].GroupSize
	codec := frames[0].Codec
	if groupSize <= 0 || groupSize > maxFECGroupSize || codec != FECParityXOR {
		return nil, 0, ErrInvalidFECGroup
	}
	payloads := make([][]byte, groupSize)
	present := make([]bool, groupSize)
	var parity []byte
	parityPresent := false
	for _, frame := range frames {
		if frame.GroupID != groupID || frame.GroupSize != groupSize || frame.Codec != codec ||
			frame.Index < 0 || frame.Index > groupSize || len(frame.Payload) == 0 || len(frame.Payload) > maxFECPayloadSize {
			return nil, 0, ErrInvalidFECGroup
		}
		if frame.Index == groupSize {
			if parityPresent {
				return nil, 0, ErrInvalidFECGroup
			}
			parityPresent = true
			parity = frame.Payload
			continue
		}
		if present[frame.Index] {
			return nil, 0, ErrInvalidFECGroup
		}
		present[frame.Index] = true
		payloads[frame.Index] = append([]byte(nil), frame.Payload...)
	}

	missing := make([]int, 0)
	for index, exists := range present {
		if !exists {
			missing = append(missing, index)
		}
	}
	if len(missing) == 0 {
		return payloads, 0, nil
	}
	payloadLength := -1
	for index, exists := range present {
		if exists {
			payloadLength = len(payloads[index])
			break
		}
	}
	if len(missing) > 1 || !parityPresent || payloadLength < 0 || len(parity) != payloadLength {
		return nil, 0, ErrFECUnrecoverable
	}
	recovered := append([]byte(nil), parity...)
	for index, exists := range present {
		if !exists {
			continue
		}
		for offset := range recovered {
			recovered[offset] ^= payloads[index][offset]
		}
	}
	payloads[missing[0]] = recovered
	return payloads, 1, nil
}
