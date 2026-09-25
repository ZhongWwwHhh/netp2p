package link

import (
	"time"

	"github.com/netp2p/netp2p/internal/wire/pb"
)

// The protobuf conversions live here rather than in internal/wire to avoid an
// import cycle: link depends on bft, and bft depends on wire for hashing.

func observationToProto(observation Observation) *pb.LinkObservation {
	return &pb.LinkObservation{
		ObserverId:         observation.ObserverID,
		SubjectId:          observation.SubjectID,
		Scope:              string(observation.Scope),
		Direction:          string(observation.Direction),
		RttMilliseconds:    observation.RTTMilliseconds,
		LossPercent:        observation.LossPercent,
		JitterMilliseconds: observation.JitterMilliseconds,
		BandwidthMbps:      observation.BandwidthMbps,
		Samples:            int32(observation.Samples),
		MeasuredAt:         formatTime(observation.MeasuredAt),
		Sequence:           observation.Sequence,
		Signature:          append([]byte(nil), observation.Signature...),
	}
}

func observationFromProto(message *pb.LinkObservation) Observation {
	if message == nil {
		return Observation{}
	}
	return Observation{
		ObserverID:         message.GetObserverId(),
		SubjectID:          message.GetSubjectId(),
		Scope:              Scope(message.GetScope()),
		Direction:          Direction(message.GetDirection()),
		RTTMilliseconds:    message.GetRttMilliseconds(),
		LossPercent:        message.GetLossPercent(),
		JitterMilliseconds: message.GetJitterMilliseconds(),
		BandwidthMbps:      message.GetBandwidthMbps(),
		Samples:            int(message.GetSamples()),
		MeasuredAt:         parseTime(message.GetMeasuredAt()),
		Sequence:           message.GetSequence(),
		Signature:          append([]byte(nil), message.GetSignature()...),
	}
}

func formatTime(value time.Time) string {
	if value.IsZero() {
		return ""
	}
	return value.UTC().Format(time.RFC3339Nano)
}

func parseTime(value string) time.Time {
	if value == "" {
		return time.Time{}
	}
	parsed, err := time.Parse(time.RFC3339Nano, value)
	if err != nil {
		return time.Time{}
	}
	return parsed.UTC()
}
