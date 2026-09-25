package presence

import (
	"github.com/netp2p/netp2p/internal/wire/pb"
)

// The protobuf conversions live here rather than in internal/wire to avoid an
// import cycle: link and presence depend on bft, and bft depends on wire for
// hashing.

func observationToProto(observation Observation) *pb.PresenceObservation {
	return &pb.PresenceObservation{
		PeerId:     observation.PeerID,
		Online:     observation.Online,
		LastSeen:   formatTime(observation.LastSeen),
		RemoteAddr: observation.RemoteAddr,
		Observer:   observation.Observer,
		UpdatedAt:  formatTime(observation.UpdatedAt),
	}
}

func observationFromProto(message *pb.PresenceObservation) Observation {
	if message == nil {
		return Observation{}
	}
	return Observation{
		PeerID:     message.GetPeerId(),
		Online:     message.GetOnline(),
		LastSeen:   parseTime(message.GetLastSeen()),
		RemoteAddr: message.GetRemoteAddr(),
		Observer:   message.GetObserver(),
		UpdatedAt:  parseTime(message.GetUpdatedAt()),
	}
}
