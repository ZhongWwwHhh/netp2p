package client

import (
	"fmt"

	"github.com/netp2p/netp2p/internal/model"
	"github.com/netp2p/netp2p/internal/packet"
)

func (client *Client) peerByPeerID(peerID string) (model.PeerRecord, error) {
	client.mu.RLock()
	defer client.mu.RUnlock()
	for _, candidate := range client.snapshot.State.Peers {
		if candidate.PeerID == peerID {
			return candidate, nil
		}
	}
	return model.PeerRecord{}, fmt.Errorf("unknown peer %s", peerID)
}

func describePacket(ipPacket packet.IPv4Packet) (string, uint16) {
	if ipPacket.Protocol() == packet.ProtocolICMP {
		return "icmp", 0
	}
	return fmt.Sprintf("ip-%d", ipPacket.Protocol()), 0
}

func isEchoReply(request packet.IPv4Packet) bool {
	if request.Protocol() != packet.ProtocolICMP || len(request) <= request.HeaderLength() {
		return false
	}
	icmp := packet.ICMPMessage(request[request.HeaderLength():])
	return icmp.Type() == packet.ICMPTypeEchoReply
}

func buildEchoReply(request packet.IPv4Packet) ([]byte, bool) {
	if request.Protocol() != packet.ProtocolICMP || len(request) <= request.HeaderLength() {
		return nil, false
	}
	icmp := packet.ICMPMessage(request[request.HeaderLength():])
	if icmp.Type() != packet.ICMPTypeEchoRequest {
		return nil, false
	}
	reply, err := packet.BuildEchoReply(request, icmp)
	if err != nil {
		return nil, false
	}
	return reply, true
}
