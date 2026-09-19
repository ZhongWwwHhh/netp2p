package packet

import (
	"encoding/binary"
	"net/netip"
)

// Flow describes one direction of a packet's transport flow. Ports are zero
// when the protocol has none.
type Flow struct {
	Protocol        uint8
	Source          netip.Addr
	Destination     netip.Addr
	SourcePort      uint16
	DestinationPort uint16
}

// Flow extracts the flow identity of an IPv4 packet. ICMP uses the echo
// identifier in place of a source port so replies map back to the request.
func (packet IPv4Packet) Flow() (Flow, bool) {
	source, ok := addressOf(packet.Source())
	if !ok {
		return Flow{}, false
	}
	destination, ok := addressOf(packet.Destination())
	if !ok {
		return Flow{}, false
	}
	flow := Flow{Protocol: packet.Protocol(), Source: source, Destination: destination}
	if packet.Protocol() == ProtocolICMP && packet.FragmentOffset() == 0 {
		headerLength := packet.HeaderLength()
		if len(packet) >= headerLength+8 {
			// A request and its reply carry the echo identifier in the same
			// position, so record it on both sides. Reverse() then maps the
			// reply onto the request instead of swapping it away.
			identifier := binary.BigEndian.Uint16(packet[headerLength+4 : headerLength+6])
			flow.SourcePort = identifier
			flow.DestinationPort = identifier
		}
		return flow, true
	}
	if sourcePort, destinationPort, ok := packet.TransportPorts(); ok {
		flow.SourcePort = sourcePort
		flow.DestinationPort = destinationPort
	}
	return flow, true
}

func addressOf(value interface{ String() string }) (netip.Addr, bool) {
	address, err := netip.ParseAddr(value.String())
	if err != nil {
		return netip.Addr{}, false
	}
	return address.Unmap(), true
}
