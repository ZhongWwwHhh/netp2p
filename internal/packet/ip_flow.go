package packet

import (
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"net/netip"
)

// IPFlow is the manager-side, version-independent view of an overlay packet.
// It carries only the fields needed for admission and routing decisions.
type IPFlow struct {
	Version         int
	Protocol        uint8
	Source          netip.Addr
	Destination     netip.Addr
	SourcePort      uint16
	DestinationPort uint16
}

func (flow IPFlow) ProtocolName() string {
	switch flow.Protocol {
	case 1:
		return "icmp"
	case 6:
		return "tcp"
	case 17:
		return "udp"
	case 58:
		return "icmpv6"
	default:
		return "ip"
	}
}

func ParseIPFlow(raw []byte) (IPFlow, bool) {
	if len(raw) < 1 {
		return IPFlow{}, false
	}
	switch raw[0] >> 4 {
	case 4:
		return parseIPv4Flow(raw)
	case 6:
		return parseIPv6Flow(raw)
	default:
		return IPFlow{}, false
	}
}

func parseIPv4Flow(raw []byte) (IPFlow, bool) {
	ipPacket := IPv4Packet(raw)
	if err := ipPacket.Validate(); err != nil {
		return IPFlow{}, false
	}
	source, ok := netip.AddrFromSlice(ipPacket.Source())
	if !ok {
		return IPFlow{}, false
	}
	destination, ok := netip.AddrFromSlice(ipPacket.Destination())
	if !ok {
		return IPFlow{}, false
	}
	flow := IPFlow{
		Version: 4, Protocol: ipPacket.Protocol(),
		Source: source.Unmap(), Destination: destination.Unmap(),
	}
	if sourcePort, destinationPort, ok := ipPacket.TransportPorts(); ok {
		flow.SourcePort = sourcePort
		flow.DestinationPort = destinationPort
	}
	return flow, true
}

func parseIPv6Flow(raw []byte) (IPFlow, bool) {
	if len(raw) < 40 {
		return IPFlow{}, false
	}
	if raw[0]>>4 != 6 {
		return IPFlow{}, false
	}
	payloadLength := binary.BigEndian.Uint16(raw[4:6])
	if int(payloadLength) != len(raw)-40 {
		return IPFlow{}, false
	}
	source, ok := netip.AddrFromSlice(raw[8:24])
	if !ok {
		return IPFlow{}, false
	}
	destination, ok := netip.AddrFromSlice(raw[24:40])
	if !ok {
		return IPFlow{}, false
	}
	flow := IPFlow{
		Version: 6, Protocol: raw[6],
		Source: source.Unmap(), Destination: destination.Unmap(),
	}
	switch flow.Protocol {
	case ProtocolTCP, ProtocolUDP:
		if len(raw) >= 44 {
			flow.SourcePort = binary.BigEndian.Uint16(raw[40:42])
			flow.DestinationPort = binary.BigEndian.Uint16(raw[42:44])
		}
	}
	return flow, true
}

func FlowHash(raw []byte) (uint64, bool) {
	flow, ok := ParseIPFlow(raw)
	if !ok {
		return 0, false
	}
	digest := sha256.New()
	_, _ = digest.Write([]byte{byte(flow.Version), flow.Protocol})
	_, _ = digest.Write(flow.Source.AsSlice())
	_, _ = digest.Write(flow.Destination.AsSlice())
	if (flow.Protocol == ProtocolTCP || flow.Protocol == ProtocolUDP) && flow.DestinationPort != 0 {
		var ports [2]byte
		binary.BigEndian.PutUint16(ports[:], flow.SourcePort)
		_, _ = digest.Write(ports[:])
		binary.BigEndian.PutUint16(ports[:], flow.DestinationPort)
		_, _ = digest.Write(ports[:])
	}
	return binary.BigEndian.Uint64(digest.Sum(nil)), true
}

func ValidateIPPacket(raw []byte) error {
	if _, ok := ParseIPFlow(raw); !ok {
		return fmt.Errorf("invalid IPv4 or IPv6 overlay packet")
	}
	return nil
}
