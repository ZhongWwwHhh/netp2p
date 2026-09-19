package packet

import (
	"encoding/binary"
	"fmt"
	"net"
)

type IPv4Packet []byte

const (
	ProtocolTCP = 6
	ProtocolUDP = 17
)

func (packet IPv4Packet) Validate() error {
	if len(packet) < 20 {
		return fmt.Errorf("packet shorter than IPv4 header")
	}
	if packet.Version() != 4 {
		return fmt.Errorf("unsupported IP version %d", packet.Version())
	}
	if len(packet) < packet.HeaderLength() {
		return fmt.Errorf("IPv4 header exceeds packet length")
	}
	if len(packet) != int(packet.TotalLength()) {
		return fmt.Errorf("IPv4 total length mismatch")
	}
	return nil
}

func (packet IPv4Packet) Version() uint8      { return packet[0] >> 4 }
func (packet IPv4Packet) HeaderLength() int   { return int(packet[0]&0x0f) * 4 }
func (packet IPv4Packet) TotalLength() uint16 { return binary.BigEndian.Uint16(packet[2:4]) }
func (packet IPv4Packet) Protocol() uint8     { return packet[9] }
func (packet IPv4Packet) Source() net.IP      { return net.IP(append([]byte(nil), packet[12:16]...)) }
func (packet IPv4Packet) Destination() net.IP { return net.IP(append([]byte(nil), packet[16:20]...)) }

// FlagsAndFragmentOffset returns the 16-bit flags/fragment-offset field.
func (packet IPv4Packet) FlagsAndFragmentOffset() uint16 { return binary.BigEndian.Uint16(packet[6:8]) }

// FragmentOffset returns the fragment offset in 8-byte units. A non-zero
// offset means this is a later fragment and carries no transport header.
func (packet IPv4Packet) FragmentOffset() uint16 { return packet.FlagsAndFragmentOffset() & 0x1fff }

// TransportPorts returns the source and destination ports for TCP and UDP
// packets. It reports false for other protocols, for later fragments, and for
// truncated packets, in which case callers must treat the port as unknown.
func (packet IPv4Packet) TransportPorts() (uint16, uint16, bool) {
	switch packet.Protocol() {
	case ProtocolTCP, ProtocolUDP:
	default:
		return 0, 0, false
	}
	if packet.FragmentOffset() != 0 {
		return 0, 0, false
	}
	headerLength := packet.HeaderLength()
	if len(packet) < headerLength+4 {
		return 0, 0, false
	}
	return binary.BigEndian.Uint16(packet[headerLength : headerLength+2]),
		binary.BigEndian.Uint16(packet[headerLength+2 : headerLength+4]), true
}
