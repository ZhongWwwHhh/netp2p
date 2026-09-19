package packet

import (
	"encoding/binary"
	"fmt"
	"net"
)

type IPv4Packet []byte

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
