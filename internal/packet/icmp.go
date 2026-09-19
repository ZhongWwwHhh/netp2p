package packet

import (
	"encoding/binary"
	"fmt"
	"net"
)

const ProtocolICMP = 1

type ICMPType uint8

const (
	ICMPTypeEchoRequest ICMPType = 8
	ICMPTypeEchoReply   ICMPType = 0
)

type ICMPMessage []byte

func (message ICMPMessage) Validate() error {
	if len(message) < 8 {
		return fmt.Errorf("ICMP message shorter than 8 bytes")
	}
	return nil
}

func (message ICMPMessage) Type() ICMPType     { return ICMPType(message[0]) }
func (message ICMPMessage) Code() uint8        { return message[1] }
func (message ICMPMessage) Identifier() uint16 { return binary.BigEndian.Uint16(message[4:6]) }
func (message ICMPMessage) Sequence() uint16   { return binary.BigEndian.Uint16(message[6:8]) }

func checksum(data []byte) uint16 {
	var sum uint32
	for index := 0; index < len(data); index += 2 {
		if index+1 == len(data) {
			sum += uint32(data[index])
		} else {
			sum += uint32(binary.BigEndian.Uint16(data[index : index+2]))
		}
	}
	for sum>>16 != 0 {
		sum = (sum >> 16) + (sum & 0xffff)
	}
	return ^uint16(sum)
}

func ParseEchoRequest(data []byte) (IPv4Packet, ICMPMessage, error) {
	ipPacket := IPv4Packet(data)
	if err := ipPacket.Validate(); err != nil {
		return nil, nil, err
	}
	if ipPacket.Protocol() != ProtocolICMP {
		return nil, nil, fmt.Errorf("not an ICMP packet")
	}
	icmp := ICMPMessage(ipPacket[ipPacket.HeaderLength():])
	if err := icmp.Validate(); err != nil {
		return nil, nil, err
	}
	if icmp.Type() != ICMPTypeEchoRequest {
		return nil, nil, fmt.Errorf("not an ICMP echo request")
	}
	return ipPacket, icmp, nil
}

func BuildEchoRequest(source, destination net.IP, identifier, sequence uint16, payload []byte) ([]byte, error) {
	if len(payload) > 1400 {
		return nil, fmt.Errorf("probe payload too large")
	}
	icmp := make([]byte, 8+len(payload))
	icmp[0] = byte(ICMPTypeEchoRequest)
	binary.BigEndian.PutUint16(icmp[4:6], identifier)
	binary.BigEndian.PutUint16(icmp[6:8], sequence)
	copy(icmp[8:], payload)
	binary.BigEndian.PutUint16(icmp[2:4], checksum(icmp))
	return buildIPv4(source, destination, ProtocolICMP, icmp), nil
}

func BuildEchoReply(request IPv4Packet, icmp ICMPMessage) ([]byte, error) {
	replyICMP := make([]byte, len(icmp))
	copy(replyICMP, icmp)
	replyICMP[0] = byte(ICMPTypeEchoReply)
	replyICMP[2], replyICMP[3] = 0, 0
	binary.BigEndian.PutUint16(replyICMP[2:4], checksum(replyICMP))
	return buildIPv4(request.Destination(), request.Source(), ProtocolICMP, replyICMP), nil
}

func buildIPv4(source, destination net.IP, protocol uint8, payload []byte) []byte {
	packet := make([]byte, 20+len(payload))
	packet[0] = 0x45
	binary.BigEndian.PutUint16(packet[2:4], uint16(len(packet)))
	packet[8] = 64
	packet[9] = protocol
	copy(packet[12:16], source.To4())
	copy(packet[16:20], destination.To4())
	copy(packet[20:], payload)
	return packet
}
