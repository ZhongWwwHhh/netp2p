package packet

import (
	"encoding/binary"
	"net"
	"testing"
)

func synthIPv4(protocol uint8, source, destination string, payload []byte) IPv4Packet {
	total := 20 + len(payload)
	packet := make([]byte, total)
	packet[0] = 0x45
	binary.BigEndian.PutUint16(packet[2:4], uint16(total))
	packet[8] = 64
	packet[9] = protocol
	copy(packet[12:16], net.ParseIP(source).To4())
	copy(packet[16:20], net.ParseIP(destination).To4())
	copy(packet[20:], payload)
	return IPv4Packet(packet)
}

func TestTransportPortsForTCP(t *testing.T) {
	payload := make([]byte, 20)
	binary.BigEndian.PutUint16(payload[0:2], 51000)
	binary.BigEndian.PutUint16(payload[2:4], 443)
	packet := synthIPv4(ProtocolTCP, "100.64.0.1", "100.64.0.2", payload)

	source, destination, ok := packet.TransportPorts()
	if !ok {
		t.Fatal("expected ports for a TCP packet")
	}
	if source != 51000 || destination != 443 {
		t.Fatalf("ports = %d -> %d, want 51000 -> 443", source, destination)
	}
}

func TestTransportPortsForUDP(t *testing.T) {
	payload := make([]byte, 8)
	binary.BigEndian.PutUint16(payload[0:2], 5353)
	binary.BigEndian.PutUint16(payload[2:4], 53)
	packet := synthIPv4(ProtocolUDP, "100.64.0.1", "100.64.0.2", payload)

	source, destination, ok := packet.TransportPorts()
	if !ok || source != 5353 || destination != 53 {
		t.Fatalf("ports = %d -> %d ok=%v, want 5353 -> 53", source, destination, ok)
	}
}

func TestTransportPortsRejectsNonTransportProtocols(t *testing.T) {
	packet := synthIPv4(ProtocolICMP, "100.64.0.1", "100.64.0.2", make([]byte, 8))
	if _, _, ok := packet.TransportPorts(); ok {
		t.Fatal("ICMP has no transport ports")
	}
}

func TestTransportPortsIgnoresLaterFragments(t *testing.T) {
	payload := make([]byte, 20)
	binary.BigEndian.PutUint16(payload[0:2], 51000)
	binary.BigEndian.PutUint16(payload[2:4], 443)
	packet := synthIPv4(ProtocolTCP, "100.64.0.1", "100.64.0.2", payload)
	// Non-zero fragment offset means no transport header is present.
	binary.BigEndian.PutUint16(packet[6:8], 185)
	if _, _, ok := packet.TransportPorts(); ok {
		t.Fatal("later fragments must not be parsed for ports")
	}
}

func TestTransportPortsRejectsTruncatedHeader(t *testing.T) {
	packet := synthIPv4(ProtocolTCP, "100.64.0.1", "100.64.0.2", nil)
	if _, _, ok := packet.TransportPorts(); ok {
		t.Fatal("packet without a transport header must not report ports")
	}
}

func TestFlowICMPUsesIdentifierOnBothSides(t *testing.T) {
	// Echo request and reply both put the identifier at the same offset, so
	// both sides of the flow carry it and Reverse() still lines up.
	payload := []byte{byte(ICMPTypeEchoRequest), 0, 0, 0, 0x12, 0x34, 0x00, 0x01}
	request := synthIPv4(ProtocolICMP, "100.64.0.1", "100.64.0.2", payload)
	flow, ok := request.Flow()
	if !ok {
		t.Fatal("expected a flow for an ICMP packet")
	}
	if flow.SourcePort != 0x1234 || flow.DestinationPort != 0x1234 {
		t.Fatalf("identifier = %#x/%#x, want 0x1234 on both sides", flow.SourcePort, flow.DestinationPort)
	}
	if flow.Source.String() != "100.64.0.1" || flow.Destination.String() != "100.64.0.2" {
		t.Fatalf("unexpected addresses %s -> %s", flow.Source, flow.Destination)
	}
}

func TestFlowForTCPIsDirectional(t *testing.T) {
	payload := make([]byte, 20)
	binary.BigEndian.PutUint16(payload[0:2], 51000)
	binary.BigEndian.PutUint16(payload[2:4], 443)
	packet := synthIPv4(ProtocolTCP, "100.64.0.1", "100.64.0.2", payload)

	flow, ok := packet.Flow()
	if !ok {
		t.Fatal("expected a flow for a TCP packet")
	}
	// A reply arrives with the ports swapped relative to the request.
	replyPayload := make([]byte, 20)
	binary.BigEndian.PutUint16(replyPayload[0:2], 443)
	binary.BigEndian.PutUint16(replyPayload[2:4], 51000)
	reply := synthIPv4(ProtocolTCP, "100.64.0.2", "100.64.0.1", replyPayload)
	replyFlow, _ := reply.Flow()
	if replyFlow.SourcePort != 443 || replyFlow.DestinationPort != 51000 {
		t.Fatalf("reply ports = %d -> %d, want 443 -> 51000", replyFlow.SourcePort, replyFlow.DestinationPort)
	}
	// Swapping the reply's endpoints and ports must reproduce the request.
	reverse := replyFlow
	reverse.Source, reverse.Destination = replyFlow.Destination, replyFlow.Source
	reverse.SourcePort, reverse.DestinationPort = replyFlow.DestinationPort, replyFlow.SourcePort
	if reverse != flow {
		t.Fatalf("reply reverse = %+v, want request %+v", reverse, flow)
	}
}
