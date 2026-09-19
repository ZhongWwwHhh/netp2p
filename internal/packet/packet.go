// Package packet provides a userspace replacement for a Linux TUN endpoint.
package packet

import (
	"encoding/binary"
	"fmt"
	"net"
	"sync"
)

const MaxPacketSize = 65535

type PacketSink interface {
	ReadPacket() ([]byte, error)
	WritePacket(packet []byte) error
	Close() error
}

// UserspaceICMP is implemented by sinks with no kernel IP stack behind them.
// Such sinks must have ICMP echo replies synthesized in userspace, because
// nothing else will answer them.
type UserspaceICMP interface {
	SynthesizeICMP() bool
}

// RouteReconciler is implemented by sinks backed by a kernel routing table.
// They must be told which overlay addresses are currently reachable so the
// operating system sends those destinations into the overlay.
type RouteReconciler interface {
	ReconcileRoutes(overlayIPs []string) error
}

type UDPPacketSink struct {
	connection *net.UDPConn
	mu         sync.Mutex
	lastPeer   *net.UDPAddr
}

// NewUDPPacketSink listens on listen for length-prefixed IPv4 packets. Replies
// are sent back to the most recent sender, which keeps the userspace endpoint
// usable by clients that bind an ephemeral source port.
func NewUDPPacketSink(listen string) (*UDPPacketSink, error) {
	localAddress, err := net.ResolveUDPAddr("udp", listen)
	if err != nil {
		return nil, fmt.Errorf("resolve packet listen: %w", err)
	}
	connection, err := net.ListenUDP("udp", localAddress)
	if err != nil {
		return nil, err
	}
	return &UDPPacketSink{connection: connection}, nil
}

func (sink *UDPPacketSink) ReadPacket() ([]byte, error) {
	buffer := make([]byte, 2+MaxPacketSize)
	read, sender, err := sink.connection.ReadFromUDP(buffer)
	if err != nil {
		return nil, err
	}
	if read < 2 {
		return nil, fmt.Errorf("short packet header")
	}
	length := int(binary.BigEndian.Uint16(buffer))
	if length == 0 || length > MaxPacketSize || 2+length > read {
		return nil, fmt.Errorf("invalid packet length %d", length)
	}
	packet := make([]byte, length)
	copy(packet, buffer[2:2+length])
	sink.mu.Lock()
	sink.lastPeer = sender
	sink.mu.Unlock()
	return packet, nil
}

func (sink *UDPPacketSink) WritePacket(packet []byte) error {
	if len(packet) == 0 || len(packet) > MaxPacketSize {
		return fmt.Errorf("invalid packet size %d", len(packet))
	}
	buffer := make([]byte, 2+len(packet))
	binary.BigEndian.PutUint16(buffer, uint16(len(packet)))
	copy(buffer[2:], packet)
	sink.mu.Lock()
	peer := sink.lastPeer
	sink.mu.Unlock()
	if peer == nil {
		return fmt.Errorf("no packet endpoint peer known yet")
	}
	_, err := sink.connection.WriteToUDP(buffer, peer)
	return err
}

func (sink *UDPPacketSink) LocalAddr() net.Addr {
	return sink.connection.LocalAddr()
}

func (sink *UDPPacketSink) Close() error {
	return sink.connection.Close()
}

// SynthesizeICMP reports that this endpoint has no kernel IP stack, so ICMP
// echo requests must be answered by the client itself.
func (sink *UDPPacketSink) SynthesizeICMP() bool { return true }

// EncodeFrame wraps an IP packet in the length-prefixed local framing.
func EncodeFrame(packet []byte) ([]byte, error) {
	if len(packet) == 0 || len(packet) > MaxPacketSize {
		return nil, fmt.Errorf("invalid packet size %d", len(packet))
	}
	buffer := make([]byte, 2+len(packet))
	binary.BigEndian.PutUint16(buffer, uint16(len(packet)))
	copy(buffer[2:], packet)
	return buffer, nil
}

// DecodeFrame unwraps the length-prefixed local framing.
func DecodeFrame(buffer []byte) ([]byte, error) {
	if len(buffer) < 2 {
		return nil, fmt.Errorf("short packet header")
	}
	length := int(binary.BigEndian.Uint16(buffer))
	if length == 0 || length > MaxPacketSize || 2+length > len(buffer) {
		return nil, fmt.Errorf("invalid packet length %d", length)
	}
	packet := make([]byte, length)
	copy(packet, buffer[2:2+length])
	return packet, nil
}
