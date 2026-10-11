package client

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"time"

	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/netp2p/netp2p/internal/model"
	"github.com/netp2p/netp2p/internal/packet"
)

// ErrPingUnsupported is returned before a request is put on the wire when the
// daemon has not yet certified the local overlay identity.
var ErrPingUnsupported = errors.New("overlay ping requires a ready client identity")

// Ping sends one ICMP echo through the same active path selector and transport
// as ordinary traffic. It works for both kernel TUN and userspace clients
// because the daemon owns that data path; the CLI only renders the result.
func (client *Client) Ping(ctx context.Context, target net.IP, timeout time.Duration) (time.Duration, error) {
	if target == nil || target.To4() == nil {
		return 0, fmt.Errorf("%w: invalid target", ErrPingUnsupported)
	}
	destination, err := client.peerByIP(target)
	if err != nil {
		return 0, err
	}
	sourceIP := net.ParseIP(client.selfOverlayIP())
	targetIP := net.ParseIP(destination.OverlayIP)
	if sourceIP == nil || targetIP == nil {
		return 0, fmt.Errorf("%w: overlay address is unavailable", ErrPingUnsupported)
	}
	allowed, err := client.authorize(destination, "icmp", 0)
	if err != nil {
		return 0, fmt.Errorf("authorize ping: %w", err)
	}
	if !allowed {
		return 0, errors.New("policy denies icmp")
	}
	identifier, err := pingIdentifier()
	if err != nil {
		return 0, err
	}
	request, err := packet.BuildEchoRequest(sourceIP, targetIP, identifier, 1, []byte("netp2p-ping"))
	if err != nil {
		return 0, err
	}
	started := time.Now()
	replies := make(chan packet.IPv4Packet, 1)
	if !client.setDiagnosticWaiter(identifier, targetIP.String(), replies) {
		return 0, fmt.Errorf("diagnostic ping identifier collision")
	}
	defer client.clearDiagnosticWaiter(identifier)

	sourceID, err := peer.Decode(client.selfPeerID())
	if err != nil {
		return 0, fmt.Errorf("decode local peer: %w", err)
	}
	if !client.admitOutbound(len(request)) {
		return 0, errors.New("quota denies ping")
	}
	if err := client.sendDiagnosticPing(sourceID, destination, request); err != nil {
		return 0, err
	}
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return 0, ctx.Err()
	case <-replies:
		return time.Since(started), nil
	case <-timer.C:
		return 0, fmt.Errorf("ping %s: i/o timeout", target)
	}
}

// sendDiagnosticPing uses the certified assignment order. Direct and
// via-manager paths therefore follow exactly the same admission rules as
// packets arriving from the operating system.
func (client *Client) sendDiagnosticPing(source peer.ID, destination model.PeerRecord, request []byte) error {
	destinationID, err := peer.Decode(destination.PeerID)
	if err != nil {
		return fmt.Errorf("decode destination peer: %w", err)
	}
	if err := client.syncPathSelector(); err != nil {
		return fmt.Errorf("sync paths: %w", err)
	}
	assignment, path, status := client.paths.selectWithStatus(source, destinationID)
	client.recordPathSelection(destinationID, status)
	if !status.OK {
		if status.Err != nil {
			return status.Err
		}
		return errors.New("no usable path")
	}
	if path.Kind == model.PathKindDirect {
		if !client.sendFrame(destinationID, request) {
			return errors.New("direct send failed")
		}
		return nil
	}
	if err := client.paths.forwarder.Send(source, destinationID, assignment.ID, path.ID, request); err != nil {
		return fmt.Errorf("forward send failed: %w", err)
	}
	return nil
}

func (client *Client) setDiagnosticWaiter(identifier uint16, destinationIP string, replies chan packet.IPv4Packet) bool {
	client.mu.Lock()
	defer client.mu.Unlock()
	if client.pingWaiters == nil {
		client.pingWaiters = make(map[uint16]chan packet.IPv4Packet)
	}
	if _, exists := client.pingWaiters[identifier]; exists {
		return false
	}
	client.pingWaiters[identifier] = replies
	return true
}

func (client *Client) clearDiagnosticWaiter(identifier uint16) {
	client.mu.Lock()
	defer client.mu.Unlock()
	if _, exists := client.pingWaiters[identifier]; exists {
		delete(client.pingWaiters, identifier)
	}
}

func (client *Client) deliverDiagnosticPing(ipPacket packet.IPv4Packet) bool {
	icmpStart := ipPacket.HeaderLength()
	if len(ipPacket) < icmpStart+8 || packet.ICMPMessage(ipPacket[icmpStart:]).Type() != packet.ICMPTypeEchoReply {
		return false
	}
	identifier := packet.ICMPMessage(ipPacket[icmpStart:]).Identifier()
	client.mu.RLock()
	replies, exists := client.pingWaiters[identifier]
	client.mu.RUnlock()
	if !exists {
		return false
	}
	select {
	case replies <- append(packet.IPv4Packet(nil), ipPacket...):
		return true
	default:
		return true
	}
}

func pingIdentifier() (uint16, error) {
	var value uint16
	for {
		if err := binary.Read(rand.Reader, binary.BigEndian, &value); err != nil {
			return 0, err
		}
		// Keep this diagnostic class separate from the fixed admission probe.
		if value != 0 && value != 0x4e50 {
			return value, nil
		}
	}
}
