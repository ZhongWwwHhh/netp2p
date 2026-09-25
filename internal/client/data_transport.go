package client

import (
	"context"
	"time"

	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/netp2p/netp2p/internal/conntrack"
	"github.com/netp2p/netp2p/internal/forward"
	"github.com/netp2p/netp2p/internal/model"
	"github.com/netp2p/netp2p/internal/p2p"
	"github.com/netp2p/netp2p/internal/packet"
	"github.com/netp2p/netp2p/internal/transport"
)

const maxOverlayPacket = 65535

func (client *Client) ServePackets(ctx context.Context) error {
	frames := transport.NewWithEnvelope(ctx, client.node.Host, p2p.FrameProtocol, client.handleFrame, client.handleEnvelope)
	defer frames.Close()
	client.mu.Lock()
	client.frames = frames
	client.mu.Unlock()

	for {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		raw, err := client.sink.ReadPacket()
		if err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			time.Sleep(10 * time.Millisecond)
			continue
		}
		client.forwardLocalPacket(ctx, raw)
	}
}

// forwardLocalPacket reads a packet from the local userspace endpoint, applies
// policy for the outbound direction and forwards it to the owning overlay peer.
func (client *Client) forwardLocalPacket(ctx context.Context, raw []byte) {
	if len(raw) == 0 || len(raw) > maxOverlayPacket {
		debugDrop("forward: size %d", len(raw))
		return
	}
	ipPacket := packet.IPv4Packet(raw)
	if err := ipPacket.Validate(); err != nil {
		debugDrop("forward: invalid %v", err)
		return
	}
	destination, err := client.peerByIP(ipPacket.Destination())
	if err != nil {
		debugDrop("forward: %v", err)
		return
	}
	flow, hasFlow := ipPacket.Flow()
	// Outbound return traffic: this packet answers something we admitted
	// inbound, so the reverse policy must not be required to also allow it.
	if hasFlow && client.flows.ReplyAllowed(conntrack.Key(flow)) {
		client.sendToPeer(destination, raw)
		return
	}
	protocolName, port := describePacket(ipPacket)
	allowed, err := client.authorize(destination, protocolName, port)
	if err != nil || !allowed {
		debugDrop("forward: denied %s/%d to %s (err=%v)", protocolName, port, destination.OverlayIP, err)
		return
	}
	// Remember the flow so the reply direction is admitted without requiring a
	// second, mirror-image policy rule.
	if hasFlow {
		client.flows.Observe(conntrack.Key(flow))
	}
	client.sendToPeer(destination, raw)
}

func (client *Client) sendToPeer(destination model.PeerRecord, raw []byte) {
	target, err := peer.Decode(destination.PeerID)
	if err != nil {
		return
	}
	if client.sendViaAssignment(client.selfPeerID(), target.String(), raw) {
		return
	}
	client.sendFrame(target, raw)
}

func (client *Client) handleEnvelope(remote peer.ID, wire []byte) {
	envelope, err := forward.DecodeEnvelope(wire)
	if err != nil {
		debugDrop("forwarded envelope: %v", err)
		return
	}
	source, err := peer.Decode(envelope.Header.SourcePeerID)
	if err != nil {
		debugDrop("forwarded source: %v", err)
		return
	}
	if remote == source {
		debugDrop("forwarded envelope from source peer")
		return
	}
	if envelope.Header.DestinationPeerID != client.selfPeerID() {
		debugDrop("forwarded envelope destination mismatch")
		return
	}
	client.handleFrame(source, envelope.Payload)
}

func (client *Client) sendFrame(target peer.ID, raw []byte) {
	client.mu.RLock()
	frames := client.frames
	client.mu.RUnlock()
	if frames == nil {
		return
	}
	_ = frames.Send(target, raw)
}

// handleFrame is the inbound data path: verify the frame really came from the
// peer that owns the source address, then admit it either as return traffic for
// a flow we originated or through the inbound policy.
func (client *Client) handleFrame(remote peer.ID, raw []byte) {
	if len(raw) == 0 || len(raw) > maxOverlayPacket {
		debugDrop("inbound: size %d", len(raw))
		return
	}
	ipPacket := packet.IPv4Packet(raw)
	if err := ipPacket.Validate(); err != nil {
		debugDrop("inbound: invalid %v", err)
		return
	}
	source, err := client.peerByPeerID(remote.String())
	if err != nil {
		debugDrop("inbound: %v", err)
		return
	}
	if source.OverlayIP != ipPacket.Source().String() {
		debugDrop("inbound: source %s does not own %s", source.OverlayIP, ipPacket.Source())
		return
	}
	if isEchoReply(ipPacket) && client.deliverAdmission(ipPacket) {
		return
	}
	if ipPacket.Destination().String() != client.selfOverlayIP() {
		// v0 does not forward on behalf of third parties.
		debugDrop("inbound: not for us (%s)", ipPacket.Destination())
		return
	}
	flow, hasFlow := ipPacket.Flow()
	if hasFlow && client.flows.ReplyAllowed(conntrack.Key(flow)) {
		_ = client.sink.WritePacket(raw)
		return
	}
	protocolName, port := describePacket(ipPacket)
	allowed, err := client.authorizeInbound(source, protocolName, port)
	if err != nil || !allowed {
		debugDrop("inbound: denied %s/%d from %s (err=%v)", protocolName, port, source.OverlayIP, err)
		return
	}
	// The response the local stack produces is return traffic for this flow.
	if hasFlow {
		client.flows.Observe(conntrack.Key(flow))
	}
	if client.synthesizeICMP {
		if reply, ok := buildEchoReply(ipPacket); ok {
			// The userspace endpoint has no kernel to answer the echo request,
			// so build the reply here.
			client.sendFrame(remote, reply)
			return
		}
	}
	_ = client.sink.WritePacket(raw)
}
