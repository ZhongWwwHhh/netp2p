package client

import (
	"context"
	"encoding/json"
	"time"

	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/netp2p/netp2p/internal/p2p"
	"github.com/netp2p/netp2p/internal/packet"
)

const maxOverlayPacket = 65535

func (client *Client) ServePackets(ctx context.Context) error {
	go client.handleFrameStreams(ctx)
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
		return
	}
	ipPacket := packet.IPv4Packet(raw)
	if err := ipPacket.Validate(); err != nil {
		return
	}
	destination, err := client.peerByIP(ipPacket.Destination())
	if err != nil {
		return
	}
	protocolName, port := describePacket(ipPacket)
	allowed, err := client.authorize(destination, protocolName, port)
	if err != nil || !allowed {
		return
	}
	peerID, err := peer.Decode(destination.PeerID)
	if err != nil {
		return
	}
	client.sendFrame(ctx, peerID, raw)
}

func (client *Client) sendFrame(ctx context.Context, peerID peer.ID, raw []byte) {
	sendContext, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	_ = client.node.Send(sendContext, peerID, p2p.FrameProtocol, raw)
}

func (client *Client) handleFrameStreams(ctx context.Context) {
	client.node.Handle(p2p.FrameProtocol, func(stream network.Stream) {
		defer stream.Close()
		raw, err := decodeFramePayload(stream)
		if err != nil {
			return
		}
		if len(raw) == 0 || len(raw) > maxOverlayPacket {
			return
		}
		ipPacket := packet.IPv4Packet(raw)
		if err := ipPacket.Validate(); err != nil {
			return
		}
		remote := stream.Conn().RemotePeer()
		source, err := client.peerByPeerID(remote.String())
		if err != nil {
			return
		}
		if source.OverlayIP != ipPacket.Source().String() {
			return
		}
		if ipPacket.Destination().String() != client.selfOverlayIP() {
			// v0 does not forward on behalf of third parties.
			return
		}
		if isEchoReply(ipPacket) {
			// An echo reply answers a probe we originated, so it is delivered
			// to the local endpoint without a second policy check. v0 trusts
			// replies that already pass the source-peer and source-IP checks
			// above.
			_ = client.sink.WritePacket(raw)
			return
		}
		protocolName, port := describePacket(ipPacket)
		allowed, err := client.authorizeInbound(source, protocolName, port)
		if err != nil || !allowed {
			return
		}
		if reply, ok := buildEchoReply(ipPacket); ok {
			// Answer an inbound echo request for our own overlay IP by sending
			// the reply back to the requester over the frame stream. Writing it
			// to the local sink would address the wrong endpoint.
			client.sendFrame(ctx, remote, reply)
			return
		}
		_ = client.sink.WritePacket(raw)
	})
}

func decodeFramePayload(stream network.Stream) ([]byte, error) {
	envelope, err := p2p.DecodeEnvelope(stream)
	if err != nil {
		return nil, err
	}
	var raw []byte
	if err := json.Unmarshal(envelope.Payload, &raw); err != nil {
		return nil, err
	}
	return raw, nil
}
