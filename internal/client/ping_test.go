package client

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"

	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/netp2p/netp2p/internal/forward"
	"github.com/netp2p/netp2p/internal/model"
	"github.com/netp2p/netp2p/internal/packet"
)

func TestPingUsesActiveDataPath(t *testing.T) {
	node := newTransportNode(t)
	state := transportState(node.Host.ID().String())
	state.Peers[0].PeerID = node.Host.ID().String()
	state.Groups[0].PeerIDs = []string{node.Host.ID().String()}
	state.Peers[1].PeerID = transportSourceID
	state.Groups[1].PeerIDs = []string{transportSourceID}
	state.Assignments[0].SourcePeerID = node.Host.ID().String()
	state.Assignments[0].DestinationPeerID = transportSourceID
	client, sink := newDestinationClient(t, node, state)
	source, err := peer.Decode(transportSourceID)
	if err != nil {
		t.Fatal(err)
	}
	forwarding := forward.NewTable(state, node.Host.ID().String(), func(remote peer.ID, envelope forward.Envelope) error {
		if envelope.Header.PathID != "via-manager" {
			t.Errorf("unexpected path %s", envelope.Header.PathID)
		}
		request := packet.IPv4Packet(envelope.Payload)
		time.Sleep(2 * time.Millisecond)
		reply, err := packet.BuildEchoReply(request, packet.ICMPMessage(request[request.HeaderLength():]))
		if err != nil {
			t.Fatalf("build reply: %v", err)
		}
		client.handleFrameWithAdmission(source, reply, false)
		return nil
	})
	client.forwarding = forwarding
	client.paths.forwarder = forwarding

	elapsed, err := client.Ping(context.Background(), net.ParseIP("100.64.0.2"), time.Second)
	if err != nil {
		t.Fatalf("active-path ping failed: %v", err)
	}
	if elapsed <= 0 {
		t.Fatalf("elapsed = %v, want positive", elapsed)
	}
	if len(sink.written) != 0 {
		t.Fatalf("diagnostic ping bypassed the active path and wrote %d packets", len(sink.written))
	}
}

func TestPingTimeoutClearsWaiter(t *testing.T) {
	node := newTransportNode(t)
	state := transportState(node.Host.ID().String())
	state.Peers[0].PeerID = node.Host.ID().String()
	state.Groups[0].PeerIDs = []string{node.Host.ID().String()}
	state.Peers[1].PeerID = transportSourceID
	state.Groups[1].PeerIDs = []string{transportSourceID}
	state.Assignments[0].SourcePeerID = node.Host.ID().String()
	state.Assignments[0].DestinationPeerID = transportSourceID
	client, _ := newDestinationClient(t, node, state)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()

	_, err := client.Ping(ctx, net.ParseIP("100.64.0.2"), 50*time.Millisecond)
	if err == nil || !errors.Is(err, ctx.Err()) {
		t.Fatalf("ping error = %v, want context deadline", err)
	}

	identifier := uint16(1)
	replies := make(chan packet.IPv4Packet, 1)
	if !client.setDiagnosticWaiter(identifier, "100.64.0.2", replies) {
		t.Fatal("timed-out ping identifier was not cleared")
	}
	client.clearDiagnosticWaiter(identifier)
}

func TestPingHonorsPolicy(t *testing.T) {
	node := newTransportNode(t)
	state := transportState(node.Host.ID().String())
	state.Peers[0].PeerID = node.Host.ID().String()
	state.Groups[0].PeerIDs = []string{node.Host.ID().String()}
	state.Peers[1].PeerID = transportSourceID
	state.Groups[1].PeerIDs = []string{transportSourceID}
	state.Assignments[0].SourcePeerID = node.Host.ID().String()
	state.Assignments[0].DestinationPeerID = transportSourceID
	state.Policies[0].Effect = model.EffectDeny
	client, _ := newDestinationClient(t, node, state)
	forwarding := forward.NewTable(state, node.Host.ID().String(), func(peer.ID, forward.Envelope) error {
		t.Error("denied ping reached the data path")
		return nil
	})
	client.forwarding = forwarding
	client.paths.forwarder = forwarding

	_, err := client.Ping(context.Background(), net.ParseIP("100.64.0.2"), 50*time.Millisecond)
	if err == nil || err.Error() != "policy denies icmp" {
		t.Fatalf("denied ping error = %v", err)
	}
}
