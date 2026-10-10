package transport_test

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/netp2p/netp2p/internal/forward"
	"github.com/netp2p/netp2p/internal/model"
	"github.com/netp2p/netp2p/internal/p2p"
	"github.com/netp2p/netp2p/internal/packet"
	"github.com/netp2p/netp2p/internal/transport"
)

func benchNode(b *testing.B, seed int64) *p2p.Node {
	b.Helper()
	node, err := p2p.New(context.Background(), p2p.Config{
		IdentitySeed: seed,
		Listen:       []string{"/ip4/127.0.0.1/udp/0/quic-v1"},
		WebRTCListen: []string{"/ip4/127.0.0.1/udp/0/webrtc-direct"},
	})
	if err != nil {
		b.Fatal(err)
	}
	b.Cleanup(func() { _ = node.Close() })
	return node
}

func benchPayload(b *testing.B) []byte {
	b.Helper()
	payload, err := packet.BuildEchoRequest(
		net.ParseIP("100.64.0.1"), net.ParseIP("100.64.0.2"), 1, 1, make([]byte, 1172),
	)
	if err != nil {
		b.Fatal(err)
	}
	return payload
}

func connectNodes(b *testing.B, source, destination *p2p.Node) {
	b.Helper()
	info, err := peer.AddrInfoFromString(destination.Addresses()[0])
	if err != nil {
		b.Fatal(err)
	}
	if err := source.Host.Connect(context.Background(), *info); err != nil {
		b.Fatal(err)
	}
}

func BenchmarkTransportDirectThroughput(b *testing.B) {
	source := benchNode(b, 901)
	destination := benchNode(b, 902)
	connectNodes(b, source, destination)
	received := make(chan struct{}, 1)
	ctx := context.Background()
	sourceTransport := transport.NewWithEnvelope(ctx, source.Host, p2p.FrameProtocol, func(peer.ID, []byte) {}, nil)
	destinationTransport := transport.NewWithEnvelope(ctx, destination.Host, p2p.FrameProtocol, func(peer.ID, []byte) {
		select {
		case received <- struct{}{}:
		default:
		}
	}, nil)
	b.Cleanup(func() {
		_ = sourceTransport.Close()
		_ = destinationTransport.Close()
	})
	payload := benchPayload(b)
	b.SetBytes(int64(len(payload)))
	b.ReportAllocs()
	b.ResetTimer()
	for index := 0; index < b.N; index++ {
		if err := sourceTransport.SendPacket(destination.Host.ID(), payload); err != nil {
			b.Fatal(err)
		}
		select {
		case <-received:
		case <-time.After(5 * time.Second):
			b.Fatal("direct benchmark packet was not received")
		}
	}
}

func BenchmarkTransportViaManagerThroughput(b *testing.B) {
	source := benchNode(b, 911)
	manager := benchNode(b, 912)
	destination := benchNode(b, 913)
	connectNodes(b, source, manager)
	connectNodes(b, manager, destination)

	sourceID := source.Host.ID()
	managerID := manager.Host.ID()
	destinationID := destination.Host.ID()
	received := make(chan struct{}, 1)
	ctx := context.Background()
	state := viaManagerBenchmarkState(sourceID, managerID, destinationID)

	sourceTransport := transport.NewWithEnvelope(ctx, source.Host, p2p.FrameProtocol, func(peer.ID, []byte) {}, nil)
	var managerForward *forward.Table
	managerTransport := transport.NewWithEnvelope(ctx, manager.Host, p2p.FrameProtocol, func(peer.ID, []byte) {}, func(remote peer.ID, wire []byte) {
		envelope, err := forward.DecodeEnvelope(wire)
		if err != nil {
			b.Error(err)
			return
		}
		if _, err := managerForward.Accept(remote, envelope); err != nil {
			b.Error(err)
		}
	})
	destinationForward := forward.NewTable(state, destinationID.String(), func(peer.ID, forward.Envelope) error {
		return nil
	})
	destinationTransport := transport.NewWithEnvelope(ctx, destination.Host, p2p.FrameProtocol, nil, func(remote peer.ID, wire []byte) {
		envelope, err := forward.DecodeEnvelope(wire)
		if err != nil {
			b.Error(err)
			return
		}
		delivered, err := destinationForward.Accept(remote, envelope)
		if err != nil {
			b.Error(err)
			return
		}
		if !delivered {
			b.Error("destination did not accept forwarded envelope")
			return
		}
		select {
		case received <- struct{}{}:
		default:
		}
	})
	b.Cleanup(func() {
		_ = sourceTransport.Close()
		_ = managerTransport.Close()
		_ = destinationTransport.Close()
	})

	managerForward = forward.NewTable(state, managerID.String(), func(remote peer.ID, envelope forward.Envelope) error {
		wire, err := forward.EncodeEnvelope(envelope)
		if err != nil {
			return err
		}
		return managerTransport.SendEnvelope(remote, wire)
	})

	sourceForward := forward.NewTable(state, sourceID.String(), func(remote peer.ID, envelope forward.Envelope) error {
		wire, err := forward.EncodeEnvelope(envelope)
		if err != nil {
			return err
		}
		return sourceTransport.SendEnvelope(remote, wire)
	})
	payload := benchPayload(b)
	b.SetBytes(int64(len(payload)))
	b.ReportAllocs()
	b.ResetTimer()
	for index := 0; index < b.N; index++ {
		if err := sourceForward.Send(sourceID, destinationID, "assignment", "path", payload); err != nil {
			b.Fatal(err)
		}
		select {
		case <-received:
		case <-time.After(5 * time.Second):
			sourceSent, sourceDropped := sourceTransport.Stats(managerID)
			managerSent, managerDropped := managerTransport.Stats(destinationID)
			b.Fatalf(
				"via-manager benchmark packet was not received (source sent/dropped=%d/%d, manager sent/dropped=%d/%d)",
				sourceSent, sourceDropped, managerSent, managerDropped,
			)
		}
	}
}

func viaManagerBenchmarkState(source, manager, destination peer.ID) model.NetworkState {
	return model.NetworkState{
		NetworkID: "benchmark",
		Assignments: []model.RouteAssignment{{
			ID: "assignment", NetworkID: "benchmark",
			SourcePeerID: source.String(), DestinationPeerID: destination.String(),
			Primary: model.PathSpec{
				ID: "path", Kind: model.PathKindViaManager,
				ManagerHops: []string{manager.String()},
			},
		}},
	}
}
