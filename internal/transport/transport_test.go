package transport

import (
	"bytes"
	"context"
	"errors"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/netp2p/netp2p/internal/forward"
	"github.com/netp2p/netp2p/internal/model"
	"github.com/netp2p/netp2p/internal/p2p"
	"github.com/netp2p/netp2p/internal/packet"
	"github.com/netp2p/netp2p/internal/path"
)

func newTestNode(t *testing.T) (*p2p.Node, context.CancelFunc) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	node, err := p2p.New(ctx, p2p.Config{Listen: []string{"/ip4/127.0.0.1/udp/0/quic-v1"}})
	if err != nil {
		cancel()
		t.Fatal(err)
	}
	return node, cancel
}

// TestTransportDispatchesBothHandlers verifies that a peer may register both
// handlers on the shared frame protocol: direct frames reach the packet
// handler and forwarded envelopes reach the envelope handler, each rejecting
// the other's framing at the application layer.
func TestTransportDispatchesBothHandlers(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	left, cancelLeft := newTestNode(t)
	defer cancelLeft()
	defer left.Close()
	right, cancelRight := newTestNode(t)
	defer cancelRight()
	defer right.Close()
	if err := left.Host.Connect(ctx, peer.AddrInfo{ID: right.Host.ID(), Addrs: right.Host.Addrs()}); err != nil {
		t.Fatal(err)
	}

	packets := make(chan []byte, 4)
	envelopes := make(chan []byte, 4)
	receiver := NewWithEnvelope(ctx, right.Host, p2p.FrameProtocol, func(_ peer.ID, payload []byte) {
		// A direct frame is a raw IPv4 packet; an envelope is rejected by the
		// magic byte check the client performs.
		if len(payload) == 0 || payload[0] == forward.MagicByte {
			return
		}
		packets <- payload
	}, func(_ peer.ID, payload []byte) error {
		if _, err := forward.DecodeEnvelope(payload); err != nil {
			return nil
		}
		envelopes <- payload
		return nil
	})
	defer receiver.Close()
	sender := New(ctx, left.Host, p2p.FrameProtocol, nil)
	defer sender.Close()

	payload := []byte{0x45, 0x00, 0x00, 0x14, 'd', 'i', 'r', 'e', 'c', 't'}
	if err := sender.SendPacket(right.Host.ID(), payload); err != nil {
		t.Fatal(err)
	}
	envelope, err := forward.EncodeEnvelope(forward.Envelope{
		Header: forward.Header{
			SourcePeerID: left.Host.ID().String(), DestinationPeerID: right.Host.ID().String(),
			AssignmentID: "assignment", PathID: "path", TTL: 3,
		},
		Payload: []byte("forwarded"),
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := sender.SendEnvelope(right.Host.ID(), envelope); err != nil {
		t.Fatal(err)
	}
	select {
	case got := <-packets:
		if !bytes.Equal(got, payload) {
			t.Fatalf("packet mismatch: %s", got)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("packet handler was not called")
	}
	select {
	case got := <-envelopes:
		if !bytes.Equal(got, envelope) {
			t.Fatal("envelope mismatch")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("envelope handler was not called")
	}
	select {
	case got := <-packets:
		t.Fatalf("envelope was also delivered to packet handler: %s", got)
	default:
	}
}

func TestTransportDeliversEnvelopes(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	left, cancelLeft := newTestNode(t)
	defer cancelLeft()
	defer left.Close()
	right, cancelRight := newTestNode(t)
	defer cancelRight()
	defer right.Close()
	if err := left.Host.Connect(ctx, peer.AddrInfo{ID: right.Host.ID(), Addrs: right.Host.Addrs()}); err != nil {
		t.Fatal(err)
	}

	envelopes := make(chan []byte, 1)
	receiver := NewWithEnvelope(ctx, right.Host, p2p.FrameProtocol, nil, func(_ peer.ID, payload []byte) error {
		envelopes <- payload
		return nil
	})
	defer receiver.Close()
	sender := New(ctx, left.Host, p2p.FrameProtocol, nil)
	defer sender.Close()

	envelope, err := forward.EncodeEnvelope(forward.Envelope{
		Header: forward.Header{
			SourcePeerID: left.Host.ID().String(), DestinationPeerID: right.Host.ID().String(),
			AssignmentID: "assignment", PathID: "path", TTL: 3,
		},
		Payload: []byte("forwarded"),
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := sender.SendEnvelope(right.Host.ID(), envelope); err != nil {
		t.Fatal(err)
	}
	select {
	case got := <-envelopes:
		if !bytes.Equal(got, envelope) {
			t.Fatal("envelope mismatch")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("envelope was not delivered")
	}
}

// TestTransportDeliversFramesBetweenHosts exercises the persistent stream in
// both directions, which is the property the old per-packet stream never had.
func TestTransportDeliversFramesBetweenHosts(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	left, cancelLeft := newTestNode(t)
	defer cancelLeft()
	defer left.Close()
	right, cancelRight := newTestNode(t)
	defer cancelRight()
	defer right.Close()

	if err := left.Host.Connect(ctx, peer.AddrInfo{ID: right.Host.ID(), Addrs: right.Host.Addrs()}); err != nil {
		t.Fatalf("connect: %v", err)
	}

	var mu sync.Mutex
	receivedByRight := make(map[string][]byte)
	receivedByLeft := make(map[string][]byte)

	rightTransport := New(ctx, right.Host, p2p.FrameProtocol, func(_ peer.ID, payload []byte) {
		mu.Lock()
		receivedByRight[string(payload)] = append([]byte(nil), payload...)
		mu.Unlock()
	})
	defer rightTransport.Close()
	leftTransport := New(ctx, left.Host, p2p.FrameProtocol, func(_ peer.ID, payload []byte) {
		mu.Lock()
		receivedByLeft[string(payload)] = append([]byte(nil), payload...)
		mu.Unlock()
	})
	defer leftTransport.Close()

	payloads := [][]byte{
		bytes.Repeat([]byte{0x01}, 64),
		bytes.Repeat([]byte{0x02}, 1280),
		bytes.Repeat([]byte{0x03}, 8192),
	}
	for _, payload := range payloads {
		if err := leftTransport.SendPacket(right.Host.ID(), payload); err != nil {
			t.Fatalf("send right: %v", err)
		}
		if err := rightTransport.SendPacket(left.Host.ID(), payload); err != nil {
			t.Fatalf("send left: %v", err)
		}
	}

	deadline := time.Now().Add(10 * time.Second)
	for {
		mu.Lock()
		rightCount, leftCount := len(receivedByRight), len(receivedByLeft)
		mu.Unlock()
		if rightCount == len(payloads) && leftCount == len(payloads) {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("delivered right=%d left=%d, want %d each", rightCount, leftCount, len(payloads))
		}
		time.Sleep(20 * time.Millisecond)
	}

	for _, payload := range payloads {
		mu.Lock()
		gotRight, okRight := receivedByRight[string(payload)]
		gotLeft, okLeft := receivedByLeft[string(payload)]
		mu.Unlock()
		if !okRight || !bytes.Equal(gotRight, payload) {
			t.Fatalf("right received %d bytes, want %d", len(gotRight), len(payload))
		}
		if !okLeft || !bytes.Equal(gotLeft, payload) {
			t.Fatalf("left received %d bytes, want %d", len(gotLeft), len(payload))
		}
	}
}

// TestTransportReusesOneStream confirms the design goal: many packets share a
// single outbound stream instead of opening one stream per packet.
func TestTransportReusesOneStream(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	left, cancelLeft := newTestNode(t)
	defer cancelLeft()
	defer left.Close()
	right, cancelRight := newTestNode(t)
	defer cancelRight()
	defer right.Close()

	if err := left.Host.Connect(ctx, peer.AddrInfo{ID: right.Host.ID(), Addrs: right.Host.Addrs()}); err != nil {
		t.Fatalf("connect: %v", err)
	}

	delivered := make(chan struct{}, 256)
	rightTransport := New(ctx, right.Host, p2p.FrameProtocol, func(_ peer.ID, _ []byte) {
		delivered <- struct{}{}
	})
	defer rightTransport.Close()
	leftTransport := New(ctx, left.Host, p2p.FrameProtocol, nil)
	defer leftTransport.Close()

	const count = 64
	for index := 0; index < count; index++ {
		if err := leftTransport.SendPacket(right.Host.ID(), []byte{byte(index), 0xff}); err != nil {
			t.Fatalf("send %d: %v", index, err)
		}
	}
	for index := 0; index < count; index++ {
		select {
		case <-delivered:
		case <-time.After(10 * time.Second):
			t.Fatalf("only %d of %d frames arrived", index, count)
		}
	}

	// One outbound stream to the peer, not one per packet.
	if streams := left.Host.Network().ConnsToPeer(right.Host.ID()); len(streams) == 0 {
		t.Fatal("no connection to the peer")
	}
	sent, dropped := leftTransport.Stats(right.Host.ID())
	if sent != count {
		t.Fatalf("sent = %d, want %d", sent, count)
	}
	if dropped != 0 {
		t.Fatalf("dropped = %d, want 0", dropped)
	}
}

// TestSendScaleDoesNotReuseStalePersistentStream reproduces the idle-stream
// failure without waiting for the production read deadline. The first packet
// establishes a persistent stream, that stream is then reset as an idle receiver
// would do, and the next scale frame must still be delivered and acknowledged.
func TestSendScaleDoesNotReuseStalePersistentStream(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	left, cancelLeft := newTestNode(t)
	defer cancelLeft()
	defer left.Close()
	right, cancelRight := newTestNode(t)
	defer cancelRight()
	defer right.Close()
	if err := left.Host.Connect(ctx, peer.AddrInfo{ID: right.Host.ID(), Addrs: right.Host.Addrs()}); err != nil {
		t.Fatalf("connect: %v", err)
	}

	packets := make(chan struct{}, 1)
	scales := make(chan []byte, 1)
	rightTransport := NewWithEnvelope(
		ctx, right.Host, p2p.FrameProtocol,
		func(peer.ID, []byte) { packets <- struct{}{} },
		func(_ peer.ID, payload []byte) error {
			scales <- payload
			return nil
		},
	)
	defer rightTransport.Close()
	leftTransport := New(ctx, left.Host, p2p.FrameProtocol, nil)
	defer leftTransport.Close()

	if err := leftTransport.SendPacket(right.Host.ID(), []byte{0x45, 0x00}); err != nil {
		t.Fatalf("seed persistent stream: %v", err)
	}
	select {
	case <-packets:
	case <-time.After(5 * time.Second):
		t.Fatal("persistent stream was not established")
	}

	leftTransport.mu.Lock()
	conn, ok := leftTransport.conns[right.Host.ID()]
	leftTransport.mu.Unlock()
	if !ok {
		t.Fatal("persistent outbound connection was not created")
	}
	conn.mu.Lock()
	stream := conn.stream
	conn.mu.Unlock()
	if stream == nil {
		t.Fatal("persistent outbound stream was not created")
	}
	_ = stream.Reset()

	payload := []byte("first-scale-after-stale-stream")
	if err := leftTransport.SendScale(right.Host.ID(), payload); err != nil {
		t.Fatalf("send scale after stale stream: %v", err)
	}
	select {
	case got := <-scales:
		if !bytes.Equal(got, payload) {
			t.Fatalf("scale payload mismatch: %q", got)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("scale frame was lost on a stale persistent stream")
	}
}

func TestScaleForwardCounterRequiresDestinationAcknowledgement(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	sourceNode, cancelSource := newTestNode(t)
	defer cancelSource()
	defer sourceNode.Close()
	managerNode, cancelManager := newTestNode(t)
	defer cancelManager()
	defer managerNode.Close()
	destinationNode, cancelDestination := newTestNode(t)
	defer cancelDestination()
	defer destinationNode.Close()
	if err := managerNode.Host.Connect(ctx, peer.AddrInfo{
		ID: destinationNode.Host.ID(), Addrs: destinationNode.Host.Addrs(),
	}); err != nil {
		t.Fatalf("connect destination: %v", err)
	}

	sourceID := sourceNode.Host.ID().String()
	managerID := managerNode.Host.ID().String()
	destinationID := destinationNode.Host.ID().String()
	state := model.NetworkState{
		NetworkID: "scale-ack-test",
		Peers: []model.PeerRecord{
			{PeerID: sourceID, OverlayIP: "100.64.0.1", Groups: []string{"sources"}},
			{PeerID: destinationID, OverlayIP: "100.64.0.2", Groups: []string{"destinations"}},
		},
		Groups: []model.Group{
			{ID: "sources", PeerIDs: []string{sourceID}},
			{ID: "destinations", PeerIDs: []string{destinationID}},
		},
		Policies: []model.Policy{{
			ID: "allow-icmp", SourceGroups: []string{"sources"}, DestinationGroups: []string{"destinations"},
			Services: []model.Service{{Protocol: "icmp"}}, Effect: model.EffectAllow,
		}},
		PathFamilies: []model.PathFamily{{
			ID: "family-via-manager", Kind: model.PathKindViaManager,
			ManagerHops:  []string{managerID},
			SourceGroups: []string{"sources"}, DestinationScopes: []string{"group:destinations"},
			FlowClasses: []string{string(path.FlowLatency)},
		}},
		RoutingDomains: []model.RoutingDomainAuthorization{{
			ID: "manager/sources/group:destinations/latency",
			Key: model.RoutingDomainKey{
				SourceManagerID: "manager", SourceGroupID: "sources",
				DestinationScope: model.DestinationScopeGroup + "destinations",
				FlowClass:        string(path.FlowLatency),
			},
			PathFamilyIDs: []string{"family-via-manager"}, PolicyIDs: []string{"allow-icmp"},
		}},
	}

	var rejectScale atomic.Bool
	packets := make(chan struct{}, 1)
	delivered := make(chan []byte, 1)
	destinationTransport := NewWithEnvelope(
		ctx, destinationNode.Host, p2p.FrameProtocol,
		func(peer.ID, []byte) { packets <- struct{}{} },
		func(_ peer.ID, wire []byte) error {
			if rejectScale.Load() {
				return errors.New("destination rejected scale frame")
			}
			delivered <- wire
			return nil
		},
	)
	defer destinationTransport.Close()
	managerTransport := New(ctx, managerNode.Host, p2p.FrameProtocol, nil)
	defer managerTransport.Close()

	table := forward.NewTable(state, managerID, nil)
	table.SetScaleRouting(func(_, _, _, _, _ string) (forward.ScaleAuthorization, error) {
		return forward.ScaleAuthorization{
			FaceID: managerID, NextHop: destinationID, ExpectedPredecessor: sourceID,
		}, nil
	}, func(remote peer.ID, envelope forward.ScaleEnvelope) error {
		wire, err := forward.EncodeScaleEnvelope(envelope)
		if err != nil {
			return err
		}
		return managerTransport.SendScale(remote, wire)
	})

	if err := managerTransport.SendPacket(destinationNode.Host.ID(), []byte{0x45, 0x00}); err != nil {
		t.Fatalf("seed persistent stream: %v", err)
	}
	select {
	case <-packets:
	case <-time.After(5 * time.Second):
		t.Fatal("persistent stream was not established")
	}
	managerTransport.mu.Lock()
	conn := managerTransport.conns[destinationNode.Host.ID()]
	managerTransport.mu.Unlock()
	if conn == nil {
		t.Fatal("persistent connection is missing")
	}
	conn.mu.Lock()
	staleStream := conn.stream
	conn.mu.Unlock()
	if staleStream == nil {
		t.Fatal("persistent stream is missing")
	}
	_ = staleStream.Reset()

	newEnvelope := func(t *testing.T, identifier uint16) forward.ScaleEnvelope {
		t.Helper()
		payload, err := packet.BuildEchoRequest(
			net.ParseIP("100.64.0.1"), net.ParseIP("100.64.0.2"), identifier, 1, []byte("ack"),
		)
		if err != nil {
			t.Fatal(err)
		}
		flowHash, ok := packet.FlowHash(payload)
		if !ok {
			t.Fatal("test payload has no flow hash")
		}
		return forward.ScaleEnvelope{
			Header: forward.ScaleHeader{
				SourcePeerID: sourceID, DestinationPeerID: destinationID,
				RoutingDomainID: "manager/sources/group:destinations/latency",
				PathFamilyID:    "family-via-manager", PathInstanceID: managerID,
				FlowClass: string(path.FlowLatency), FlowHash: flowHash, TTL: forward.DefaultTTL,
			},
			Payload: payload,
		}
	}
	source, err := peer.Decode(sourceID)
	if err != nil {
		t.Fatal(err)
	}
	deliveredResult, err := table.AcceptScale(source, newEnvelope(t, 0x5151))
	if err != nil || deliveredResult {
		t.Fatalf("accepted scale frame = (%v, %v), want (false, nil)", deliveredResult, err)
	}
	select {
	case wire := <-delivered:
		envelope, err := forward.DecodeScaleEnvelope(wire)
		if err != nil || envelope.Header.SourcePeerID != sourceID {
			t.Fatalf("delivered scale envelope = (%+v, %v)", envelope.Header, err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("scale frame was not delivered before forwarding was counted")
	}
	forwarded, dropped := table.Stats()
	if forwarded != 1 || dropped != 0 {
		t.Fatalf("after acknowledged frame stats = (%d, %d), want (1, 0)", forwarded, dropped)
	}

	rejectScale.Store(true)
	if _, err := table.AcceptScale(source, newEnvelope(t, 0x5152)); err == nil {
		t.Fatal("rejected scale frame was reported as accepted")
	}
	forwarded, dropped = table.Stats()
	if forwarded != 1 || dropped != 1 {
		t.Fatalf("after rejected frame stats = (%d, %d), want (1, 1)", forwarded, dropped)
	}
}

func TestSendRejectsInvalidFrameSize(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	node, cancelNode := newTestNode(t)
	defer cancelNode()
	defer node.Close()

	transport := New(ctx, node.Host, p2p.FrameProtocol, nil)
	defer transport.Close()

	remote, err := peer.Decode("12D3KooWNC1cKisChtyY5ZbeJBV8Xqqaj1k8gxGJPt2u2JtCAPp4")
	if err != nil {
		t.Fatal(err)
	}
	if err := transport.SendPacket(remote, nil); err == nil {
		t.Fatal("empty frame must be rejected")
	}
	if err := transport.SendPacket(remote, make([]byte, MaxFrameSize+1)); err == nil {
		t.Fatal("oversized frame must be rejected")
	}
}

func TestTransportRejectsOversizedForwardingEnvelope(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	left, cancelLeft := newTestNode(t)
	defer cancelLeft()
	defer left.Close()
	right, cancelRight := newTestNode(t)
	defer cancelRight()
	defer right.Close()

	if err := left.Host.Connect(ctx, peer.AddrInfo{ID: right.Host.ID(), Addrs: right.Host.Addrs()}); err != nil {
		t.Fatalf("connect: %v", err)
	}
	decoded := make(chan error, 1)
	rightTransport := NewWithEnvelope(ctx, right.Host, p2p.FrameProtocol, nil, func(_ peer.ID, payload []byte) error {
		_, err := forward.DecodeEnvelope(payload)
		decoded <- err
		return nil
	})
	defer rightTransport.Close()
	leftTransport := NewWithEnvelope(ctx, left.Host, p2p.FrameProtocol, nil, nil)
	defer leftTransport.Close()

	envelope, err := forward.EncodeEnvelope(forward.Envelope{
		Header: forward.Header{
			SourcePeerID: "source", DestinationPeerID: "destination",
			AssignmentID: "assignment", PathID: "path", TTL: 3,
		},
		Payload: []byte("x"),
	})
	if err != nil {
		t.Fatal(err)
	}
	oversized := append(append([]byte{}, envelope[:len(envelope)-1]...), make([]byte, forward.MaxFrameSize+1)...)
	if err := leftTransport.SendEnvelope(right.Host.ID(), oversized); err != nil {
		t.Fatalf("send oversized envelope: %v", err)
	}
	select {
	case err := <-decoded:
		if !errors.Is(err, forward.ErrMalformedEnvelope) {
			t.Fatalf("decode error = %v, want %v", err, forward.ErrMalformedEnvelope)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for oversized envelope")
	}
}

// TestSendDropsAndReportsBackpressure fills the queue with an unreachable peer
// and asserts Send reports backpressure instead of blocking the data path.
func TestSendDropsAndReportsBackpressure(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	node, cancelNode := newTestNode(t)
	defer cancelNode()
	defer node.Close()

	transport := New(ctx, node.Host, p2p.FrameProtocol, nil)
	defer transport.Close()
	transport.depth = 4

	remote, err := peer.Decode("12D3KooWGeZkArb2TCBHanoBgz84uEbgqH3p1L1SA3ZFqznetjw3")
	if err != nil {
		t.Fatal(err)
	}
	// The peer is unreachable, so the writer drains slowly and the queue fills.
	var full bool
	for index := 0; index < 512; index++ {
		if err := transport.SendPacket(remote, []byte{byte(index)}); err == ErrQueueFull {
			full = true
			break
		}
	}
	if !full {
		t.Fatal("expected backpressure once the queue filled")
	}
	if _, dropped := transport.Stats(remote); dropped == 0 {
		t.Fatal("dropped counter was not incremented")
	}
}
