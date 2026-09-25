package transport

import (
	"bytes"
	"context"
	"sync"
	"testing"
	"time"

	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/netp2p/netp2p/internal/forward"
	"github.com/netp2p/netp2p/internal/p2p"
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
	}, func(_ peer.ID, payload []byte) {
		if _, err := forward.DecodeEnvelope(payload); err != nil {
			return
		}
		envelopes <- payload
	})
	defer receiver.Close()
	sender := New(ctx, left.Host, p2p.FrameProtocol, nil)
	defer sender.Close()

	payload := []byte{0x45, 0x00, 0x00, 0x14, 'd', 'i', 'r', 'e', 'c', 't'}
	if err := sender.Send(right.Host.ID(), payload); err != nil {
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
	if err := sender.Send(right.Host.ID(), envelope); err != nil {
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
	receiver := NewWithEnvelope(ctx, right.Host, p2p.FrameProtocol, nil, func(_ peer.ID, payload []byte) {
		envelopes <- payload
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
	if err := sender.Send(right.Host.ID(), envelope); err != nil {
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
		if err := leftTransport.Send(right.Host.ID(), payload); err != nil {
			t.Fatalf("send right: %v", err)
		}
		if err := rightTransport.Send(left.Host.ID(), payload); err != nil {
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
		if err := leftTransport.Send(right.Host.ID(), []byte{byte(index), 0xff}); err != nil {
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
	if err := transport.Send(remote, nil); err == nil {
		t.Fatal("empty frame must be rejected")
	}
	if err := transport.Send(remote, make([]byte, MaxFrameSize+1)); err == nil {
		t.Fatal("oversized frame must be rejected")
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
		if err := transport.Send(remote, []byte{byte(index)}); err == ErrQueueFull {
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
