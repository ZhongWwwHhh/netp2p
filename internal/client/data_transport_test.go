package client

import (
	"context"
	"errors"
	"io"
	"net"
	"testing"
	"time"

	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/netp2p/netp2p/internal/conntrack"
	"github.com/netp2p/netp2p/internal/forward"
	"github.com/netp2p/netp2p/internal/model"
	"github.com/netp2p/netp2p/internal/p2p"
	"github.com/netp2p/netp2p/internal/packet"
	"github.com/netp2p/netp2p/internal/transport"
)

const (
	transportSourceID  = "12D3KooWGbPJsds7aL2oM7ZgPACEcvoiUxsiYTDzCh9a5C8uB76m"
	transportSpoofID   = "12D3KooWSAoLjUuFPUZkCf7S4xxYr8Hhz8HQr3t9DTanRc9L8AWG"
	transportManagerID = "12D3KooWNC1cKisChtyY5ZbeJBV8Xqqaj1k8gxGJPt2u2JtCAPp4"
)

type transportSink struct {
	written [][]byte
	reads   [][]byte
}

func (sink *transportSink) ReadPacket() ([]byte, error) {
	if len(sink.reads) == 0 {
		return nil, io.ErrClosedPipe
	}
	next := sink.reads[0]
	sink.reads = sink.reads[1:]
	return next, nil
}

func (sink *transportSink) WritePacket(raw []byte) error {
	sink.written = append(sink.written, append([]byte(nil), raw...))
	return nil
}

func (sink *transportSink) Close() error { return nil }

func newTransportNode(t *testing.T) *p2p.Node {
	t.Helper()
	node, err := p2p.New(context.Background(), p2p.Config{})
	if err != nil {
		t.Fatalf("create p2p node: %v", err)
	}
	t.Cleanup(func() { _ = node.Close() })
	return node
}

func transportState(destinationID string) model.NetworkState {
	return model.NetworkState{
		NetworkID: "transport-test",
		Settings: model.NetworkSettings{
			DirectPathEnabled:       false,
			QuotaEnforcementEnabled: false,
		},
		Peers: []model.PeerRecord{
			{PeerID: transportSourceID, OverlayIP: "100.64.0.1", Groups: []string{"sources"}},
			{PeerID: destinationID, OverlayIP: "100.64.0.2", Groups: []string{"destinations"}},
			{PeerID: transportSpoofID, OverlayIP: "100.64.0.3"},
			{PeerID: transportManagerID, OverlayIP: "100.64.0.4"},
		},
		Groups: []model.Group{
			{ID: "sources", PeerIDs: []string{transportSourceID}},
			{ID: "destinations", PeerIDs: []string{destinationID}},
		},
		Policies: []model.Policy{{
			ID: "allow", SourceGroups: []string{"sources"}, DestinationGroups: []string{"destinations"},
			Effect: model.EffectAllow,
		}},
		Assignments: []model.RouteAssignment{{
			ID: "assignment", SourcePeerID: transportSourceID, DestinationPeerID: destinationID,
			Primary: model.PathSpec{
				ID: "via-manager", Kind: model.PathKindViaManager,
				ManagerHops: []string{transportManagerID},
			},
		}},
	}
}

func newDestinationClient(t *testing.T, node *p2p.Node, state model.NetworkState) (*Client, *transportSink) {
	t.Helper()
	sink := &transportSink{}
	forwarding := forward.NewTable(state, node.Host.ID().String(), func(peer.ID, forward.Envelope) error {
		return nil
	})
	paths := newPathSelector(forwarding, nil)
	if err := paths.syncSnapshot(model.SignedSnapshot{State: state}); err != nil {
		t.Fatalf("sync path selector: %v", err)
	}
	var self model.PeerRecord
	for _, candidate := range state.Peers {
		if candidate.PeerID == node.Host.ID().String() {
			self = candidate
		}
	}
	return &Client{
		node: node, sink: sink, flows: conntrack.NewTable(),
		forwarding: forwarding, paths: paths,
		snapshot: model.SignedSnapshot{State: state}, self: self,
	}, sink
}

func transportPayload(t *testing.T) []byte {
	t.Helper()
	payload, err := packet.BuildEchoRequest(
		net.ParseIP("100.64.0.1"), net.ParseIP("100.64.0.2"), 0x4e50, 1, []byte("spoof"),
	)
	if err != nil {
		t.Fatal(err)
	}
	return payload
}

func TestForwardedEnvelopeFromSpoofedPeerIsDropped(t *testing.T) {
	node := newTransportNode(t)
	state := transportState(node.Host.ID().String())
	client, sink := newDestinationClient(t, node, state)

	envelope := forward.Envelope{
		Header: forward.Header{
			SourcePeerID: transportSourceID, DestinationPeerID: node.Host.ID().String(),
			AssignmentID: "assignment", PathID: "via-manager", TTL: forward.DefaultTTL,
		},
		Payload: transportPayload(t),
	}
	wire, err := forward.EncodeEnvelope(envelope)
	if err != nil {
		t.Fatal(err)
	}

	// Peer C opens the transport stream but claims peer A in the envelope.
	spoof, err := peer.Decode(transportSpoofID)
	if err != nil {
		t.Fatal(err)
	}
	client.handleEnvelope(spoof, wire)
	if len(sink.written) != 0 {
		t.Fatalf("spoofed envelope delivered %d packets", len(sink.written))
	}
	if _, dropped := client.forwarding.Stats(); dropped != 1 {
		t.Fatalf("forwarding drops = %d, want 1", dropped)
	}

	// The certified manager predecessor is accepted.
	manager, err := peer.Decode(transportManagerID)
	if err != nil {
		t.Fatal(err)
	}
	client.handleEnvelope(manager, wire)
	if len(sink.written) != 1 {
		t.Fatalf("certified envelope writes = %d, want 1", len(sink.written))
	}
}

func TestNoDirectFallbackWhenDirectPathsAreDisabled(t *testing.T) {
	node := newTransportNode(t)
	state := transportState(node.Host.ID().String())
	state.Settings.DirectPathEnabled = false
	state.Assignments = []model.RouteAssignment{{
		ID: "assignment", SourcePeerID: node.Host.ID().String(), DestinationPeerID: transportSourceID,
		Primary: model.PathSpec{ID: "direct", Kind: model.PathKindDirect},
	}}
	client, _ := newDestinationClient(t, node, state)

	var target model.PeerRecord
	for _, candidate := range state.Peers {
		if candidate.PeerID == transportSourceID {
			target = candidate
		}
	}
	if client.sendToPeer(target, transportPayload(t)) {
		t.Fatal("direct delivery succeeded while direct paths were disabled")
	}

	state.Assignments[0].Primary = model.PathSpec{
		ID: "via-manager", Kind: model.PathKindViaManager,
		ManagerHops: []string{transportManagerID},
	}
	updated := model.SignedSnapshot{State: state, Height: 2}
	if err := client.paths.syncSnapshot(updated); err != nil {
		t.Fatalf("sync updated path selector: %v", err)
	}
	client.forwarding = forward.NewTable(state, node.Host.ID().String(), func(peer.ID, forward.Envelope) error {
		return errors.New("forwarding unavailable")
	})
	client.paths.forwarder = client.forwarding
	if client.sendToPeer(target, transportPayload(t)) {
		t.Fatal("failed manager forwarding fell back to direct delivery")
	}
	if client.DataPlaneStats().OutboundDrops == 0 {
		t.Fatal("disabled direct fallback was not counted as a drop")
	}
}

func TestUnassignedDirectUsesExplicitPacketFrame(t *testing.T) {
	sourceNode := newTransportNode(t)
	destinationNode := newTransportNode(t)
	destinationAddresses := destinationNode.Addresses()
	if len(destinationAddresses) == 0 {
		t.Fatal("destination node has no addresses")
	}

	state := model.NetworkState{
		NetworkID: "transport-direct-test",
		Settings: model.NetworkSettings{
			DirectPathEnabled:       true,
			QuotaEnforcementEnabled: false,
		},
		Peers: []model.PeerRecord{
			{PeerID: sourceNode.Host.ID().String(), OverlayIP: "100.64.0.1", Groups: []string{"sources"}},
			{
				PeerID: destinationNode.Host.ID().String(), OverlayIP: "100.64.0.2",
				Addresses: destinationAddresses, Groups: []string{"destinations"},
			},
		},
		Groups: []model.Group{
			{ID: "sources", PeerIDs: []string{sourceNode.Host.ID().String()}},
			{ID: "destinations", PeerIDs: []string{destinationNode.Host.ID().String()}},
		},
		Policies: []model.Policy{{
			ID: "allow", SourceGroups: []string{"sources"}, DestinationGroups: []string{"destinations"},
			Effect: model.EffectAllow,
		}},
	}
	forwarding := forward.NewTable(state, sourceNode.Host.ID().String(), func(peer.ID, forward.Envelope) error {
		t.Error("unassigned direct path used the forwarding sender")
		return nil
	})
	paths := newPathSelector(forwarding, nil)
	if err := paths.syncSnapshot(model.SignedSnapshot{State: state}); err != nil {
		t.Fatalf("sync path selector: %v", err)
	}

	packets := make(chan []byte, 1)
	envelopes := make(chan []byte, 1)
	receiver := transport.NewWithEnvelope(
		context.Background(), destinationNode.Host, p2p.FrameProtocol,
		func(remote peer.ID, payload []byte) { packets <- payload },
		func(remote peer.ID, payload []byte) error {
			envelopes <- payload
			return nil
		},
	)
	defer receiver.Close()
	client := &Client{
		node: sourceNode, sink: &transportSink{}, flows: conntrack.NewTable(),
		forwarding: forwarding, paths: paths,
		snapshot: model.SignedSnapshot{State: state},
		self:     state.Peers[0],
	}
	client.frames = transport.New(context.Background(), sourceNode.Host, p2p.FrameProtocol, nil)
	defer client.frames.Close()
	connectCtx, cancelConnect := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancelConnect()
	if err := sourceNode.Host.Connect(connectCtx, peer.AddrInfo{
		ID: destinationNode.Host.ID(), Addrs: destinationNode.Host.Addrs(),
	}); err != nil {
		t.Fatalf("connect destination: %v", err)
	}

	if !client.sendToPeer(state.Peers[1], transportPayload(t)) {
		t.Fatal("unassigned direct send failed")
	}
	select {
	case raw := <-packets:
		if packet.IPv4Packet(raw).Validate() != nil {
			t.Fatal("explicit packet frame carried an invalid IPv4 packet")
		}
	case <-envelopes:
		t.Fatal("raw packet was sent as an envelope frame")
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for explicit packet frame")
	}
}

func TestServePacketsFailsFastOnPermanentReadError(t *testing.T) {
	node := newTransportNode(t)
	sink := &transportSink{reads: [][]byte{{0}}}
	client := &Client{node: node, sink: sink, flows: conntrack.NewTable()}
	before := client.DataPlaneStats().OutboundDrops

	err := client.ServePackets(context.Background())
	if !errors.Is(err, io.ErrClosedPipe) {
		t.Fatalf("serve error = %v, want io.ErrClosedPipe", err)
	}
	if got := client.DataPlaneStats().OutboundDrops - before; got == 0 {
		t.Fatal("invalid queued packet was not counted as a drop")
	}
}
