package client

import (
	"bytes"
	"encoding/binary"
	"net"
	"testing"

	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/core/test"
	"github.com/netp2p/netp2p/internal/conntrack"
	"github.com/netp2p/netp2p/internal/model"
	"github.com/netp2p/netp2p/internal/packet"
)

// captureSink records the raw packets that reach the local network stack.
type captureSink struct {
	written [][]byte
}

func (sink *captureSink) ReadPacket() ([]byte, error) { return nil, nil }
func (sink *captureSink) WritePacket(raw []byte) error {
	sink.written = append(sink.written, append([]byte(nil), raw...))
	return nil
}
func (sink *captureSink) Close() error { return nil }

func randPeerID(t *testing.T) string {
	t.Helper()
	id, err := test.RandPeerID()
	if err != nil {
		t.Fatalf("rand peer id: %v", err)
	}
	return id.String()
}

// peerIDFromString restores the decoded peer.ID, mirroring what the transport
// hands the data plane on a real stream.
func peerIDFromString(t *testing.T, value string) peer.ID {
	t.Helper()
	id, err := peer.Decode(value)
	if err != nil {
		t.Fatalf("decode peer id %q: %v", value, err)
	}
	return id
}

// exitTestState builds a certified state with one subnet route whose gateway is
// an exit node in the "gateways" group and whose users are the "clients" group.
func exitTestState(gatewayID, sourceID string) model.NetworkState {
	return model.NetworkState{
		NetworkID: "net",
		Settings:  model.NetworkSettings{ExitNodeEnabled: true},
		Peers: []model.PeerRecord{
			{PeerID: sourceID, OverlayIP: "100.64.0.1", Groups: []string{"clients"}},
			{PeerID: gatewayID, OverlayIP: "100.64.0.2", Groups: []string{"gateways"}, IsExitNode: true},
		},
		Groups: []model.Group{
			{ID: "clients", PeerIDs: []string{sourceID}},
			{ID: "gateways", PeerIDs: []string{gatewayID}},
		},
		Routes: []model.Route{{
			ID: "corp", Destination: "10.10.0.0/16", RoutingGroup: "gateways",
			DistributionGroup: []string{"clients"}, Metric: 10, Masquerade: true,
		}},
	}
}

// synthUDPPacket builds a minimal valid IPv4/UDP datagram for data-plane tests.
func synthUDPPacket(t *testing.T, source, destination string, sourcePort, destinationPort uint16) []byte {
	t.Helper()
	src := net.ParseIP(source).To4()
	dst := net.ParseIP(destination).To4()
	if src == nil || dst == nil {
		t.Fatalf("invalid addresses %s -> %s", source, destination)
	}
	payload := make([]byte, 8)
	raw := make([]byte, 20+len(payload))
	raw[0] = 0x45
	binary.BigEndian.PutUint16(raw[2:4], uint16(len(raw)))
	raw[8] = 64
	raw[9] = packet.ProtocolUDP
	copy(raw[12:16], src)
	copy(raw[16:20], dst)
	binary.BigEndian.PutUint16(raw[20:22], sourcePort)
	binary.BigEndian.PutUint16(raw[22:24], destinationPort)
	return raw
}

// An exit node must hand a routed packet to the kernel (the fake sink) exactly
// once and remember the flow so the reply comes back through the overlay.
func TestExitNodeInjectsRoutedPacketIntoKernel(t *testing.T) {
	gatewayID := randPeerID(t)
	sourceID := randPeerID(t)
	sink := &captureSink{}
	netClient := &Client{sink: sink, flows: conntrack.NewTable()}
	netClient.self = model.PeerRecord{PeerID: gatewayID, OverlayIP: "100.64.0.2"}
	netClient.snapshot = model.SignedSnapshot{State: exitTestState(gatewayID, sourceID)}

	raw := synthUDPPacket(t, "100.64.0.1", "10.10.4.20", 4000, 4444)
	netClient.handleFrame(peerIDFromString(t, sourceID), raw)

	if len(sink.written) != 1 {
		t.Fatalf("kernel writes = %d, want 1", len(sink.written))
	}
	if !bytes.Equal(sink.written[0], raw) {
		t.Fatalf("kernel packet altered:\n got %x\nwant %x", sink.written[0], raw)
	}

	// The reply from the public subnet must be recognised as return traffic.
	reply := synthUDPPacket(t, "10.10.4.20", "100.64.0.1", 4444, 4000)
	flow, ok := packet.IPv4Packet(reply).Flow()
	if !ok {
		t.Fatal("reply has no flow")
	}
	if !netClient.flows.ReplyAllowed(conntrack.Key(flow)) {
		t.Fatal("exit node did not record the flow for the return path")
	}
}

// A source outside the route's distribution group must not be able to use the
// gateway as an open relay.
func TestExitNodeRejectsSourceOutsideDistributionGroup(t *testing.T) {
	gatewayID := randPeerID(t)
	state := exitTestState(gatewayID, randPeerID(t))
	strangerID := randPeerID(t)
	state.Peers = append(state.Peers, model.PeerRecord{PeerID: strangerID, OverlayIP: "100.64.0.9"})
	sink := &captureSink{}
	netClient := &Client{sink: sink, flows: conntrack.NewTable()}
	netClient.self = model.PeerRecord{PeerID: gatewayID, OverlayIP: "100.64.0.2"}
	netClient.snapshot = model.SignedSnapshot{State: state}

	raw := synthUDPPacket(t, "100.64.0.9", "10.10.4.20", 4000, 4444)
	netClient.handleFrame(peerIDFromString(t, strangerID), raw)

	if len(sink.written) != 0 {
		t.Fatalf("gateway forwarded for a disallowed source: %x", sink.written[0])
	}
}

// A peer that is not an exit node must drop packets addressed off-overlay
// instead of acting as a router.
func TestNonExitNodeDropsOffOverlayPacket(t *testing.T) {
	gatewayID := randPeerID(t)
	selfID := randPeerID(t)
	state := exitTestState(gatewayID, randPeerID(t))
	sink := &captureSink{}
	netClient := &Client{sink: sink, flows: conntrack.NewTable()}
	netClient.self = model.PeerRecord{PeerID: selfID, OverlayIP: "100.64.0.1"}
	netClient.snapshot = model.SignedSnapshot{State: state}

	raw := synthUDPPacket(t, "100.64.0.2", "10.10.4.20", 4000, 4444)
	netClient.handleFrame(peerIDFromString(t, gatewayID), raw)

	if len(sink.written) != 0 {
		t.Fatal("non-exit peer forwarded an off-overlay packet")
	}
}

// The return leg of a masqueraded flow arrives from the foreign address, not
// the gateway's overlay IP. It must be delivered to the kernel when it matches
// an outbound flow and the gateway really covers that address.
func TestGatewayReturnDeliveredForKnownFlow(t *testing.T) {
	sourceID := randPeerID(t)
	gatewayID := randPeerID(t)
	state := exitTestState(gatewayID, sourceID)
	sink := &captureSink{}
	netClient := &Client{sink: sink, flows: conntrack.NewTable()}
	netClient.self = model.PeerRecord{PeerID: sourceID, OverlayIP: "100.64.0.1"}
	netClient.snapshot = model.SignedSnapshot{State: state}

	outbound := synthUDPPacket(t, "100.64.0.1", "10.10.4.20", 4000, 4444)
	flow, ok := packet.IPv4Packet(outbound).Flow()
	if !ok {
		t.Fatal("outbound has no flow")
	}
	netClient.flows.Observe(conntrack.Key(flow))

	reply := synthUDPPacket(t, "10.10.4.20", "100.64.0.1", 4444, 4000)
	netClient.handleFrame(peerIDFromString(t, gatewayID), reply)

	if len(sink.written) != 1 {
		t.Fatalf("kernel writes = %d, want the gateway return", len(sink.written))
	}
}

// A gateway return with no matching outbound flow, or for an address the
// gateway does not cover, is spoofing and must be dropped.
func TestGatewayReturnRejectedWithoutFlowOrCoverage(t *testing.T) {
	sourceID := randPeerID(t)
	gatewayID := randPeerID(t)
	state := exitTestState(gatewayID, sourceID)
	sink := &captureSink{}
	netClient := &Client{sink: sink, flows: conntrack.NewTable()}
	netClient.self = model.PeerRecord{PeerID: sourceID, OverlayIP: "100.64.0.1"}
	netClient.snapshot = model.SignedSnapshot{State: state}
	remote := peerIDFromString(t, gatewayID)

	// No flow observed at all.
	netClient.handleFrame(remote, synthUDPPacket(t, "10.10.4.20", "100.64.0.1", 4444, 4000))

	// Flow observed, but the source is outside every route the gateway covers.
	outbound := synthUDPPacket(t, "100.64.0.1", "10.10.4.20", 4000, 4444)
	flow, _ := packet.IPv4Packet(outbound).Flow()
	netClient.flows.Observe(conntrack.Key(flow))
	netClient.handleFrame(remote, synthUDPPacket(t, "8.8.8.8", "100.64.0.1", 4444, 4000))

	if len(sink.written) != 0 {
		t.Fatalf("kernel writes = %d, want none for unverified gateway traffic", len(sink.written))
	}
}
