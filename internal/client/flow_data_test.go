package client

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/netp2p/netp2p/internal/conntrack"
	"github.com/netp2p/netp2p/internal/forward"
	"github.com/netp2p/netp2p/internal/model"
	"github.com/netp2p/netp2p/internal/p2p"
	"github.com/netp2p/netp2p/internal/transport"
)

func TestSendToPeerUsesWeightedFlowSelectionOverRealTransports(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	sourceNode := newTransportNode(t)
	managerANode := newTransportNode(t)
	managerBNode := newTransportNode(t)
	destinationNode := newTransportNode(t)
	sourceID := sourceNode.Host.ID().String()
	destinationID := destinationNode.Host.ID().String()
	managerAID := managerANode.Host.ID().String()
	managerBID := managerBNode.Host.ID().String()

	assignmentRecord := model.RouteAssignment{
		ID: "assignment", SourcePeerID: sourceID, DestinationPeerID: destinationID,
		Primary: model.PathSpec{
			ID: "via-a", Kind: model.PathKindViaManager, ManagerHops: []string{managerAID},
			RTTMilliseconds: 20, BandwidthMbps: 100, Confidence: .9,
		},
		Fallbacks: []model.PathSpec{{
			ID: "via-b", Kind: model.PathKindViaManager, ManagerHops: []string{managerBID},
			RTTMilliseconds: 22, BandwidthMbps: 100, Confidence: .9,
		}},
	}
	state := model.NetworkState{
		NetworkID: "flow-real-transport-test",
		Settings:  model.NetworkSettings{DirectPathEnabled: false, DefaultFlowClass: "throughput"},
		Peers: []model.PeerRecord{
			{PeerID: sourceID, OverlayIP: "100.64.0.1"},
			{PeerID: destinationID, OverlayIP: "100.64.0.2"},
			{PeerID: managerAID, OverlayIP: "100.64.0.3"},
			{PeerID: managerBID, OverlayIP: "100.64.0.4"},
		},
		Assignments: []model.RouteAssignment{assignmentRecord},
	}

	var mu sync.Mutex
	counts := map[string]int{}
	destinationForwarding := forward.NewTable(state, destinationID, func(peer.ID, forward.Envelope) error {
		return nil
	})
	destinationFrames := transport.NewWithEnvelope(ctx, destinationNode.Host, p2p.FrameProtocol,
		func(peer.ID, []byte) {},
		func(remote peer.ID, payload []byte) {
			envelope, err := forward.DecodeEnvelope(payload)
			if err != nil {
				t.Errorf("decode destination envelope: %v", err)
				return
			}
			delivered, err := destinationForwarding.Accept(remote, envelope)
			if err != nil {
				t.Errorf("accept destination envelope: %v", err)
				return
			}
			if delivered {
				mu.Lock()
				counts[envelope.Header.PathID]++
				mu.Unlock()
			}
		},
	)
	defer destinationFrames.Close()

	startManager := func(node *p2p.Node, managerID string) *transport.Transport {
		var frames *transport.Transport
		forwarding := forward.NewTable(state, managerID, func(remote peer.ID, envelope forward.Envelope) error {
			wire, err := forward.EncodeEnvelope(envelope)
			if err != nil {
				return err
			}
			return frames.SendEnvelope(remote, wire)
		})
		frames = transport.NewWithEnvelope(ctx, node.Host, p2p.FrameProtocol,
			func(peer.ID, []byte) {},
			func(remote peer.ID, payload []byte) {
				envelope, err := forward.DecodeEnvelope(payload)
				if err != nil {
					t.Errorf("decode manager envelope: %v", err)
					return
				}
				if _, err := forwarding.Accept(remote, envelope); err != nil {
					t.Errorf("accept manager envelope: %v", err)
				}
			},
		)
		return frames
	}
	managerAFrames := startManager(managerANode, managerAID)
	defer managerAFrames.Close()
	managerBFrames := startManager(managerBNode, managerBID)
	defer managerBFrames.Close()

	var sourceFrames *transport.Transport
	sourceForwarding := forward.NewTable(state, sourceID, func(remote peer.ID, envelope forward.Envelope) error {
		wire, err := forward.EncodeEnvelope(envelope)
		if err != nil {
			return err
		}
		return sourceFrames.SendEnvelope(remote, wire)
	})
	sourceFrames = transport.NewWithEnvelope(ctx, sourceNode.Host, p2p.FrameProtocol,
		func(peer.ID, []byte) {},
		func(peer.ID, []byte) { t.Error("source unexpectedly received a forwarded envelope") },
	)
	defer sourceFrames.Close()

	paths := newPathSelector(sourceForwarding, nil)
	if err := paths.syncSnapshot(model.SignedSnapshot{State: state}); err != nil {
		t.Fatal(err)
	}
	applyFlowEpoch(t, paths, state.NetworkID, 1, map[string]float64{"via-a": .5, "via-b": .5})
	netClient := &Client{
		node: sourceNode, sink: &transportSink{}, flows: conntrack.NewTable(),
		forwarding: sourceForwarding, paths: paths, frames: sourceFrames,
		snapshot: model.SignedSnapshot{State: state}, self: state.Peers[0],
	}

	connectHosts(t, sourceNode.Host, managerANode.Host)
	connectHosts(t, sourceNode.Host, managerBNode.Host)
	connectHosts(t, managerANode.Host, destinationNode.Host)
	connectHosts(t, managerBNode.Host, destinationNode.Host)

	const packetCount = 200
	for index := 0; index < packetCount; index++ {
		raw := synthUDPPacket(t, "100.64.0.1", "100.64.0.2", uint16(20000+index), 443)
		if !netClient.sendToPeer(state.Peers[1], raw) {
			t.Fatalf("send flow %d failed", index)
		}
	}

	deadline := time.Now().Add(5 * time.Second)
	for {
		mu.Lock()
		total := counts["via-a"] + counts["via-b"]
		mu.Unlock()
		if total == packetCount {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for real forwarded packets: %+v", counts)
		}
		time.Sleep(10 * time.Millisecond)
	}
	mu.Lock()
	defer mu.Unlock()
	if counts["via-a"] < 60 || counts["via-a"] > 140 || counts["via-b"] < 60 || counts["via-b"] > 140 {
		t.Fatalf("real transport path distribution = %v", counts)
	}
	if diagnostics := netClient.FlowDiagnostics(); diagnostics.ActiveFlows != packetCount {
		t.Fatalf("active real flows = %d, want %d", diagnostics.ActiveFlows, packetCount)
	}
}

func connectHosts(t *testing.T, left, right host.Host) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := left.Connect(ctx, peer.AddrInfo{ID: right.ID(), Addrs: right.Addrs()}); err != nil {
		t.Fatalf("connect %s to %s: %v", left.ID(), right.ID(), err)
	}
}
