package client

import (
	"context"
	"fmt"
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

func TestScaleManagerSelectionUsesActiveManager(t *testing.T) {
	managers := scaleTestManagers(t)
	snapshot := scaleManagerSnapshot(managers)
	active := managers[1].ID

	manager, managerID, ok := forwardingManagerForSnapshot(snapshot, managers, active, "client-key")
	if !ok || manager != active || managerID != "manager-1" {
		t.Fatalf("selection=(%v,%q,%v), want active manager %q", manager, managerID, ok, active)
	}
}

func TestScaleManagerFallbackIsWeightDistributed(t *testing.T) {
	managers := scaleTestManagers(t)
	snapshot := scaleManagerSnapshot(managers)
	counts := make(map[string]int, len(managers))
	for index := 0; index < 1000; index++ {
		manager, _, ok := forwardingManagerForSnapshot(snapshot, managers, "", fmt.Sprintf("client-%d", index))
		if !ok {
			t.Fatal("no forwarding manager selected")
		}
		counts[manager.String()]++
	}
	if len(counts) != len(managers) {
		t.Fatalf("weighted selection used %d of %d managers: %v", len(counts), len(managers), counts)
	}
	for _, manager := range managers {
		if counts[manager.ID.String()] == 0 {
			t.Fatalf("manager %s received no traffic: %v", manager.ID, counts)
		}
	}
}

func TestScaleRoutingDomainUsesActiveManagerScope(t *testing.T) {
	managers := scaleTestManagers(t)
	state := model.NetworkState{
		Groups: []model.Group{
			{ID: "sources", PeerIDs: []string{transportSourceID}},
			{ID: "destinations", PeerIDs: []string{transportManagerID}},
		},
	}
	for index := range managers {
		state.RoutingDomains = append(state.RoutingDomains, model.RoutingDomainAuthorization{
			ID: fmt.Sprintf("domain-%d", index),
			Key: model.RoutingDomainKey{
				SourceManagerID: fmt.Sprintf("manager-%d", index), SourceGroupID: "sources",
				DestinationScope: model.DestinationScopeGroup + "destinations", FlowClass: string(FlowClassLatency),
			},
			PathFamilyIDs: []string{fmt.Sprintf("family-%d", index)},
		})
	}
	self := model.PeerRecord{PeerID: transportSourceID, Groups: []string{"sources"}}
	destination := model.PeerRecord{PeerID: transportManagerID, Groups: []string{"destinations"}}

	domain, ok := scaleRoutingDomain(state, self, destination, transportPayload(t), FlowClassLatency, "manager-1", false)
	if !ok || domain.ID != "domain-1" {
		t.Fatalf("domain=(%q,%v), want domain-1", domain.ID, ok)
	}
}

func TestScaleRoutingDomainUsesSenderScopedReturnDomain(t *testing.T) {
	state := model.NetworkState{
		Groups: []model.Group{
			{ID: "clients-a", PeerIDs: []string{transportSourceID}},
			{ID: "clients-b", PeerIDs: []string{transportSpoofID}},
		},
		RoutingDomains: []model.RoutingDomainAuthorization{{
			ID: "manager-1/clients-a/group:clients-b/latency",
			Key: model.RoutingDomainKey{
				SourceManagerID: "manager-1", SourceGroupID: "clients-a",
				DestinationScope: model.DestinationScopeGroup + "clients-b", FlowClass: string(FlowClassLatency),
			},
			PathFamilyIDs: []string{"family-return"},
		}},
	}
	self := model.PeerRecord{PeerID: transportSpoofID, OverlayIP: "100.64.0.2", Groups: []string{"clients-b"}}
	destination := model.PeerRecord{PeerID: transportSourceID, OverlayIP: "100.64.0.1", Groups: []string{"clients-a"}}
	payload, err := packet.BuildEchoRequest(
		net.ParseIP("100.64.0.2"), net.ParseIP("100.64.0.1"), 0x5150, 1, []byte("return"),
	)
	if err != nil {
		t.Fatal(err)
	}

	if _, ok := scaleRoutingDomain(state, self, destination, payload, FlowClassLatency, "manager-1", true); ok {
		t.Fatal("return traffic reused the forward-only routing domain")
	}

	state.RoutingDomains = append(state.RoutingDomains, model.RoutingDomainAuthorization{
		ID: "manager-1/clients-b/group:clients-a/latency",
		Key: model.RoutingDomainKey{
			SourceManagerID: "manager-1", SourceGroupID: "clients-b",
			DestinationScope: model.DestinationScopeGroup + "clients-a", FlowClass: string(FlowClassLatency),
		},
		PathFamilyIDs: []string{"family-return"},
	})
	domain, ok := scaleRoutingDomain(state, self, destination, payload, FlowClassLatency, "manager-1", true)
	if !ok || domain.ID != "manager-1/clients-b/group:clients-a/latency" {
		t.Fatalf("return domain=(%q,%v), want the sender-scoped reverse domain", domain.ID, ok)
	}
	domain, ok = scaleRoutingDomain(state, self, destination, payload, FlowClassLatency, "manager-1", false)
	if !ok || domain.ID != "manager-1/clients-b/group:clients-a/latency" {
		t.Fatalf("new-flow domain=(%q,%v), want the sender-scoped reverse domain", domain.ID, ok)
	}
}

func TestHandleScaleEnvelopeAcceptsOnlyCommitteeManager(t *testing.T) {
	node := newTransportNode(t)
	state := transportState(node.Host.ID().String())
	client, sink := newDestinationClient(t, node, state)
	client.snapshot.Committee = []model.CommitteeMember{{
		ID: "manager", PeerID: transportManagerID, ForwardingEnabled: true,
	}}

	flowHash, ok := packet.FlowHash(transportPayload(t))
	if !ok {
		t.Fatal("test payload is not a valid IP packet")
	}
	envelope := forward.ScaleEnvelope{
		Header: forward.ScaleHeader{
			SourcePeerID: transportSourceID, DestinationPeerID: node.Host.ID().String(),
			RoutingDomainID: "domain", PathFamilyID: "family", PathInstanceID: "manager",
			FlowClass: string(FlowClassLatency), FlowHash: flowHash, TTL: forward.DefaultTTL,
		},
		Payload: transportPayload(t),
	}
	wire, err := forward.EncodeScaleEnvelope(envelope)
	if err != nil {
		t.Fatal(err)
	}

	spoof, err := peer.Decode(transportSpoofID)
	if err != nil {
		t.Fatal(err)
	}
	client.handleScaleEnvelope(spoof, wire)
	if len(sink.written) != 0 {
		t.Fatalf("non-committee sender delivered %d packets", len(sink.written))
	}

	manager, err := peer.Decode(transportManagerID)
	if err != nil {
		t.Fatal(err)
	}
	client.handleScaleEnvelope(manager, wire)
	if len(sink.written) != 1 {
		t.Fatalf("committee manager delivered %d packets, want 1", len(sink.written))
	}
}

func TestSendScaleUsesSynchronousManagerStream(t *testing.T) {
	managerNode := newTransportNode(t)
	clientNode := newTransportNode(t)
	managerAddress := managerNode.Addresses()[0]
	managerInfo, err := peer.AddrInfoFromString(managerAddress)
	if err != nil {
		t.Fatal(err)
	}
	connectContext, cancelConnect := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancelConnect()
	if err := clientNode.Host.Connect(connectContext, *managerInfo); err != nil {
		t.Fatalf("connect manager: %v", err)
	}

	received := make(chan forward.ScaleEnvelope, 1)
	managerTransport := transport.NewWithEnvelope(
		context.Background(), managerNode.Host, p2p.FrameProtocol, nil,
		func(_ peer.ID, wire []byte) error {
			envelope, err := forward.DecodeScaleEnvelope(wire)
			if err != nil {
				return err
			}
			received <- envelope
			return nil
		},
	)
	defer managerTransport.Close()
	clientFrames := transport.New(context.Background(), clientNode.Host, p2p.FrameProtocol, nil)
	defer clientFrames.Close()

	state := model.NetworkState{
		Settings: model.NetworkSettings{ViaManagerEnabled: true, DirectPathEnabled: false},
		Groups: []model.Group{
			{ID: "sources", PeerIDs: []string{clientNode.Host.ID().String()}},
			{ID: "destinations", PeerIDs: []string{transportSpoofID}},
		},
		RoutingDomains: []model.RoutingDomainAuthorization{{
			ID: "manager-1/sources/group:destinations/latency",
			Key: model.RoutingDomainKey{
				SourceManagerID: "manager-1", SourceGroupID: "sources",
				DestinationScope: model.DestinationScopeGroup + "destinations",
				FlowClass:        string(FlowClassLatency),
			},
			PathFamilyIDs: []string{"family"},
		}},
	}
	self := model.PeerRecord{PeerID: clientNode.Host.ID().String(), OverlayIP: "100.64.0.1", Groups: []string{"sources"}}
	destination := model.PeerRecord{PeerID: transportSpoofID, OverlayIP: "100.64.0.2", Groups: []string{"destinations"}}
	client := &Client{
		node: clientNode, sink: &transportSink{}, flows: conntrack.NewTable(),
		snapshot: model.SignedSnapshot{State: state, Committee: []model.CommitteeMember{{
			ID: "manager-1", PeerID: managerInfo.ID.String(), ForwardingEnabled: true,
		}}},
		self: self, manager: *managerInfo, managers: []peer.AddrInfo{*managerInfo},
		frames: clientFrames,
	}

	selected, status, err := client.sendScale(destination, transportPayload(t), FlowClassLatency, false)
	if err != nil {
		t.Fatalf("sendScale: %v", err)
	}
	if selected != managerInfo.ID || !status.OK || status.PathID != "global-scale" {
		t.Fatalf("selection=(%v,%+v), want manager %s and certified global-scale", selected, status, managerInfo.ID)
	}

	select {
	case envelope := <-received:
		if envelope.Header.SourcePeerID != self.PeerID ||
			envelope.Header.DestinationPeerID != destination.PeerID ||
			envelope.Header.RoutingDomainID != state.RoutingDomains[0].ID {
			t.Fatalf("unexpected scale envelope header: %+v", envelope.Header)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for synchronous scale frame")
	}
}

func scaleTestManagers(t *testing.T) []peer.AddrInfo {
	t.Helper()
	values := []string{transportSourceID, transportSpoofID, transportManagerID}
	managers := make([]peer.AddrInfo, 0, len(values))
	for _, value := range values {
		id, err := peer.Decode(value)
		if err != nil {
			t.Fatal(err)
		}
		managers = append(managers, peer.AddrInfo{ID: id})
	}
	return managers
}

func scaleManagerSnapshot(managers []peer.AddrInfo) model.SignedSnapshot {
	committee := make([]model.CommitteeMember, 0, len(managers))
	for index, manager := range managers {
		committee = append(committee, model.CommitteeMember{
			ID: fmt.Sprintf("manager-%d", index), PeerID: manager.ID.String(), ForwardingEnabled: true,
		})
	}
	return model.SignedSnapshot{Committee: committee}
}
