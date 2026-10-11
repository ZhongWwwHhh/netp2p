package client

import (
	"net"
	"testing"

	"github.com/netp2p/netp2p/internal/model"
)

func subnetState() model.NetworkState {
	return model.NetworkState{
		NetworkID: "net",
		Settings:  model.NetworkSettings{ExitNodeEnabled: true},
		Peers: []model.PeerRecord{
			{PeerID: "self", OverlayIP: "100.64.0.1", Groups: []string{"clients"}},
			{PeerID: "gw-b", OverlayIP: "100.64.0.3", Groups: []string{"gateways"}, IsExitNode: true},
			{PeerID: "gw-a", OverlayIP: "100.64.0.2", Groups: []string{"gateways"}, IsExitNode: true},
		},
		Groups: []model.Group{
			{ID: "clients", PeerIDs: []string{"self"}},
			{ID: "gateways", PeerIDs: []string{"gw-a", "gw-b"}},
		},
		Routes: []model.Route{{
			ID: "corp", Destination: "10.10.0.0/16", RoutingGroup: "gateways",
			DistributionGroup: []string{"clients"}, Metric: 10, Masquerade: true,
		}},
	}
}

func TestSubnetGatewaySelectsDeterministicExitNode(t *testing.T) {
	netClient := &Client{}
	netClient.self = model.PeerRecord{PeerID: "self", OverlayIP: "100.64.0.1"}
	netClient.snapshot = model.SignedSnapshot{State: subnetState()}

	gateway, ok := netClient.subnetGateway(net.ParseIP("10.10.4.20"))
	if !ok {
		t.Fatal("expected a gateway for a routed destination")
	}
	if gateway.PeerID != "gw-a" {
		t.Fatalf("gateway = %s, want the lowest peer id gw-a", gateway.PeerID)
	}
}

func TestSubnetGatewayIgnoresUnroutedDestination(t *testing.T) {
	netClient := &Client{}
	netClient.self = model.PeerRecord{PeerID: "self", OverlayIP: "100.64.0.1"}
	netClient.snapshot = model.SignedSnapshot{State: subnetState()}
	if _, ok := netClient.subnetGateway(net.ParseIP("203.0.113.53")); ok {
		t.Fatal("unrouted destination must not resolve to a gateway")
	}
}

func TestSubnetGatewayDisabledBySettings(t *testing.T) {
	state := subnetState()
	state.Settings.ExitNodeEnabled = false
	netClient := &Client{}
	netClient.self = model.PeerRecord{PeerID: "self"}
	netClient.snapshot = model.SignedSnapshot{State: state}
	if _, ok := netClient.subnetGateway(net.ParseIP("10.10.4.20")); ok {
		t.Fatal("exit routing must be disabled when the setting is off")
	}
}

func TestExitNodeForPacketHonoursDistributionGroup(t *testing.T) {
	netClient := &Client{}
	netClient.self = model.PeerRecord{PeerID: "gw-a", OverlayIP: "100.64.0.2"}
	netClient.snapshot = model.SignedSnapshot{State: subnetState()}
	allowed := model.PeerRecord{PeerID: "self", OverlayIP: "100.64.0.1"}
	if !netClient.exitNodeForPacket(allowed, net.ParseIP("10.10.4.20")) {
		t.Fatal("gateway must forward for a peer in the distribution group")
	}
	outsider := model.PeerRecord{PeerID: "stranger", OverlayIP: "100.64.0.9"}
	if netClient.exitNodeForPacket(outsider, net.ParseIP("10.10.4.20")) {
		t.Fatal("gateway must reject a source outside the distribution group")
	}
	if netClient.exitNodeForPacket(allowed, net.ParseIP("203.0.113.53")) {
		t.Fatal("gateway must not forward destinations outside the route")
	}
}

func TestExitRoutesListsOwnedRoutes(t *testing.T) {
	netClient := &Client{}
	netClient.self = model.PeerRecord{PeerID: "gw-a", OverlayIP: "100.64.0.2"}
	netClient.snapshot = model.SignedSnapshot{State: subnetState()}
	routes := netClient.exitRoutes()
	if len(routes) != 1 || routes[0].Destination != "10.10.0.0/16" {
		t.Fatalf("exit routes = %+v, want the corp route", routes)
	}

	netClient.self = model.PeerRecord{PeerID: "self", OverlayIP: "100.64.0.1"}
	if got := netClient.exitRoutes(); len(got) != 0 {
		t.Fatalf("a non-gateway must not serve exit routes: %+v", got)
	}
}
