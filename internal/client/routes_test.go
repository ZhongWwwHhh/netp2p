package client

import (
	"testing"

	"github.com/netp2p/netp2p/internal/model"
)

// A sink that records the routes it is asked to install.
type recordingSink struct {
	routes [][]string
}

func (sink *recordingSink) ReadPacket() ([]byte, error) { return nil, nil }
func (sink *recordingSink) WritePacket([]byte) error    { return nil }
func (sink *recordingSink) Close() error                { return nil }
func (sink *recordingSink) ReconcileRoutes(overlayIPs []string) error {
	sink.routes = append(sink.routes, append([]string(nil), overlayIPs...))
	return nil
}

// Routes must cover every peer, not just policy-allowed ones: the kernel needs
// a route to emit return traffic for a flow that was admitted inbound, and a
// one-way allow policy would otherwise strand the reply. Access control stays
// in the userspace policy check.
func TestRoutesCoverDeniedPeersToo(t *testing.T) {
	sink := &recordingSink{}
	netClient := &Client{sink: sink}
	netClient.self = model.PeerRecord{PeerID: "self", OverlayIP: "100.64.0.1"}
	netClient.snapshot = model.SignedSnapshot{State: model.NetworkState{
		Peers: []model.PeerRecord{
			{PeerID: "self", OverlayIP: "100.64.0.1"},
			{PeerID: "allowed", OverlayIP: "100.64.0.2"},
			{PeerID: "denied", OverlayIP: "100.64.0.3"},
			{PeerID: "no-address"},
		},
	}}

	netClient.ReconcileRoutes()

	if len(sink.routes) != 1 {
		t.Fatalf("reconcile called %d times, want 1", len(sink.routes))
	}
	routes := sink.routes[0]
	if len(routes) != 2 {
		t.Fatalf("routes = %v, want both remote peers", routes)
	}
	// Sorted, excludes self, and skips peers with no overlay address.
	if routes[0] != "100.64.0.2" || routes[1] != "100.64.0.3" {
		t.Fatalf("routes = %v, want [100.64.0.2 100.64.0.3]", routes)
	}
}

func TestRoutesIgnoreSinkWithoutKernelTable(t *testing.T) {
	// A userspace endpoint cannot install routes; reconcile must be a no-op
	// rather than an error.
	netClient := &Client{sink: &plainSink{}}
	netClient.self = model.PeerRecord{PeerID: "self"}
	netClient.ReconcileRoutes()
}

type plainSink struct{}

func (sink *plainSink) ReadPacket() ([]byte, error) { return nil, nil }
func (sink *plainSink) WritePacket([]byte) error    { return nil }
func (sink *plainSink) Close() error                { return nil }
