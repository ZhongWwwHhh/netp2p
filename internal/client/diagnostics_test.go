package client

import (
	"strings"
	"sync"
	"testing"

	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/netp2p/netp2p/internal/model"
)

func TestSendToPeerRecordsAssignmentMissing(t *testing.T) {
	node := newTransportNode(t)
	state := transportState(node.Host.ID().String())
	state.Assignments = nil
	client, _ := newDestinationClient(t, node, state)

	if client.sendToPeer(client.self, transportPayload(t)) {
		t.Fatal("packet was delivered without a certified assignment")
	}

	diagnostics := client.PathDiagnostics()
	if diagnostics.LastState != string(PathSelectionAssignmentMissing) {
		t.Fatalf("last path state = %q, want %q", diagnostics.LastState, PathSelectionAssignmentMissing)
	}
	if diagnostics.LastError == "" || !strings.Contains(diagnostics.LastError, node.Host.ID().String()) {
		t.Fatalf("last path error does not identify destination: %q", diagnostics.LastError)
	}
	if !strings.Contains(diagnostics.LastOutboundDropReason, "assignment-missing") ||
		!strings.Contains(diagnostics.LastOutboundDropReason, node.Host.ID().String()) {
		t.Fatalf("last outbound drop reason = %q", diagnostics.LastOutboundDropReason)
	}
	if action := client.NextAction(); !strings.Contains(action, "assignment-missing") {
		t.Fatalf("next action = %q, want the missing-assignment drop reason", action)
	}
}

func TestPathDiagnosticsAreConcurrencySafe(t *testing.T) {
	client := &Client{}
	destination, err := peer.Decode(transportSourceID)
	if err != nil {
		t.Fatal(err)
	}
	status := failedSelection(PathSelectionAssignmentMissing, ErrAssignmentMissing)

	const workers = 8
	var done sync.WaitGroup
	done.Add(workers)
	for range workers {
		go func() {
			defer done.Done()
			for range 20 {
				client.recordPathSelection(destination, status)
				client.markOutboundDrop("assignment-missing to peer")
				_ = client.PathDiagnostics()
				_ = client.NextAction()
				client.clearOutboundDrop()
				client.recordPathSelection(destination, successfulSelection(model.RouteAssignment{}, model.PathSpec{}))
			}
		}()
	}
	done.Wait()

	diagnostics := client.PathDiagnostics()
	if diagnostics.LastState != string(PathSelectionCertified) || diagnostics.LastOutboundDropReason != "" {
		t.Fatalf("diagnostics after successful selection = %+v", diagnostics)
	}
}

func TestPathDiagnosticsExposeGlobalScaleSelection(t *testing.T) {
	client := &Client{}
	destination, err := peer.Decode(transportSourceID)
	if err != nil {
		t.Fatal(err)
	}

	client.recordPathSelection(destination, PathSelectionStatus{
		State: PathSelectionCertified, PathID: "global-scale", Kind: model.PathKindViaManager,
		ManagerPeerID: transportManagerID, RoutingDomainID: "domain-a",
		Certified: true, OK: true, FlowClass: FlowClassLatency,
	})

	diagnostics := client.PathDiagnostics()
	if diagnostics.LastState != string(PathSelectionCertified) ||
		diagnostics.LastPathID != "global-scale" ||
		diagnostics.LastKind != string(model.PathKindViaManager) ||
		diagnostics.LastManagerPeerID != transportManagerID ||
		diagnostics.LastRoutingDomainID != "domain-a" {
		t.Fatalf("global-scale diagnostics = %+v", diagnostics)
	}
}
