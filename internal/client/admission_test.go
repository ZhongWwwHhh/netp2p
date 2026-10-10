package client

import (
	"testing"

	"github.com/netp2p/netp2p/internal/model"
)

func TestAdmissionProbeSkipsPolicyDeniedDirection(t *testing.T) {
	node := newTransportNode(t)
	state := transportState(node.Host.ID().String())
	state.Assignments = []model.RouteAssignment{{
		ID:           "reverse-assignment",
		SourcePeerID: node.Host.ID().String(), DestinationPeerID: transportSourceID,
		Primary: model.PathSpec{
			ID: "via-manager", Kind: model.PathKindViaManager,
			ManagerHops: []string{transportManagerID},
		},
	}}
	client, _ := newDestinationClient(t, node, state)
	snapshot := model.SignedSnapshot{State: state, Height: 1}
	if err := client.paths.syncSnapshot(snapshot); err != nil {
		t.Fatalf("sync path selector: %v", err)
	}

	client.runAdmissionProbe(snapshot, node.Host.ID().String())

	if _, exists := client.paths.admissions["via-manager"]; exists {
		t.Fatal("policy-denied admission probe recorded a path failure")
	}
	if len(client.admissionQueue) != 0 {
		t.Fatalf("policy-denied admission probe queued %d reports", len(client.admissionQueue))
	}
}
