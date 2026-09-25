package forward

import (
	"testing"

	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/netp2p/netp2p/internal/model"
)

const sourceID = "12D3KooWNvDrQcY7ZsjaRkDtWMVzW6VEcahFzC77gTZEtzm8rD6d"

const destinationID = "12D3KooWNvDrQcY7ZsjaRkDtWMVzW6VEcahFzC77gTZEtzm8rD6d"

const managerHopID = "12D3KooWNvDrQcY7ZsjaRkDtWMVzW6VEcahFzC77gTZEtzm8rD6d"

func testState() model.NetworkState {
	return model.NetworkState{Assignments: []model.RouteAssignment{{
		ID: "assignment-1", SourcePeerID: sourceID, DestinationPeerID: destinationID,
		Primary: model.PathSpec{ID: "path-via", Kind: model.PathKindViaManager, ManagerHops: []string{managerHopID, managerHopID}},
	}}}
}

func TestSendAndForwardAlongCertifiedPath(t *testing.T) {
	state := testState()
	var sent []Envelope
	sender := func(remote peer.ID, envelope Envelope) error {
		sent = append(sent, envelope)
		return nil
	}
	sourceTable := NewTable(state, sourceID, sender)
	source, err := peer.Decode(sourceID)
	if err != nil {
		t.Fatal(err)
	}
	destination, err := peer.Decode(destinationID)
	if err != nil {
		t.Fatal(err)
	}
	if err := sourceTable.Send(source, destination, "assignment-1", "path-via", []byte("payload")); err != nil {
		t.Fatalf("send: %v", err)
	}
	if len(sent) != 1 || sent[0].Header.TTL != DefaultTTL {
		t.Fatalf("unexpected send %+v", sent)
	}

	managerTable := NewTable(state, managerHopID, sender)
	forwarded, err := managerTable.Accept(sent[0])
	if err != nil || forwarded {
		t.Fatalf("manager hop: forwarded=%v err=%v", forwarded, err)
	}
	if len(sent) != 2 || sent[1].Header.TTL != DefaultTTL-1 {
		t.Fatalf("unexpected forward %+v", sent)
	}
}

func TestAcceptRejectsUnknownAssignmentAndTTL(t *testing.T) {
	state := testState()
	sender := func(peer.ID, Envelope) error { return nil }
	table := NewTable(state, managerHopID, sender)
	base := Envelope{Header: Header{SourcePeerID: sourceID, DestinationPeerID: destinationID, AssignmentID: "assignment-1", PathID: "path-via", TTL: 1}}
	if _, err := table.Accept(base); err != nil {
		t.Fatalf("valid frame rejected: %v", err)
	}
	unknown := base
	unknown.Header.AssignmentID = "unknown"
	if _, err := table.Accept(unknown); err == nil {
		t.Fatal("unknown assignment accepted")
	}
	expired := base
	expired.Header.TTL = 0
	if _, err := table.Accept(expired); err != ErrTTLExceeded {
		t.Fatalf("expired frame error = %v", err)
	}
}
