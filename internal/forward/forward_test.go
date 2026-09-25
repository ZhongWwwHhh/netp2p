package forward

import (
	"errors"
	"testing"

	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/netp2p/netp2p/internal/model"
)

// Distinct, valid libp2p PeerIDs keep source, destination and the two manager
// hops distinguishable; identical test identities would hide spoofing bugs.
const (
	sourceID      = "12D3KooWGbPJsds7aL2oM7ZgPACEcvoiUxsiYTDzCh9a5C8uB76m"
	destinationID = "12D3KooWSAoLjUuFPUYkCf7S4xxYr8Hhz8HQr3t9DTanRc9L8AWG"
	firstHopID    = "12D3KooWNC1cKisChtyY5ZbeJBV8Xqqaj1k8gxGJPt2u2JtCAPp4"
	secondHopID   = "12D3KooWGeZkArb2TCBHanoBgz84uEbgqH3p1L1SA3ZFqznetjw3"
)

func testState() model.NetworkState {
	return model.NetworkState{Assignments: []model.RouteAssignment{{
		ID: "assignment-1", SourcePeerID: sourceID, DestinationPeerID: destinationID,
		Primary: model.PathSpec{
			ID: "path-via", Kind: model.PathKindViaManager,
			ManagerHops: []string{firstHopID, secondHopID},
		},
	}}}
}

func TestSendAndForwardAlongCertifiedPath(t *testing.T) {
	state := testState()
	var sent []Envelope
	sender := func(_ peer.ID, envelope Envelope) error {
		sent = append(sent, envelope)
		return nil
	}
	source, err := peer.Decode(sourceID)
	if err != nil {
		t.Fatal(err)
	}
	destination, err := peer.Decode(destinationID)
	if err != nil {
		t.Fatal(err)
	}
	firstHop, err := peer.Decode(firstHopID)
	if err != nil {
		t.Fatal(err)
	}
	secondHop, err := peer.Decode(secondHopID)
	if err != nil {
		t.Fatal(err)
	}

	sourceTable := NewTable(state, sourceID, sender)
	if err := sourceTable.Send(source, destination, "assignment-1", "path-via", []byte("payload")); err != nil {
		t.Fatalf("send: %v", err)
	}
	if len(sent) != 1 || sent[0].Header.TTL != DefaultTTL {
		t.Fatalf("unexpected send %+v", sent)
	}

	firstTable := NewTable(state, firstHopID, sender)
	forwarded, err := firstTable.Accept(source, sent[0])
	if err != nil || forwarded {
		t.Fatalf("first hop: forwarded=%v err=%v", forwarded, err)
	}
	if len(sent) != 2 || sent[1].Header.TTL != DefaultTTL-1 {
		t.Fatalf("unexpected first forward %+v", sent)
	}

	secondTable := NewTable(state, secondHopID, sender)
	forwarded, err = secondTable.Accept(firstHop, sent[1])
	if err != nil || forwarded {
		t.Fatalf("second hop: forwarded=%v err=%v", forwarded, err)
	}
	if len(sent) != 3 || sent[2].Header.TTL != DefaultTTL-2 {
		t.Fatalf("unexpected second forward %+v", sent)
	}

	// A manager that is the destination accepts only from the last hop.
	destinationTable := NewTable(state, destinationID, sender)
	delivered, err := destinationTable.Accept(secondHop, sent[2])
	if err != nil || !delivered {
		t.Fatalf("destination: delivered=%v err=%v", delivered, err)
	}
	if forwarded, _ := firstTable.Stats(); forwarded != 1 {
		t.Fatalf("first hop forwarded = %d, want 1", forwarded)
	}
}

func TestAcceptRejectsUnknownAssignmentAndTTL(t *testing.T) {
	table := NewTable(testState(), firstHopID, func(peer.ID, Envelope) error { return nil })
	source, err := peer.Decode(sourceID)
	if err != nil {
		t.Fatal(err)
	}
	base := Envelope{Header: Header{SourcePeerID: sourceID, DestinationPeerID: destinationID, AssignmentID: "assignment-1", PathID: "path-via", TTL: 1}}
	if _, err := table.Accept(source, base); err != nil {
		t.Fatalf("valid frame rejected: %v", err)
	}
	unknown := base
	unknown.Header.AssignmentID = "unknown"
	if _, err := table.Accept(source, unknown); !errors.Is(err, ErrNoAssignment) {
		t.Fatalf("unknown assignment error = %v", err)
	}
	expired := base
	expired.Header.TTL = 0
	if _, err := table.Accept(source, expired); !errors.Is(err, ErrTTLExceeded) {
		t.Fatalf("expired frame error = %v", err)
	}
	spoofed := base
	spoofed.Header.SourcePeerID = destinationID
	if _, err := table.Accept(source, spoofed); !errors.Is(err, ErrInvalidSource) {
		t.Fatalf("spoofed source error = %v", err)
	}
}

// TestAcceptRejectsWrongPredecessor ensures a hop only accepts frames from the
// identity the certified path names as its predecessor: a manager that sees a
// frame from any other peer must drop it, even with a valid header.
func TestAcceptRejectsWrongPredecessor(t *testing.T) {
	state := testState()
	table := NewTable(state, secondHopID, func(peer.ID, Envelope) error { return nil })
	envelope := Envelope{Header: Header{
		SourcePeerID: sourceID, DestinationPeerID: destinationID,
		AssignmentID: "assignment-1", PathID: "path-via", TTL: 3,
	}}

	stranger, err := peer.Decode(destinationID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := table.Accept(stranger, envelope); !errors.Is(err, ErrInvalidSource) {
		t.Fatalf("frame from wrong predecessor error = %v, want ErrInvalidSource", err)
	}

	predecessor, err := peer.Decode(firstHopID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := table.Accept(predecessor, envelope); err != nil {
		t.Fatalf("frame from certified predecessor rejected: %v", err)
	}
}
