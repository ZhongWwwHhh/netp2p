package forward

import (
	"crypto/rand"
	"testing"

	"github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/netp2p/netp2p/internal/model"
)

func benchmarkPeerID(b *testing.B) peer.ID {
	b.Helper()
	privateKey, _, err := crypto.GenerateEd25519Key(rand.Reader)
	if err != nil {
		b.Fatal(err)
	}
	identifier, err := peer.IDFromPrivateKey(privateKey)
	if err != nil {
		b.Fatal(err)
	}
	return identifier
}

func benchmarkForwardState(b *testing.B, assignments int) (model.NetworkState, peer.ID, peer.ID, peer.ID) {
	b.Helper()
	source := benchmarkPeerID(b)
	destination := benchmarkPeerID(b)
	manager := benchmarkPeerID(b)
	state := model.NetworkState{NetworkID: "benchmark"}
	state.Assignments = make([]model.RouteAssignment, assignments)
	for index := range state.Assignments {
		state.Assignments[index] = model.RouteAssignment{
			ID: "assignment", NetworkID: state.NetworkID,
			SourcePeerID: source.String(), DestinationPeerID: destination.String(),
			Primary: model.PathSpec{
				ID: "path", Kind: model.PathKindViaManager,
				ManagerHops: []string{manager.String()},
			},
		}
	}
	return state, source, destination, manager
}

func BenchmarkForwardTableReplace(b *testing.B) {
	state, source, _, _ := benchmarkForwardState(b, 128)
	table := NewTable(state, source.String(), func(peer.ID, Envelope) error { return nil })
	b.ReportAllocs()
	b.ResetTimer()
	for index := 0; index < b.N; index++ {
		table.Replace(state)
	}
}

func BenchmarkForwardTableSend(b *testing.B) {
	state, source, destination, _ := benchmarkForwardState(b, 128)
	table := NewTable(state, source.String(), func(peer.ID, Envelope) error { return nil })
	payload := make([]byte, 1200)
	b.SetBytes(int64(len(payload)))
	b.ReportAllocs()
	b.ResetTimer()
	for index := 0; index < b.N; index++ {
		if err := table.Send(source, destination, "assignment", "path", payload); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkForwardTableAccept(b *testing.B) {
	state, source, destination, manager := benchmarkForwardState(b, 128)
	table := NewTable(state, manager.String(), func(peer.ID, Envelope) error { return nil })
	payload := make([]byte, 1200)
	envelope := Envelope{
		Header: Header{
			SourcePeerID: source.String(), DestinationPeerID: destination.String(),
			AssignmentID: "assignment", PathID: "path", TTL: DefaultTTL,
		},
		Payload: payload,
	}
	b.SetBytes(int64(len(payload)))
	b.ReportAllocs()
	b.ResetTimer()
	for index := 0; index < b.N; index++ {
		if _, err := table.Accept(source, envelope); err != nil {
			b.Fatal(err)
		}
	}
}
