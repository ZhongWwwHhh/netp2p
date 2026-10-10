package bft

import (
	"encoding/json"
	"fmt"
	"testing"

	"github.com/netp2p/netp2p/internal/model"
	"github.com/netp2p/netp2p/internal/wire"
	"github.com/netp2p/netp2p/internal/wire/pb"
	"google.golang.org/protobuf/proto"
)

func benchmarkSnapshot() model.SignedSnapshot {
	const peers = 1000
	state := model.NetworkState{
		NetworkID: "benchmark", OverlayCIDR: "100.64.0.0/16", NextIPOffset: 10,
	}
	state.Peers = make([]model.PeerRecord, peers)
	for index := range state.Peers {
		state.Peers[index] = model.PeerRecord{
			PeerID: fmt.Sprintf("peer-%04d", index), OverlayIP: fmt.Sprintf("100.64.%d.%d", index/250, index%250+1),
			Groups: []string{fmt.Sprintf("group-%03d", index%128)}, Hostname: fmt.Sprintf("peer-%04d", index),
			OS: "linux", ClientVersion: "3.0.0", DNSLabel: fmt.Sprintf("peer-%04d", index),
		}
	}
	state.Groups = make([]model.Group, 128)
	for index := range state.Groups {
		state.Groups[index] = model.Group{ID: fmt.Sprintf("group-%03d", index), Managed: true, Issued: model.GroupIssuedAPI}
	}
	state.Policies = make([]model.Policy, 128)
	for index := range state.Policies {
		state.Policies[index] = model.Policy{
			ID: fmt.Sprintf("policy-%03d", index), SourceGroups: []string{fmt.Sprintf("group-%03d", index)},
			DestinationGroups: []string{fmt.Sprintf("group-%03d", (index+1)%128)},
			Services:          []model.Service{{Protocol: "tcp", StartPort: 1, EndPort: 65535}},
			Effect:            model.EffectAllow, Direction: model.DirectionBidirectional,
		}
	}
	state.Routes = make([]model.Route, 128)
	for index := range state.Routes {
		state.Routes[index] = model.Route{
			ID: fmt.Sprintf("route-%03d", index), Destination: fmt.Sprintf("10.%d.0.0/16", index%250),
			RoutingGroup: fmt.Sprintf("group-%03d", index), DistributionGroup: []string{fmt.Sprintf("group-%03d", (index+1)%128)},
		}
	}
	transition := model.StateTransition{Type: TransitionGenesis}
	return model.SignedSnapshot{State: state, Transition: transition}
}

func BenchmarkSnapshotClientViewHash(b *testing.B) {
	snapshot := benchmarkSnapshot()
	b.ReportAllocs()
	b.ResetTimer()
	for index := 0; index < b.N; index++ {
		_ = ClientViewHash(snapshot.State, snapshot.Transition)
	}
}

func BenchmarkSnapshotSyncPath(b *testing.B) {
	snapshot := benchmarkSnapshot()
	clientSnapshot := model.ClientSnapshot(snapshot)
	encoded, err := proto.Marshal(wire.SignedSnapshotToProto(clientSnapshot))
	if err != nil {
		b.Fatal(err)
	}
	b.SetBytes(int64(len(encoded)))
	b.ReportAllocs()
	b.ResetTimer()
	for index := 0; index < b.N; index++ {
		client := model.ClientSnapshot(snapshot)
		message := wire.SignedSnapshotToProto(client)
		raw, err := proto.Marshal(message)
		if err != nil {
			b.Fatal(err)
		}
		var decoded pb.SignedSnapshot
		if err := proto.Unmarshal(raw, &decoded); err != nil {
			b.Fatal(err)
		}
		restored := wire.SignedSnapshotFromProto(&decoded)
		_ = ClientViewHash(restored.State, restored.Transition)
	}
}

func BenchmarkSnapshotJSONSize(b *testing.B) {
	snapshot := benchmarkSnapshot()
	clientSnapshot := model.ClientSnapshot(snapshot)
	encoded, err := json.Marshal(clientSnapshot)
	if err != nil {
		b.Fatal(err)
	}
	b.SetBytes(int64(len(encoded)))
	b.ReportAllocs()
	b.ResetTimer()
	for index := 0; index < b.N; index++ {
		if _, err := json.Marshal(model.ClientSnapshot(snapshot)); err != nil {
			b.Fatal(err)
		}
	}
}
