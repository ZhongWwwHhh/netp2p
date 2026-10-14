package manager

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/netp2p/netp2p/internal/bft"
	"github.com/netp2p/netp2p/internal/forward"
	"github.com/netp2p/netp2p/internal/link"
	"github.com/netp2p/netp2p/internal/model"
	"github.com/netp2p/netp2p/internal/p2p"
	"github.com/netp2p/netp2p/internal/packet"
	"github.com/netp2p/netp2p/internal/path"
)

func TestHandleScaleWireRecordsDemandOnlyAfterAuthorization(t *testing.T) {
	ctx := context.Background()
	const sourceID = "12D3KooWGbPJsds7aL2oM7ZgPACEcvoiUxsiYTDzCh9a5C8uB76m"
	const destinationID = "12D3KooWSAoLjUuFPUYkCf7S4xxYr8Hhz8HQr3t9DTanRc9L8AWG"

	seed := int64(901)
	privateKey := bft.SeededPrivateKey(seed)
	libp2pKey, _, err := crypto.KeyPairFromStdKey(&privateKey)
	if err != nil {
		t.Fatal(err)
	}
	managerPeer, err := peer.IDFromPrivateKey(libp2pKey)
	if err != nil {
		t.Fatal(err)
	}
	node, err := p2p.New(ctx, p2p.Config{IdentitySeed: seed})
	if err != nil {
		t.Fatal(err)
	}
	defer node.Close()

	member := model.CommitteeMember{ID: "A", PeerID: managerPeer.String(), KeySeed: seed, ForwardingEnabled: true}
	state := model.NetworkState{
		NetworkID: "scale-demand-test", OverlayCIDR: "100.64.0.0/24",
		CommitteeConfig: model.CommitteeConfig{Threshold: 1, Size: 1},
		Peers: []model.PeerRecord{
			{PeerID: sourceID, OverlayIP: "100.64.0.1", Groups: []string{"sources"}},
			{PeerID: destinationID, OverlayIP: "100.64.0.2", Groups: []string{"destinations"}},
		},
		Groups: []model.Group{
			{ID: "sources", PeerIDs: []string{sourceID}},
			{ID: "destinations", PeerIDs: []string{destinationID}},
		},
		Policies: []model.Policy{{
			ID: "allow", SourceGroups: []string{"sources"}, DestinationGroups: []string{"destinations"},
			Services: []model.Service{{Protocol: "icmp"}}, Effect: model.EffectAllow,
		}},
		PathFamilies: []model.PathFamily{{
			ID: "family-a", Kind: model.PathKindViaManager, ManagerHops: []string{managerPeer.String()},
			SourceGroups: []string{"sources"}, DestinationScopes: []string{"group:destinations"},
			FlowClasses: []string{string(path.FlowLatency)},
		}},
		RoutingDomains: []model.RoutingDomainAuthorization{{
			ID: "domain-a",
			Key: model.RoutingDomainKey{
				SourceManagerID: "A", SourceGroupID: "sources",
				DestinationScope: model.DestinationScopeGroup + "destinations",
				FlowClass:        string(path.FlowLatency),
			},
			PathFamilyIDs: []string{"family-a"}, PolicyIDs: []string{"allow"},
		}},
	}
	engine, err := bft.NewEngine(state, []model.CommitteeMember{member}, member.ID, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	proposal, vote, err := engine.Propose(model.StateTransition{Type: bft.TransitionGenesis}, 0)
	if err != nil {
		t.Fatal(err)
	}
	qc, ready, err := engine.ProcessVote(vote)
	if err != nil || !ready {
		t.Fatalf("genesis vote: qc=%+v ready=%v err=%v", qc, ready, err)
	}
	snapshot, err := engine.Commit(proposal, qc)
	if err != nil {
		t.Fatal(err)
	}
	netManager := &Manager{node: node, engine: engine}
	netManager.forwarding = forward.NewTable(state, node.Host.ID().String(), nil)
	netManager.routing = newRoutingRuntime(netManager)
	netManager.routing.epoch = &link.SignedRoutingEpoch{Epoch: link.RoutingEpoch{
		NetworkID:      state.NetworkID,
		SnapshotHeight: snapshot.Height,
		SnapshotHash:   append([]byte(nil), snapshot.StateHash...),
		CommitteeEpoch: snapshot.State.CommitteeConfig.CommitteeEpoch,
		Sequence:       1,
		ExpiresAt:      time.Now().Add(time.Minute),
		Allocations: []link.PathAllocation{{
			Domain: link.RoutingDomainKey{
				SourceManagerID: "A", SourceGroupID: "sources",
				DestinationScope: model.DestinationScopeGroup + "destinations",
				FlowClass:        path.FlowLatency,
			},
			PathID: "family-a", Weight: 1,
		}},
	}}

	payload, err := packet.BuildEchoRequest(
		net.ParseIP("100.64.0.1"), net.ParseIP("100.64.0.2"), 0x5150, 1, []byte("demand"),
	)
	if err != nil {
		t.Fatal(err)
	}
	envelope := forward.ScaleEnvelope{
		Header: forward.ScaleHeader{
			SourcePeerID: sourceID, DestinationPeerID: destinationID,
			RoutingDomainID: "domain-a", FlowClass: string(path.FlowLatency), TTL: forward.DefaultTTL,
		},
		Payload: payload,
	}
	wire, err := forward.EncodeScaleEnvelope(envelope)
	if err != nil {
		t.Fatal(err)
	}
	source, err := peer.Decode(sourceID)
	if err != nil {
		t.Fatal(err)
	}

	netManager.forwarding.SetScaleRouting(func(_, _, _, _, _ string) (forward.ScaleAuthorization, error) {
		return forward.ScaleAuthorization{}, forward.ErrScaleUnauthorized
	}, nil)
	netManager.handleScaleWire(source, wire)
	if len(netManager.routing.demand) != 0 {
		t.Fatalf("unauthorized frame recorded demand: %v", netManager.routing.demand)
	}

	netManager.forwarding.SetScaleRouting(func(_, _, _, _, _ string) (forward.ScaleAuthorization, error) {
		return forward.ScaleAuthorization{Destination: true, ExpectedPredecessor: sourceID}, nil
	}, nil)
	if err := netManager.routing.applySelection(&envelope); err != nil {
		t.Fatalf("authorized scale selection: %v", err)
	}
	netManager.handleScaleWire(source, wire)
	if got := netManager.routing.demand["domain-a"]; got != uint64(len(payload)) {
		t.Fatalf("authorized demand = %d, want %d", got, len(payload))
	}
}
