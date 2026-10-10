package manager

import (
	"context"
	"testing"
	"time"

	"github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/netp2p/netp2p/internal/bft"
	"github.com/netp2p/netp2p/internal/model"
	"github.com/netp2p/netp2p/internal/p2p"
	"github.com/netp2p/netp2p/internal/protocol"
	"github.com/netp2p/netp2p/internal/version"
	"github.com/netp2p/netp2p/internal/wire"
	"github.com/netp2p/netp2p/internal/wire/pb"
	"google.golang.org/protobuf/proto"
)

func TestSyncSendsHeartbeatsAndReleasesWaiter(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	const networkID = "net-sync-heartbeat"
	state := model.NetworkState{
		NetworkID: networkID, OverlayCIDR: "100.64.0.0/24",
		CommitteeConfig: model.CommitteeConfig{Threshold: 3, Size: 3},
	}
	members := make([]model.CommitteeMember, 3)
	for index := range members {
		seed := int64(index + 301)
		privateKey := bft.SeededPrivateKey(seed)
		libp2pKey, _, err := crypto.KeyPairFromStdKey(&privateKey)
		if err != nil {
			t.Fatal(err)
		}
		peerID, err := peer.IDFromPrivateKey(libp2pKey)
		if err != nil {
			t.Fatal(err)
		}
		members[index] = model.CommitteeMember{
			ID: string(rune('A' + index)), PeerID: peerID.String(), KeySeed: seed,
		}
	}

	managerNode, err := p2p.New(ctx, p2p.Config{IdentitySeed: members[0].KeySeed})
	if err != nil {
		t.Fatal(err)
	}
	defer managerNode.Close()
	engine, err := bft.NewEngine(state, members, members[0].ID, bft.SeededPrivateKey(members[0].KeySeed))
	if err != nil {
		t.Fatal(err)
	}
	mesh, err := NewCommitteeMesh(managerNode, engine, members)
	if err != nil {
		t.Fatal(err)
	}
	manager := New(managerNode, engine, mesh, Config{})
	manager.mu.Lock()
	manager.snapshot = model.SignedSnapshot{
		Epoch: 1, Height: 1,
		State: model.NetworkState{NetworkID: networkID, OverlayCIDR: state.OverlayCIDR},
	}
	manager.mu.Unlock()

	previousInterval := syncHeartbeatInterval
	syncHeartbeatInterval = 15 * time.Millisecond
	defer func() { syncHeartbeatInterval = previousInterval }()

	clientNode, err := p2p.New(ctx, p2p.Config{})
	if err != nil {
		t.Fatal(err)
	}
	defer clientNode.Close()
	target, err := peer.AddrInfoFromString(managerNode.Addresses()[0])
	if err != nil {
		t.Fatal(err)
	}
	if err := clientNode.Host.Connect(ctx, *target); err != nil {
		t.Fatal(err)
	}

	stream, err := clientNode.Host.NewStream(ctx, managerNode.Host.ID(), p2p.SyncProtocol)
	if err != nil {
		t.Fatal(err)
	}
	request := wire.SyncRequestToProto(protocol.SyncRequest{
		NetworkID: networkID, PeerID: clientNode.Host.ID().String(), Height: 1,
		ProtocolVersion: version.ProtocolVersion,
	})
	if err := p2p.WriteMessage(stream, p2p.SyncProtocol, request); err != nil {
		t.Fatal(err)
	}
	if closer, ok := stream.(interface{ CloseWrite() error }); ok {
		_ = closer.CloseWrite()
	}

	heartbeats := 0
	deadline := time.Now().Add(time.Second)
	for heartbeats < 2 && time.Now().Before(deadline) {
		envelope, err := p2p.DecodeEnvelope(stream)
		if err != nil {
			t.Fatalf("read heartbeat %d: %v", heartbeats+1, err)
		}
		var response pb.SyncResponse
		if err := proto.Unmarshal(envelope.Payload, &response); err != nil {
			t.Fatal(err)
		}
		heartbeat := response.GetHeartbeat()
		if heartbeat == nil {
			t.Fatalf("response %d is %T, want heartbeat", heartbeats+1, response.GetResponse())
		}
		if heartbeat.GetNetworkId() != networkID || heartbeat.GetHeight() != 1 {
			t.Fatalf("heartbeat = network %q height %d, want %q height 1",
				heartbeat.GetNetworkId(), heartbeat.GetHeight(), networkID)
		}
		if heartbeat.GetServerTimeUnixMs() == 0 {
			t.Fatal("heartbeat server timestamp is empty")
		}
		heartbeats++
	}
	if heartbeats != 2 {
		t.Fatalf("received %d heartbeats, want 2", heartbeats)
	}
	_ = stream.Reset()

	waitFor(t, time.Second, func() bool {
		manager.mu.RLock()
		defer manager.mu.RUnlock()
		return len(manager.waiters) == 0
	})
}

func TestSyncRejectsNetworkMismatch(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	const networkID = "net-sync-mismatch"
	state := model.NetworkState{
		NetworkID: networkID, OverlayCIDR: "100.64.0.0/24",
		CommitteeConfig: model.CommitteeConfig{Threshold: 3, Size: 3},
	}
	members := make([]model.CommitteeMember, 3)
	for index := range members {
		seed := int64(index + 401)
		privateKey := bft.SeededPrivateKey(seed)
		libp2pKey, _, err := crypto.KeyPairFromStdKey(&privateKey)
		if err != nil {
			t.Fatal(err)
		}
		peerID, err := peer.IDFromPrivateKey(libp2pKey)
		if err != nil {
			t.Fatal(err)
		}
		members[index] = model.CommitteeMember{
			ID: string(rune('A' + index)), PeerID: peerID.String(), KeySeed: seed,
		}
	}
	managerNode, err := p2p.New(ctx, p2p.Config{IdentitySeed: members[0].KeySeed})
	if err != nil {
		t.Fatal(err)
	}
	defer managerNode.Close()
	engine, err := bft.NewEngine(state, members, members[0].ID, bft.SeededPrivateKey(members[0].KeySeed))
	if err != nil {
		t.Fatal(err)
	}
	mesh, err := NewCommitteeMesh(managerNode, engine, members)
	if err != nil {
		t.Fatal(err)
	}
	_ = New(managerNode, engine, mesh, Config{})

	clientNode, err := p2p.New(ctx, p2p.Config{})
	if err != nil {
		t.Fatal(err)
	}
	defer clientNode.Close()
	target, err := peer.AddrInfoFromString(managerNode.Addresses()[0])
	if err != nil {
		t.Fatal(err)
	}
	if err := clientNode.Host.Connect(ctx, *target); err != nil {
		t.Fatal(err)
	}
	stream, err := clientNode.Host.NewStream(ctx, managerNode.Host.ID(), p2p.SyncProtocol)
	if err != nil {
		t.Fatal(err)
	}
	defer stream.Close()
	request := wire.SyncRequestToProto(protocol.SyncRequest{
		NetworkID: "different-network", PeerID: clientNode.Host.ID().String(),
		ProtocolVersion: version.ProtocolVersion,
	})
	if err := p2p.WriteMessage(stream, p2p.SyncProtocol, request); err != nil {
		t.Fatal(err)
	}
	if closer, ok := stream.(interface{ CloseWrite() error }); ok {
		_ = closer.CloseWrite()
	}
	envelope, err := p2p.DecodeEnvelope(stream)
	if err != nil {
		t.Fatal(err)
	}
	var response pb.SyncResponse
	if err := proto.Unmarshal(envelope.Payload, &response); err != nil {
		t.Fatal(err)
	}
	if response.GetError().GetCode() != "network_mismatch" {
		t.Fatalf("sync error = %+v, want network_mismatch", response.GetError())
	}
}

func waitFor(t *testing.T, timeout time.Duration, condition func() bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if condition() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("condition was not met before timeout")
}
