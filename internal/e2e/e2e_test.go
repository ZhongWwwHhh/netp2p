// Package e2e exercises the full control and data plane in a single process:
// a four-manager BFT committee plus userspace clients exchanging overlay ICMP.
package e2e

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/netp2p/netp2p/internal/bft"
	"github.com/netp2p/netp2p/internal/client"
	"github.com/netp2p/netp2p/internal/link"
	"github.com/netp2p/netp2p/internal/manager"
	"github.com/netp2p/netp2p/internal/model"
	"github.com/netp2p/netp2p/internal/p2p"
	"github.com/netp2p/netp2p/internal/packet"
)

const (
	networkID = "net-e2e"
	keyA      = "setup-key-a"
	keyB      = "setup-key-b"
)

func testState() model.NetworkState {
	return model.NetworkState{
		NetworkID:    networkID,
		OverlayCIDR:  "100.64.0.0/24",
		NextIPOffset: 1,
		Groups:       []model.Group{{ID: "clients-a"}, {ID: "clients-b"}},
		SetupKeys: []model.SetupKey{
			{ID: keyA, Token: keyA, TokenHash: model.SetupKeyHash(keyA), Groups: []string{"clients-a"}},
			{ID: keyB, Token: keyB, TokenHash: model.SetupKeyHash(keyB), Groups: []string{"clients-b"}},
		},
		Policies: []model.Policy{
			{
				ID: "allow-a-to-b-icmp", SourceGroups: []string{"clients-a"}, DestinationGroups: []string{"clients-b"},
				Services: []model.Service{{Protocol: "icmp"}}, Effect: model.EffectAllow, Direction: model.DirectionUnidirectional,
			},
			{
				ID: "deny-b-to-a-icmp", SourceGroups: []string{"clients-b"}, DestinationGroups: []string{"clients-a"},
				Services: []model.Service{{Protocol: "icmp"}}, Effect: model.EffectDeny, Direction: model.DirectionUnidirectional, Priority: 100,
			},
		},
	}
}

type cluster struct {
	ctx      context.Context
	cancel   context.CancelFunc
	members  []model.CommitteeMember
	nodes    []*p2p.Node
	engines  []*bft.Engine
	meshes   []*manager.CommitteeMesh
	managers []*manager.Manager
}

func newCluster(t *testing.T, state model.NetworkState) *cluster {
	return newClusterWithConfig(t, state, manager.Config{})
}

func newForwardingCluster(t *testing.T, state model.NetworkState) *cluster {
	return newClusterWithConfig(t, state, manager.Config{Forwarding: true})
}

// forcedViaManagerState removes the direct path entirely so every packet must
// traverse the certified manager hop.
func forcedViaManagerState() model.NetworkState {
	state := testState()
	state.Settings = model.NetworkSettings{
		DirectPathEnabled: false, ViaManagerEnabled: true, MaxManagerHops: 2,
	}
	return state
}

func newClusterWithConfig(t *testing.T, state model.NetworkState, config manager.Config) *cluster {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	group := &cluster{ctx: ctx, cancel: cancel}

	const count = bft.CommitteeSize
	group.members = make([]model.CommitteeMember, count)
	for index := range group.members {
		seed := int64(index + 101)
		privateKey := bft.SeededPrivateKey(seed)
		libp2pKey, _, err := crypto.KeyPairFromStdKey(&privateKey)
		if err != nil {
			t.Fatal(err)
		}
		peerID, err := peer.IDFromPrivateKey(libp2pKey)
		if err != nil {
			t.Fatal(err)
		}
		group.members[index] = model.CommitteeMember{
			ID: managerName(index), PeerID: peerID.String(), KeySeed: seed,
			// Committee members forward by default so via-manager paths are
			// valid certified state.
			ForwardingEnabled: true,
		}
	}
	for index := range group.members {
		node, err := p2p.New(ctx, p2p.Config{IdentitySeed: group.members[index].KeySeed, WebRTCListen: []string{"/ip4/127.0.0.1/udp/0/webrtc-direct"}})
		if err != nil {
			t.Fatal(err)
		}
		group.nodes = append(group.nodes, node)
		addresses := node.Addresses()
		if len(addresses) == 0 {
			t.Fatal("manager has no addresses")
		}
		group.members[index].Address = addresses[0]
	}
	for index := range group.members {
		engine, err := bft.NewEngine(state, group.members, group.members[index].ID, bft.SeededPrivateKey(group.members[index].KeySeed))
		if err != nil {
			t.Fatal(err)
		}
		mesh, err := manager.NewCommitteeMesh(group.nodes[index], engine, group.members)
		if err != nil {
			t.Fatal(err)
		}
		group.engines = append(group.engines, engine)
		group.meshes = append(group.meshes, mesh)
		group.managers = append(group.managers, manager.New(group.nodes[index], engine, mesh, config))
		if config.Forwarding {
			group.managers[index].EnableForwarding(ctx)
		}
	}
	for _, mesh := range group.meshes {
		if err := mesh.Connect(ctx); err != nil {
			t.Fatalf("mesh connect: %v", err)
		}
	}
	for _, mesh := range group.meshes {
		if err := mesh.WaitReady(ctx); err != nil {
			t.Fatalf("mesh ready: %v", err)
		}
	}
	t.Cleanup(group.stop)
	group.certifyGenesis(t)
	return group
}

func managerName(index int) string {
	return "manager-" + string(rune('1'+index))
}

func (group *cluster) certifyGenesis(t *testing.T) {
	t.Helper()
	leaderID := group.engines[0].Leader(1, 0).ID
	for index, engine := range group.engines {
		if engine.LocalID() != leaderID {
			continue
		}
		if _, err := group.meshes[index].Submit(model.StateTransition{Type: bft.TransitionGenesis}); err != nil {
			t.Fatalf("genesis: %v", err)
		}
		return
	}
	t.Fatal("no height-1 leader in committee")
}

func (group *cluster) stop() {
	if group.cancel != nil {
		group.cancel()
		group.cancel = nil
	}
	for _, node := range group.nodes {
		_ = node.Close()
	}
}

func newTestClient(t *testing.T, seed int64, managerAddr, setupKey string) (*client.Client, *packet.UDPPacketSink) {
	t.Helper()
	ctx := t.Context()
	node, err := p2p.New(ctx, p2p.Config{IdentitySeed: seed})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = node.Close() })
	sink, err := packet.NewUDPPacketSink("127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = sink.Close() })
	netClient, err := client.New(node, managerAddr, sink)
	if err != nil {
		t.Fatal(err)
	}
	if err := netClient.Login(ctx, networkID, setupKey, ""); err != nil {
		t.Fatalf("login %s: %v", setupKey, err)
	}
	go netClient.ServePackets(ctx)
	go netClient.SyncLoop(ctx)
	return netClient, sink
}

func waitForPeers(t *testing.T, netClient *client.Client, want int) {
	t.Helper()
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		if len(netClient.Snapshot().State.Peers) >= want {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("client %s saw %d peers, want %d", netClient.Self().PeerID, len(netClient.Snapshot().State.Peers), want)
}

// probe sends a userspace ICMP echo request through the sink and reports the
// result of waiting for an echo reply.
func probe(t *testing.T, sink *packet.UDPPacketSink, source, target string, timeout time.Duration) (bool, error) {
	t.Helper()
	connection, err := net.Dial("udp", sink.LocalAddr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	request, err := packet.BuildEchoRequest(net.ParseIP(source), net.ParseIP(target), 0x1234, 1, []byte("netp2p-probe"))
	if err != nil {
		t.Fatal(err)
	}
	frame, err := packet.EncodeFrame(request)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := connection.Write(frame); err != nil {
		t.Fatal(err)
	}
	if err := connection.SetReadDeadline(time.Now().Add(timeout)); err != nil {
		t.Fatal(err)
	}
	buffer := make([]byte, 65535)
	read, err := connection.Read(buffer)
	if err != nil {
		return false, err
	}
	reply, err := packet.DecodeFrame(buffer[:read])
	if err != nil {
		return false, err
	}
	ipPacket := packet.IPv4Packet(reply)
	if err := ipPacket.Validate(); err != nil {
		return false, err
	}
	icmp := packet.ICMPMessage(reply[ipPacket.HeaderLength():])
	return icmp.Type() == packet.ICMPTypeEchoReply, nil
}

func TestOverlayProbeRespectsPolicy(t *testing.T) {
	group := newCluster(t, testState())
	address := group.members[0].Address

	clientA, sinkA := newTestClient(t, 201, address, keyA)
	clientB, sinkB := newTestClient(t, 202, address, keyB)

	waitForPeers(t, clientA, 2)
	waitForPeers(t, clientB, 2)
	overlayA := clientA.Self().OverlayIP
	overlayB := clientB.Self().OverlayIP
	if overlayA == overlayB || overlayA == "" || overlayB == "" {
		t.Fatalf("unexpected overlay addresses: %q %q", overlayA, overlayB)
	}

	ok, err := probe(t, sinkA, overlayA, overlayB, 5*time.Second)
	if err != nil || !ok {
		t.Fatalf("A->B probe failed: ok=%v err=%v", ok, err)
	}

	if _, err := probe(t, sinkB, overlayB, overlayA, 2*time.Second); err == nil {
		t.Fatal("B->A probe succeeded despite deny policy")
	}
}

// TestViaManagerForwardsOverlayProbe proves the data plane honours a certified
// via-manager assignment: with no direct path certified, an ICMP echo request
// and its reply must both traverse the manager, and the manager must not drop
// either frame.
func TestViaManagerForwardsOverlayProbe(t *testing.T) {
	group := newForwardingCluster(t, forcedViaManagerState())
	address := group.members[0].Address
	hopPeerID := group.members[0].PeerID

	clientA, sinkA := newTestClient(t, 231, address, keyA)
	clientB, _ := newTestClient(t, 232, address, keyB)
	waitForPeers(t, clientA, 2)
	waitForPeers(t, clientB, 2)

	sourceID := clientA.Self().PeerID
	destinationID := clientB.Self().PeerID
	viaPath := func(source, destination string) model.RouteAssignment {
		return model.RouteAssignment{
			ID: link.AssignmentID(source, destination), NetworkID: networkID,
			SourcePeerID: source, DestinationPeerID: destination, Epoch: 1,
			Primary: model.PathSpec{
				ID:   link.AssignmentID(source, destination) + "-via-" + hopPeerID,
				Kind: model.PathKindViaManager, ManagerHops: []string{hopPeerID},
			},
			UpdatedAt: time.Now().UTC(), RequiresAdmission: true,
		}
	}
	// Assignments are directed, so both directions need one.
	outbound := viaPath(sourceID, destinationID)
	inbound := viaPath(destinationID, sourceID)
	height := uint64(0)
	for _, assignment := range []model.RouteAssignment{outbound, inbound} {
		snapshot, err := group.meshes[0].Submit(model.StateTransition{
			Type: bft.TransitionUpdateAssignment, Assignment: &assignment,
		})
		if err != nil {
			t.Fatalf("submit assignment %s: %v", assignment.ID, err)
		}
		height = snapshot.Height
	}
	for _, netClient := range []*client.Client{clientA, clientB} {
		deadline := time.Now().Add(15 * time.Second)
		for netClient.SnapshotHeight() < height && time.Now().Before(deadline) {
			time.Sleep(50 * time.Millisecond)
		}
		if netClient.SnapshotHeight() < height {
			t.Fatalf("client did not sync certified assignment height %d", height)
		}
		certified := make(map[string]model.RouteAssignment)
		for _, assignment := range netClient.Snapshot().State.Assignments {
			certified[assignment.ID] = assignment
		}
		// Both directions must be certified: the request needs A->B and the
		// synthesized reply needs B->A.
		for _, want := range []model.RouteAssignment{outbound, inbound} {
			got, ok := certified[want.ID]
			if !ok {
				t.Fatalf("certified state is missing assignment %s", want.ID)
			}
			if got.Primary.Kind != model.PathKindViaManager {
				t.Fatalf("certified primary is not via-manager: %+v", got.Primary)
			}
			if len(got.Primary.ManagerHops) != 1 || got.Primary.ManagerHops[0] != hopPeerID {
				t.Fatalf("certified hop is not the manager PeerID: %+v", got.Primary.ManagerHops)
			}
			// No direct path may exist, otherwise the client could bypass the
			// manager and the forwarding assertion below would be vacuous.
			for _, path := range append([]model.PathSpec{got.Primary}, got.Fallbacks...) {
				if path.Kind == model.PathKindDirect {
					t.Fatalf("direct path certified in a via-manager-only state: %+v", path)
				}
			}
		}
	}

	ok, err := probe(t, sinkA, clientA.Self().OverlayIP, clientB.Self().OverlayIP, 10*time.Second)
	if err != nil || !ok {
		t.Fatalf("A->B via-manager probe failed: ok=%v err=%v", ok, err)
	}
	forwarded, dropped := group.managers[0].ForwardingStats()
	if forwarded == 0 {
		t.Fatal("manager never forwarded a frame; the probe did not use the certified path")
	}
	if dropped != 0 {
		t.Fatalf("manager dropped %d frames while forwarding", dropped)
	}
}

func TestQuorumCertifiesAfterManagerFailure(t *testing.T) {
	group := newCluster(t, testState())
	address := group.members[0].Address

	clientA, _ := newTestClient(t, 211, address, keyA)
	clientB, _ := newTestClient(t, 212, address, keyB)
	waitForPeers(t, clientA, 2)
	waitForPeers(t, clientB, 2)

	// Height 4 is led by manager-1; stopping manager-4 leaves a live leader and
	// exactly three voters, which is still a quorum.
	_ = group.nodes[3].Close()

	clientC, _ := newTestClient(t, 213, address, keyA)
	if clientC.Self().OverlayIP == "" {
		t.Fatal("registration with one manager down did not return an overlay address")
	}
	if clientC.SnapshotHeight() < 4 {
		t.Fatalf("certified height %d, want >= 4", clientC.SnapshotHeight())
	}
}

func TestSnapshotVerificationRejectsTampering(t *testing.T) {
	group := newCluster(t, testState())
	address := group.members[0].Address
	netClient, _ := newTestClient(t, 221, address, keyA)
	waitForPeers(t, netClient, 1)

	snapshot := netClient.Snapshot()
	if err := bft.ValidateSnapshot(snapshot); err != nil {
		t.Fatalf("valid snapshot rejected: %v", err)
	}

	tampered := snapshot
	tampered.State.NextIPOffset++
	if err := bft.ValidateSnapshot(tampered); err == nil {
		t.Fatal("state hash mismatch accepted")
	}

	missingQuorum := snapshot
	missingQuorum.QC.Signers = missingQuorum.QC.Signers[:len(missingQuorum.QC.Signers)-1]
	missingQuorum.QC.Signatures = missingQuorum.QC.Signatures[:len(missingQuorum.QC.Signatures)-1]
	if err := bft.ValidateSnapshot(missingQuorum); err == nil {
		t.Fatal("snapshot without quorum accepted")
	}
}
