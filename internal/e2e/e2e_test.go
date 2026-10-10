// Package e2e exercises the full control and data plane in a single process:
// a three-manager BFT committee plus userspace clients exchanging overlay ICMP.
package e2e

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"

	"github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/netp2p/netp2p/internal/bft"
	"github.com/netp2p/netp2p/internal/chaos"
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
		Settings: model.NetworkSettings{
			DirectPathEnabled: true,
			ViaManagerEnabled: true,
			MaxManagerHops:    2,
		},
		Groups: []model.Group{{ID: "clients-a"}, {ID: "clients-b"}},
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
	links    []*link.Gossiper
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

// probeDrivenState is a via-manager-only network with fast link probes and a
// bidirectional allow policy, so the planner can certify both directions from
// measurements alone.
func probeDrivenState() model.NetworkState {
	state := testState()
	state.Policies = []model.Policy{{
		ID:                "allow-clients-icmp",
		SourceGroups:      []string{"clients-a", "clients-b"},
		DestinationGroups: []string{"clients-a", "clients-b"},
		Services:          []model.Service{{Protocol: "icmp"}},
		Effect:            model.EffectAllow,
		Direction:         model.DirectionBidirectional,
	}}
	state.Settings = model.NetworkSettings{
		DirectPathEnabled: false, ViaManagerEnabled: true, MaxManagerHops: 2,
		LinkProbeIntervalSeconds: 1, LinkProbeTimeoutMs: 500,
	}
	return state
}

func newClusterWithConfig(t *testing.T, state model.NetworkState, config manager.Config) *cluster {
	return newClusterWithHook(t, state, config, nil)
}

// newClusterWithHook builds the standard three-manager committee but installs a
// send hook on every node, which is how chaos tests inject faults.
func newClusterWithHook(t *testing.T, state model.NetworkState, config manager.Config, hookFor func(peer.ID) p2p.SendHook) *cluster {
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
		node, err := p2p.New(ctx, p2p.Config{
			IdentitySeed: group.members[index].KeySeed,
			Listen:       []string{"/ip4/127.0.0.1/udp/0/quic-v1"},
			WebRTCListen: []string{"/ip4/127.0.0.1/udp/0/webrtc-direct"},
		})
		if err != nil {
			t.Fatal(err)
		}
		if hookFor != nil {
			node.SetSendHook(hookFor(node.Host.ID()))
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
		gossiper := link.NewGossiper(group.nodes[index], mesh.PeerIDs(), engine.LocalID(), 10*time.Second, 90*time.Second, 1000)
		group.nodes[index].Handle(p2p.LinkGossipProtocol, gossiper.Handle)
		group.links = append(group.links, gossiper)
		scoped := config
		scoped.Links = gossiper
		group.engines = append(group.engines, engine)
		group.meshes = append(group.meshes, mesh)
		netManager := manager.New(group.nodes[index], engine, mesh, scoped)
		group.managers = append(group.managers, netManager)
		if config.Forwarding {
			netManager.EnableForwarding(ctx)
		}
		go gossiper.Run(ctx)
		go netManager.RunLinkProbe(ctx)
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
	node, err := p2p.New(ctx, p2p.Config{
		IdentitySeed: seed,
		Listen:       []string{"/ip4/127.0.0.1/udp/0/quic-v1"},
	})
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
		if err := bft.ValidateClientSnapshot(netClient.Snapshot()); err != nil {
			t.Fatalf("client snapshot failed validation: %v", err)
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

// TestProbeDrivenViaManagerAssignment closes the loop end to end: real manager
// probes produce access segments, the planner turns them into certified
// via-manager assignments, and the data plane then forwards a userspace probe.
func TestProbeDrivenViaManagerAssignment(t *testing.T) {
	group := newForwardingCluster(t, probeDrivenState())
	address := group.members[0].Address
	managerID := group.nodes[0].Host.ID().String()

	clientA, sinkA := newTestClient(t, 241, address, keyA)
	clientB, _ := newTestClient(t, 242, address, keyB)
	waitForPeers(t, clientA, 2)
	waitForPeers(t, clientB, 2)

	sourceID := clientA.Self().PeerID
	destinationID := clientB.Self().PeerID
	waitForAccessSegments(t, group.managers[0], managerID, sourceID, destinationID)
	waitForCertifiedAssignments(t, group, sourceID, destinationID)

	var ok bool
	var err error
	for attempt := 0; attempt < 10; attempt++ {
		ok, err = probe(t, sinkA, clientA.Self().OverlayIP, clientB.Self().OverlayIP, 3*time.Second)
		if err == nil && ok {
			break
		}
		t.Logf("attempt %d: ok=%v err=%v", attempt+1, ok, err)
		time.Sleep(200 * time.Millisecond)
	}
	if err != nil || !ok {
		t.Fatalf("A->B probe over a measured assignment never succeeded: ok=%v err=%v", ok, err)
	}
	forwarded, dropped := group.managers[0].ForwardingStats()
	if forwarded == 0 {
		t.Fatal("manager never forwarded a frame")
	}
	if dropped != 0 {
		t.Fatalf("manager dropped %d frames", dropped)
	}
}

func waitForAccessSegments(t *testing.T, netManager *manager.Manager, managerID string, peers ...string) {
	t.Helper()
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		if hasAccessSegments(netManager.LinkView(), managerID, peers) {
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatalf("manager %s never measured access segments for %v: %+v", managerID, peers, netManager.LinkView())
}

func hasAccessSegments(view link.LinkView, managerID string, peers []string) bool {
	for _, peerID := range peers {
		found := false
		for _, segment := range view.AccessSegments {
			if (segment.From == managerID && segment.To == peerID) || (segment.From == peerID && segment.To == managerID) {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	return true
}

// waitForCertifiedAssignments drives the planner until both directions are
// certified. Each reconcile pass submits at most one changed assignment, so the
// loop may need several passes.
func waitForCertifiedAssignments(t *testing.T, group *cluster, sourceID, destinationID string) {
	t.Helper()
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		if err := group.managers[0].ReconcileAssignments(); err != nil {
			t.Logf("reconcile assignments: %v", err)
		}
		found := make(map[string]bool)
		for _, assignment := range group.engines[0].CurrentState().Assignments {
			if assignment.Primary.Kind != model.PathKindViaManager {
				continue
			}
			found[assignment.SourcePeerID+"->"+assignment.DestinationPeerID] = true
		}
		if found[sourceID+"->"+destinationID] && found[destinationID+"->"+sourceID] {
			return
		}
		time.Sleep(300 * time.Millisecond)
	}
	t.Fatalf("planner never certified via-manager assignments for %s/%s", sourceID, destinationID)
}

func TestManagerFailureBlocksWrites(t *testing.T) {
	controller := chaos.New()
	group := newClusterWithHook(t, testState(), manager.Config{}, controller.HookFor)
	waitForCommitteeHeight(t, group, 1)

	// A 3-of-3 committee has no fault budget: stopping any manager must block
	// the next certified write rather than allowing a split-brain commit.
	controller.Isolate(group.members[len(group.members)-1].PeerID)

	transition := model.StateTransition{Type: bft.TransitionUpsertGroup, Group: &model.Group{ID: "blocked-group"}}
	start := time.Now()
	_, err := group.meshes[0].Submit(transition)
	if err == nil {
		t.Fatal("write unexpectedly certified with one manager unavailable")
	}
	if !errors.Is(err, manager.ErrCommitteeUnavailable) {
		t.Fatalf("write error = %v, want committee unavailable", err)
	}
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Fatalf("degraded write took %s, want an immediate rejection", elapsed)
	}
	if got := group.engines[0].Height(); got != 1 {
		t.Fatalf("height advanced to %d while a manager was unavailable", got)
	}
}

func TestSnapshotVerificationRejectsTampering(t *testing.T) {
	group := newCluster(t, testState())
	address := group.members[0].Address
	netClient, _ := newTestClient(t, 221, address, keyA)
	waitForPeers(t, netClient, 1)

	snapshot := netClient.Snapshot()
	if err := bft.ValidateClientSnapshot(snapshot); err != nil {
		t.Fatalf("valid snapshot rejected: %v", err)
	}

	tampered := snapshot
	tampered.State.NextIPOffset++
	if err := bft.ValidateSnapshot(tampered); err == nil {
		t.Fatal("state hash mismatch accepted")
	}

	missingQuorum := snapshot
	// Clearing the signer bitmap simulates a certificate that does not carry a
	// threshold of contributions.
	missingQuorum.QC.SignerBitmap = []byte{0b00000001}
	if err := bft.ValidateSnapshot(missingQuorum); err == nil {
		t.Fatal("snapshot without quorum accepted")
	}
}
