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

func bidirectionalDirectState() model.NetworkState {
	state := testState()
	state.Policies = []model.Policy{{
		ID:                "allow-clients-icmp",
		SourceGroups:      []string{"clients-a", "clients-b"},
		DestinationGroups: []string{"clients-a", "clients-b"},
		Services:          []model.Service{{Protocol: "icmp"}},
		Effect:            model.EffectAllow,
		Direction:         model.DirectionBidirectional,
	}}
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
	libp2pKeys := make([]crypto.PrivKey, count)
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
		libp2pKeys[index] = libp2pKey
		group.members[index] = model.CommitteeMember{
			ID: managerName(index), PeerID: peerID.String(), KeySeed: seed,
			// Committee members forward by default so via-manager paths are
			// valid certified state.
			ForwardingEnabled: true,
		}
	}
	for index := range group.members {
		node, err := p2p.New(ctx, p2p.Config{
			Identity:     libp2pKeys[index],
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

// newScaleTestClient runs the real client daemon path: login, sync, packet
// endpoint, frame transport, and scale envelope admission.
func newScaleTestClient(t *testing.T, seed int64, managerAddr, setupKey string) (*client.Client, *packet.UDPPacketSink) {
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

func TestDirectOverlayProbeIsBidirectional(t *testing.T) {
	group := newCluster(t, bidirectionalDirectState())
	address := group.members[0].Address

	clientA, sinkA := newTestClient(t, 203, address, keyA)
	clientB, sinkB := newTestClient(t, 204, address, keyB)
	waitForPeers(t, clientA, 2)
	waitForPeers(t, clientB, 2)

	overlayA := clientA.Self().OverlayIP
	overlayB := clientB.Self().OverlayIP

	ok, err := probe(t, sinkA, overlayA, overlayB, 5*time.Second)
	if err != nil || !ok {
		t.Fatalf("A->B direct probe failed: ok=%v err=%v", ok, err)
	}
	ok, err = probe(t, sinkB, overlayB, overlayA, 5*time.Second)
	if err != nil || !ok {
		t.Fatalf("B->A direct probe failed: ok=%v err=%v", ok, err)
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
// probes produce access segments, the global planner certifies routing
// families and domains, and a signed epoch forwards a userspace probe.
func TestProbeDrivenViaManagerAssignment(t *testing.T) {
	group := newForwardingCluster(t, probeDrivenState())
	address := group.members[0].Address

	clientA, sinkA := newScaleTestClient(t, 241, address, keyA)
	clientB, _ := newScaleTestClient(t, 242, address, keyB)
	waitForPeers(t, clientA, 2)
	waitForPeers(t, clientB, 2)

	sourceID := clientA.Self().PeerID
	destinationID := clientB.Self().PeerID
	managerID := group.nodes[0].Host.ID().String()
	waitForAccessSegments(t, group.managers[0], managerID, sourceID, destinationID)
	_, family, epoch := waitForGlobalRouting(t, group, "clients-a", "clients-b")
	_, _, _ = waitForGlobalRouting(t, group, "clients-b", "clients-a")

	state := group.engines[0].CurrentState()
	if len(state.Assignments) != 0 {
		t.Fatalf("global planner generated %d peer-pair assignments", len(state.Assignments))
	}
	if (family.Kind != model.PathKindViaManager && family.Kind != model.PathKindMultiHop) || len(family.ManagerHops) == 0 {
		t.Fatalf("selected family is not manager-forwarded: %+v", family)
	}
	if epoch.Epoch.NetworkID != networkID || epoch.Epoch.SnapshotHeight == 0 || len(epoch.Epoch.Allocations) == 0 {
		t.Fatalf("invalid signed routing epoch: %+v", epoch.Epoch)
	}

	beforeForwarded, beforeDropped := clusterForwardingStats(group)
	ok, err := probe(t, sinkA, clientA.Self().OverlayIP, clientB.Self().OverlayIP, 10*time.Second)
	if err != nil || !ok {
		t.Fatalf("A->B probe over a measured assignment never succeeded: ok=%v err=%v", ok, err)
	}
	afterForwarded, afterDropped := waitForForwardingSettlement(group, beforeForwarded, beforeDropped)
	if afterForwarded <= beforeForwarded {
		t.Fatalf("manager forwarding did not advance: before=%d after=%d", beforeForwarded, afterForwarded)
	}
	if afterDropped != beforeDropped {
		t.Fatalf("manager dropped frames while forwarding: before=%d after=%d", beforeDropped, afterDropped)
	}
}

func clusterForwardingStats(group *cluster) (forwarded, dropped uint64) {
	for _, netManager := range group.managers {
		managerForwarded, managerDropped := netManager.ForwardingStats()
		forwarded += managerForwarded
		dropped += managerDropped
	}
	return forwarded, dropped
}

func waitForForwardingSettlement(group *cluster, beforeForwarded, beforeDropped uint64) (uint64, uint64) {
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		forwarded, dropped := clusterForwardingStats(group)
		if forwarded > beforeForwarded {
			return forwarded, dropped
		}
		time.Sleep(10 * time.Millisecond)
	}
	return clusterForwardingStats(group)
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

// waitForGlobalRouting drives the leader until the committee has certified an
// aggregate routing domain and every manager has the committee-signed epoch.
func waitForGlobalRouting(
	t *testing.T, group *cluster, sourceGroup, destinationGroup string,
) (model.RoutingDomainAuthorization, model.PathFamily, *link.SignedRoutingEpoch) {
	t.Helper()
	deadline := time.Now().Add(30 * time.Second)
	var leader *manager.Manager
	var state model.NetworkState
	for time.Now().Before(deadline) {
		leader = routingLeader(group)
		if err := leader.ReconcileRouting(); err != nil {
			t.Logf("reconcile global routing: %v", err)
		}
		state = group.engines[0].CurrentState()
		var domain model.RoutingDomainAuthorization
		for _, candidate := range state.RoutingDomains {
			if candidate.Key.SourceManagerID == managerName(0) &&
				candidate.Key.SourceGroupID == sourceGroup &&
				candidate.Key.DestinationScope == model.DestinationScopeGroup+destinationGroup &&
				candidate.Key.FlowClass == model.FlowClassLatency {
				domain = candidate
				break
			}
		}
		if domain.ID == "" {
			time.Sleep(100 * time.Millisecond)
			continue
		}
		epoch := leader.RoutingEpoch()
		if epoch == nil {
			time.Sleep(100 * time.Millisecond)
			continue
		}
		for _, netManager := range group.managers {
			if netManager.RoutingEpoch() == nil {
				epoch = nil
				break
			}
		}
		if epoch == nil {
			time.Sleep(100 * time.Millisecond)
			continue
		}
		for _, allocation := range epoch.Epoch.Allocations {
			if allocation.Domain.SourceManagerID != domain.Key.SourceManagerID ||
				allocation.Domain.SourceGroupID != domain.Key.SourceGroupID ||
				allocation.Domain.DestinationScope != domain.Key.DestinationScope ||
				string(allocation.Domain.FlowClass) != domain.Key.FlowClass {
				continue
			}
			for _, candidate := range state.PathFamilies {
				if candidate.ID == allocation.PathID && len(candidate.ManagerHops) > 0 {
					return domain, candidate, epoch
				}
			}
		}
		time.Sleep(100 * time.Millisecond)
	}
	epochManagers := 0
	for _, netManager := range group.managers {
		if netManager.RoutingEpoch() != nil {
			epochManagers++
		}
	}
	allocations := 0
	if signed := leader.RoutingEpoch(); signed != nil {
		for range signed.Epoch.Allocations {
			allocations++
		}
	}
	t.Fatalf(
		"global planner never produced a signed via-manager routing epoch: leader=%s height=%d round=%d domains=%d families=%d epochs=%d/%d allocations=%d",
		leader.LocalID(), group.engines[0].Height(), group.engines[0].CurrentRound(),
		len(state.RoutingDomains), len(state.PathFamilies), epochManagers, len(group.managers), allocations,
	)
	return model.RoutingDomainAuthorization{}, model.PathFamily{}, nil
}

func routingLeader(group *cluster) *manager.Manager {
	height := group.engines[0].Height()
	leaderID := group.engines[0].Leader(height+1, group.engines[0].CurrentRound()).ID
	for index, engine := range group.engines {
		if engine.LocalID() == leaderID {
			return group.managers[index]
		}
	}
	return group.managers[0]
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
