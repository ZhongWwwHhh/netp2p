package client

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"runtime"
	"sort"
	"sync"
	"time"

	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/core/peerstore"
	"github.com/libp2p/go-libp2p/core/protocol"
	"github.com/multiformats/go-multiaddr"
	"github.com/netp2p/netp2p/internal/bft"
	"github.com/netp2p/netp2p/internal/conntrack"
	"github.com/netp2p/netp2p/internal/model"
	"github.com/netp2p/netp2p/internal/p2p"
	"github.com/netp2p/netp2p/internal/packet"
	"github.com/netp2p/netp2p/internal/policy"
	netproto "github.com/netp2p/netp2p/internal/protocol"
	"github.com/netp2p/netp2p/internal/transport"
	"github.com/netp2p/netp2p/internal/version"
)

type Client struct {
	node       *p2p.Node
	manager    peer.AddrInfo
	sink       packet.PacketSink
	snapshot   model.SignedSnapshot
	self       model.PeerRecord
	networkMap policy.NetworkMap
	mu         sync.RWMutex

	flows          *conntrack.Table
	frames         *transport.Transport
	synthesizeICMP bool
	dnsUpdater     DNSUpdater
	dnsUpstreams   []string
}

func New(node *p2p.Node, managerAddr string, sink packet.PacketSink) (*Client, error) {
	info, err := peer.AddrInfoFromString(managerAddr)
	if err != nil {
		return nil, fmt.Errorf("invalid manager address: %w", err)
	}
	client := &Client{
		node: node, manager: *info, sink: sink,
		flows: conntrack.NewTable(),
	}
	if marker, ok := sink.(packet.UserspaceICMP); ok {
		client.synthesizeICMP = marker.SynthesizeICMP()
	}
	return client, nil
}

func (client *Client) Login(ctx context.Context, networkID, setupKey string) error {
	if err := client.connect(ctx); err != nil {
		return fmt.Errorf("connect manager: %w", err)
	}
	request := netproto.LoginRequest{NetworkID: networkID, SetupKey: setupKey, PeerID: client.node.Host.ID().String(), Addresses: client.node.Addresses()}
	request.Hostname, _ = os.Hostname()
	request.OS = runtime.GOOS
	request.ClientVersion = version.Version
	var response netproto.LoginResponse
	if err := client.request(ctx, p2p.LoginProtocol, request, &response); err != nil {
		return err
	}
	if response.Error != "" {
		return fmt.Errorf("login failed: %s", response.Error)
	}
	if err := bft.ValidateSnapshot(response.Snapshot); err != nil {
		return fmt.Errorf("invalid certified snapshot: %w", err)
	}
	client.applySnapshot(response.Snapshot, response.Peer)
	return nil
}

// Sync long-polls the manager for a newer certified snapshot. The manager
// blocks the stream until a new height is committed or the request times out.
func (client *Client) Sync(ctx context.Context) error {
	client.mu.RLock()
	height := client.snapshot.Height
	networkID := client.snapshot.State.NetworkID
	client.mu.RUnlock()
	if err := client.connect(ctx); err != nil {
		return fmt.Errorf("connect manager: %w", err)
	}
	var snapshot model.SignedSnapshot
	if err := client.request(ctx, p2p.SyncProtocol, netproto.SyncRequest{NetworkID: networkID, PeerID: client.node.Host.ID().String(), Height: height}, &snapshot); err != nil {
		return err
	}
	if err := bft.ValidateSnapshot(snapshot); err != nil {
		return err
	}
	if snapshot.Height <= height {
		return fmt.Errorf("manager did not provide newer snapshot")
	}
	client.mu.RLock()
	self := client.self
	client.mu.RUnlock()
	if peerRecord, ok := findPeer(snapshot, self.PeerID); ok {
		self = peerRecord
	}
	client.applySnapshot(snapshot, self)
	return nil
}

// SyncLoop keeps the local certified snapshot fresh for the lifetime of ctx.
func (client *Client) SyncLoop(ctx context.Context) {
	for ctx.Err() == nil {
		if err := client.Sync(ctx); err != nil {
			if ctx.Err() != nil {
				return
			}
			log.Printf("sync: %v", err)
			select {
			case <-ctx.Done():
				return
			case <-time.After(time.Second):
			}
		}
	}
}

func (client *Client) connect(ctx context.Context) error {
	return client.node.Host.Connect(ctx, client.manager)
}

func (client *Client) applySnapshot(snapshot model.SignedSnapshot, self model.PeerRecord) {
	networkMap := policy.Compile(policy.State{
		NetworkID: snapshot.State.NetworkID,
		Groups:    snapshot.State.Groups,
		Policies:  snapshot.State.Policies,
		Routes:    snapshot.State.Routes,
		Budgets:   snapshot.State.Budgets,
	}, self.PeerID, snapshot.Epoch)
	client.mu.Lock()
	client.snapshot = snapshot
	if self.PeerID != "" {
		client.self = self
	}
	client.networkMap = networkMap
	localPeerID := client.node.Host.ID()
	overlayIPs := client.peerOverlayIPsLocked()
	client.mu.Unlock()
	client.rememberPeers(snapshot, localPeerID)
	client.applyRoutes(overlayIPs)
	client.publishDNS()
}

// peerOverlayIPsLocked lists every other peer's overlay address.
//
// Routes intentionally cover all peers rather than only policy-allowed ones.
// The kernel needs a route to emit reply traffic, and a reply for a flow we
// admitted inbound is legitimate even when the mirror-image policy denies it.
// Access control stays in this process: every packet, in both directions, is
// checked against the certified policy before it is forwarded. The route only
// decides which destinations the kernel hands to the overlay instead of the
// default gateway. The caller must hold the client lock.
func (client *Client) peerOverlayIPsLocked() []string {
	self := client.self.PeerID
	result := make([]string, 0, len(client.snapshot.State.Peers))
	for _, record := range client.snapshot.State.Peers {
		if record.PeerID == self || record.OverlayIP == "" {
			continue
		}
		result = append(result, record.OverlayIP)
	}
	sort.Strings(result)
	return result
}

// ReconcileRoutes pushes the current overlay addresses into the kernel
// routing table. It is called after the device is configured, because the login
// snapshot is applied before the interface has an address.
func (client *Client) ReconcileRoutes() {
	client.mu.RLock()
	overlayIPs := client.peerOverlayIPsLocked()
	client.mu.RUnlock()
	client.applyRoutes(overlayIPs)
}

func (client *Client) applyRoutes(overlayIPs []string) {
	reconciler, ok := client.sink.(packet.RouteReconciler)
	if !ok {
		return
	}
	if err := reconciler.ReconcileRoutes(overlayIPs); err != nil {
		log.Printf("overlay route reconcile: %v", err)
	}
}

// rememberPeers teaches the libp2p peerstore how to dial overlay peers so that
// frame streams can open without an explicit connect step.
func (client *Client) rememberPeers(snapshot model.SignedSnapshot, local peer.ID) {
	for _, record := range snapshot.State.Peers {
		peerID, err := peer.Decode(record.PeerID)
		if err != nil || peerID == local {
			continue
		}
		addresses := make([]multiaddr.Multiaddr, 0, len(record.Addresses))
		for _, value := range record.Addresses {
			address, err := multiaddr.NewMultiaddr(value)
			if err != nil {
				continue
			}
			addresses = append(addresses, address)
		}
		if len(addresses) > 0 {
			client.node.Host.Peerstore().AddAddrs(peerID, addresses, peerstore.PermanentAddrTTL)
		}
	}
}

func findPeer(snapshot model.SignedSnapshot, peerID string) (model.PeerRecord, bool) {
	for _, record := range snapshot.State.Peers {
		if record.PeerID == peerID {
			return record, true
		}
	}
	return model.PeerRecord{}, false
}

func (client *Client) request(ctx context.Context, protocolID protocol.ID, request any, response any) error {
	stream, err := client.node.Host.NewStream(ctx, client.manager.ID, protocolID)
	if err != nil {
		return err
	}
	defer stream.Close()
	encoded, err := json.Marshal(request)
	if err != nil {
		return err
	}
	if err := json.NewEncoder(stream).Encode(p2p.Envelope{Protocol: protocolID, Payload: encoded}); err != nil {
		return err
	}
	if closer, ok := stream.(interface{ CloseWrite() error }); ok {
		_ = closer.CloseWrite()
	}
	return json.NewDecoder(stream).Decode(response)
}

func (client *Client) Self() model.PeerRecord {
	client.mu.RLock()
	defer client.mu.RUnlock()
	return client.self
}

func (client *Client) SnapshotHeight() uint64 {
	client.mu.RLock()
	defer client.mu.RUnlock()
	return client.snapshot.Height
}

func (client *Client) Snapshot() model.SignedSnapshot {
	client.mu.RLock()
	defer client.mu.RUnlock()
	return client.snapshot
}
