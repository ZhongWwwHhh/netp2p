package websession

import (
	"context"
	"fmt"
	"path/filepath"
	"testing"
	"time"

	"github.com/libp2p/go-libp2p/core/peer"
	ma "github.com/multiformats/go-multiaddr"
	"github.com/netp2p/netp2p/internal/p2p"
	"github.com/netp2p/netp2p/internal/store"
)

func TestGossiperReplicatesAndRevokesSessions(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	first, second := newGossipPair(t, ctx)
	now := time.Now().UTC()
	session := store.WebSession{
		ID: "session-1", UserID: "user-1",
		IssuedAt:  now.Format(time.RFC3339Nano),
		ExpiresAt: now.Add(time.Hour).Format(time.RFC3339Nano),
	}
	if err := first.state.RecordWebSession(session); err != nil {
		t.Fatal(err)
	}
	for index := 0; index < 600; index++ {
		if err := first.state.RecordWebSession(store.WebSession{
			ID: fmt.Sprintf("session-page-%04d", index), UserID: "user-1",
			IssuedAt:  now.Format(time.RFC3339Nano),
			ExpiresAt: now.Add(time.Hour).Format(time.RFC3339Nano),
		}); err != nil {
			t.Fatal(err)
		}
	}
	if err := second.gossiper.Sync(ctx); err != nil {
		t.Fatalf("sync session: %v", err)
	}
	replicated, found, err := second.state.WebSession(session.ID)
	if err != nil || !found || replicated.UserID != session.UserID {
		t.Fatalf("replicated session = %+v found=%v err=%v", replicated, found, err)
	}
	all, err := second.state.WebSessions()
	if err != nil {
		t.Fatal(err)
	}
	if len(all) != 601 {
		t.Fatalf("replicated session count = %d, want 601", len(all))
	}

	revokedAt := now.Add(time.Second)
	if err := first.state.RevokeWebSession(session.ID, revokedAt); err != nil {
		t.Fatal(err)
	}
	if err := second.gossiper.Sync(ctx); err != nil {
		t.Fatalf("sync revocation: %v", err)
	}
	replicated, _, err = second.state.WebSession(session.ID)
	if err != nil {
		t.Fatal(err)
	}
	if replicated.RevokedAt == "" {
		t.Fatalf("revocation was not replicated: %+v", replicated)
	}
}

func TestGossiperSetPeersReplacesCommitteeAllowList(t *testing.T) {
	oldPeer := peer.ID("old-manager")
	newPeer := peer.ID("new-manager")
	gossiper := &Gossiper{peers: map[peer.ID]struct{}{oldPeer: {}}}
	gossiper.SetPeers([]peer.ID{newPeer})
	peers := gossiper.peerSnapshot()
	if _, allowed := peers[oldPeer]; allowed {
		t.Fatal("old manager remained in the web session allow-list")
	}
	if _, allowed := peers[newPeer]; !allowed {
		t.Fatal("new manager was not added to the web session allow-list")
	}
}

type gossipNode struct {
	node     *p2p.Node
	state    *store.Store
	gossiper *Gossiper
}

func newGossipPair(t *testing.T, ctx context.Context) (gossipNode, gossipNode) {
	t.Helper()
	first := newGossipNode(t, ctx, 101)
	second := newGossipNode(t, ctx, 102)

	firstPeer := peer.AddrInfo{ID: first.node.Host.ID(), Addrs: addresses(t, first.node.Addresses())}
	secondPeer := peer.AddrInfo{ID: second.node.Host.ID(), Addrs: addresses(t, second.node.Addresses())}
	if err := first.node.Host.Connect(ctx, secondPeer); err != nil {
		t.Fatalf("connect first to second: %v", err)
	}
	if err := second.node.Host.Connect(ctx, firstPeer); err != nil {
		t.Fatalf("connect second to first: %v", err)
	}

	first.gossiper = NewGossiper(first.node, first.state, []peer.ID{second.node.Host.ID()})
	second.gossiper = NewGossiper(second.node, second.state, []peer.ID{first.node.Host.ID()})
	return first, second
}

func newGossipNode(t *testing.T, ctx context.Context, seed int64) gossipNode {
	t.Helper()
	node, err := p2p.New(ctx, p2p.Config{
		DataDir:      filepath.Join(t.TempDir(), "identity"),
		IdentitySeed: seed,
		Listen:       []string{"/ip4/127.0.0.1/udp/0/quic-v1"},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = node.Host.Close() })
	state, err := store.Open(filepath.Join(t.TempDir(), "manager.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = state.Close() })
	return gossipNode{node: node, state: state}
}

func addresses(t *testing.T, values []string) []ma.Multiaddr {
	t.Helper()
	result := make([]ma.Multiaddr, 0, len(values))
	for _, value := range values {
		address, err := ma.NewMultiaddr(value)
		if err != nil {
			t.Fatal(err)
		}
		result = append(result, address)
	}
	return result
}
