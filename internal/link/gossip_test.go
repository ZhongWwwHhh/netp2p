package link

import (
	"testing"
	"time"

	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/netp2p/netp2p/internal/p2p"
)

func TestGossiperPublishPreservesRemoteObservations(t *testing.T) {
	now := time.Now().UTC()
	gossiper := &Gossiper{localID: "local", ttl: time.Minute}
	gossiper.observations = []Observation{
		{ObserverID: "remote", SubjectID: "peer-x", Scope: ScopeManagerMesh, RTTMilliseconds: 5, BandwidthMbps: 50, Samples: 1, MeasuredAt: now},
		{ObserverID: "local", SubjectID: "peer-old", Scope: ScopeManagerMesh, RTTMilliseconds: 9, BandwidthMbps: 10, Samples: 1, MeasuredAt: now},
	}
	gossiper.Publish([]Observation{
		{ObserverID: "local", SubjectID: "peer-new", Scope: ScopeManagerMesh, RTTMilliseconds: 7, BandwidthMbps: 80, Samples: 1, MeasuredAt: now},
	})
	observers := map[string]bool{}
	for _, observation := range gossiper.observations {
		observers[observation.ObserverID+"->"+observation.SubjectID] = true
	}
	if !observers["remote->peer-x"] {
		t.Fatal("gossiped remote observation was dropped by Publish")
	}
	if observers["local->peer-old"] {
		t.Fatal("stale local observation was not replaced")
	}
	if !observers["local->peer-new"] {
		t.Fatal("new local observation missing")
	}
}

func TestPruneObservationsDropsExpiredAndDuplicates(t *testing.T) {
	now := time.Now().UTC()
	expired := Observation{ObserverID: "m1", SubjectID: "m2", Scope: ScopeManagerMesh, Sequence: 1, Samples: 1, MeasuredAt: now.Add(-2 * time.Minute)}
	older := Observation{ObserverID: "m1", SubjectID: "m2", Scope: ScopeManagerMesh, Sequence: 2, RTTMilliseconds: 30, Samples: 1, MeasuredAt: now.Add(-time.Second)}
	newer := Observation{ObserverID: "m1", SubjectID: "m2", Scope: ScopeManagerMesh, Sequence: 2, RTTMilliseconds: 20, Samples: 1, MeasuredAt: now}
	result := pruneObservations([]Observation{expired, older, newer}, now, time.Minute)
	if len(result) != 1 {
		t.Fatalf("pruned observations = %d, want 1", len(result))
	}
	if result[0].RTTMilliseconds != 20 {
		t.Fatalf("kept rtt %f, want the newest duplicate (20)", result[0].RTTMilliseconds)
	}
}

// TestGossipReachesPeersOverLinkGossipProtocol is a regression test for the
// protocol mismatch that used to send gossip on the probe protocol, where
// nobody was listening.
func TestGossipReachesPeersOverLinkGossipProtocol(t *testing.T) {
	ctx := t.Context()
	sender, err := p2p.New(ctx, p2p.Config{Listen: []string{"/ip4/127.0.0.1/tcp/0"}})
	if err != nil {
		t.Fatal(err)
	}
	receiver, err := p2p.New(ctx, p2p.Config{Listen: []string{"/ip4/127.0.0.1/tcp/0"}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = sender.Close()
		_ = receiver.Close()
	})
	if err := sender.Host.Connect(ctx, addrInfo(t, receiver)); err != nil {
		t.Fatalf("connect: %v", err)
	}
	receiverGossiper := NewGossiper(receiver, nil, receiver.Host.ID().String(), time.Hour, time.Minute, 0)
	receiver.Handle(p2p.LinkGossipProtocol, receiverGossiper.Handle)
	senderGossiper := NewGossiper(sender, []peer.ID{receiver.Host.ID()}, sender.Host.ID().String(), time.Hour, time.Minute, 0)
	senderGossiper.Publish([]Observation{{
		ObserverID: sender.Host.ID().String(), SubjectID: receiver.Host.ID().String(),
		Scope: ScopeManagerMesh, RTTMilliseconds: 12, BandwidthMbps: 60, Samples: 1, MeasuredAt: time.Now().UTC(),
	}})

	senderGossiper.exchange(ctx)

	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if len(receiverGossiper.Observations()) > 0 {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if observations := receiverGossiper.Observations(); len(observations) != 1 {
		t.Fatalf("receiver observations = %d, want 1 (gossip used the wrong protocol?)", len(observations))
	}
}

func addrInfo(t *testing.T, node *p2p.Node) peer.AddrInfo {
	t.Helper()
	addresses := node.Addresses()
	if len(addresses) == 0 {
		t.Fatal("node has no addresses")
	}
	info, err := peer.AddrInfoFromString(addresses[0])
	if err != nil {
		t.Fatal(err)
	}
	return *info
}
