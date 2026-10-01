package dkg

import (
	"bytes"
	"context"
	"fmt"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/netp2p/netp2p/internal/crypto/bls"
	"github.com/netp2p/netp2p/internal/p2p"
)

func TestCeremonyProducesConsistentGroupKey(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	const size, threshold = 4, 3

	nodes := make([]*p2p.Node, size)
	for index := range nodes {
		node, err := p2p.New(ctx, p2p.Config{
			IdentitySeed: int64(index + 1),
			Listen:       []string{"/ip4/127.0.0.1/udp/0/quic-v1"},
		})
		if err != nil {
			t.Fatalf("node %d: %v", index, err)
		}
		defer node.Close()
		nodes[index] = node
	}
	for i := range nodes {
		for j := range nodes {
			if i == j {
				continue
			}
			if err := nodes[i].Host.Connect(ctx, peer.AddrInfo{ID: nodes[j].Host.ID(), Addrs: nodes[j].Host.Addrs()}); err != nil {
				t.Fatalf("connect %d->%d: %v", i, j, err)
			}
		}
	}

	members := make([]Member, size)
	ids := make([]string, size)
	for index := range nodes {
		ids[index] = fmt.Sprintf("member-%d", index)
		members[index] = Member{ID: ids[index], PeerID: nodes[index].Host.ID()}
	}
	ceremonyID := CeremonyID("net-1", 1, ids)
	ceremonies := make([]*Ceremony, size)
	for index := range nodes {
		ceremony, err := New(nodes[index], Config{
			CeremonyID: ceremonyID, Threshold: threshold, Members: members, LocalID: members[index].ID,
		})
		if err != nil {
			t.Fatalf("ceremony %d: %v", index, err)
		}
		nodes[index].Handle(p2p.DKGProtocol, ceremony.Handle)
		ceremonies[index] = ceremony
	}

	results := make([]*bls.DKGResult, size)
	errors := make([]error, size)
	var wait sync.WaitGroup
	for index := range ceremonies {
		wait.Add(1)
		go func(index int) {
			defer wait.Done()
			results[index], errors[index] = ceremonies[index].Run(ctx)
		}(index)
	}
	wait.Wait()
	for index, err := range errors {
		if err != nil {
			t.Fatalf("ceremony %d failed: %v", index, err)
		}
	}
	for index := 1; index < size; index++ {
		if !bytes.Equal(results[0].GroupPublicKey, results[index].GroupPublicKey) {
			t.Fatalf("member %d group key mismatch", index)
		}
	}
	if !bls.ValidG2Point(results[0].GroupPublicKey) {
		t.Fatal("group key is not a valid G2 point")
	}
}

func TestSharePersistenceRoundTrip(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	const size, threshold = 4, 3

	nodes := make([]*p2p.Node, size)
	for index := range nodes {
		node, err := p2p.New(ctx, p2p.Config{
			IdentitySeed: int64(index + 1),
			Listen:       []string{"/ip4/127.0.0.1/udp/0/quic-v1"},
		})
		if err != nil {
			t.Fatalf("node %d: %v", index, err)
		}
		defer node.Close()
		nodes[index] = node
	}
	for i := range nodes {
		for j := range nodes {
			if i == j {
				continue
			}
			if err := nodes[i].Host.Connect(ctx, peer.AddrInfo{ID: nodes[j].Host.ID(), Addrs: nodes[j].Host.Addrs()}); err != nil {
				t.Fatalf("connect %d->%d: %v", i, j, err)
			}
		}
	}
	members := make([]Member, size)
	ids := make([]string, size)
	for index := range nodes {
		ids[index] = fmt.Sprintf("member-%d", index)
		members[index] = Member{ID: ids[index], PeerID: nodes[index].Host.ID()}
	}
	ceremonyID := CeremonyID("net-1", 4, ids)
	ceremonies := make([]*Ceremony, size)
	for index := range nodes {
		ceremony, err := New(nodes[index], Config{CeremonyID: ceremonyID, Threshold: threshold, Members: members, LocalID: members[index].ID})
		if err != nil {
			t.Fatalf("ceremony %d: %v", index, err)
		}
		nodes[index].Handle(p2p.DKGProtocol, ceremony.Handle)
		ceremonies[index] = ceremony
	}
	results := make([]*bls.DKGResult, size)
	var wait sync.WaitGroup
	for index := range ceremonies {
		wait.Add(1)
		go func(index int) {
			defer wait.Done()
			result, err := ceremonies[index].Run(ctx)
			if err != nil {
				t.Errorf("ceremony %d: %v", index, err)
				return
			}
			results[index] = result
		}(index)
	}
	wait.Wait()

	dir := t.TempDir()
	for index := range results {
		if results[index] == nil {
			t.Fatalf("member %d produced no result", index)
		}
		if err := SaveShare(filepath.Join(dir, members[index].ID), 4, members[index].ID, threshold, size, results[index]); err != nil {
			t.Fatalf("save share %d: %v", index, err)
		}
	}
	keySet, ok := LoadShare(filepath.Join(dir, members[0].ID), 4, members[0].ID, ids, threshold)
	if !ok {
		t.Fatal("share did not load")
	}
	message := []byte("height=1 round=0")
	partials := make(map[int][]byte, threshold)
	for _, index := range []int{0, 1, 2} {
		loaded, ok := LoadShare(filepath.Join(dir, members[index].ID), 4, members[index].ID, ids, threshold)
		if !ok {
			t.Fatalf("member %d share did not load", index)
		}
		signature, err := loaded.SignShare(index, message)
		if err != nil {
			t.Fatalf("sign %d: %v", index, err)
		}
		partials[index] = signature
	}
	aggregate, err := keySet.Aggregate(partials)
	if err != nil {
		t.Fatalf("aggregate: %v", err)
	}
	if !bls.Verify(results[0].GroupPublicKey, message, aggregate) {
		t.Fatal("persisted shares did not produce a valid threshold signature")
	}
}
