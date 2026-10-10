package main

import (
	"testing"

	"github.com/netp2p/netp2p/internal/config"
	"github.com/netp2p/netp2p/internal/model"
)

func TestSeedManagerEndpoints(t *testing.T) {
	seed := config.Seed{Managers: []model.CommitteeMember{
		{ID: "one", Address: "/ip4/127.0.0.1/udp/4001/quic-v1", PeerID: "peer-one"},
		{ID: "two", Address: "/ip4/127.0.0.1/udp/4002/quic-v1", PeerID: "peer-two"},
		{ID: "three", Address: "/ip4/127.0.0.1/udp/4003/quic-v1", PeerID: "peer-three"},
	}}
	endpoints := seedManagerEndpoints(seed)
	if len(endpoints) != 3 {
		t.Fatalf("endpoint count = %d, want 3", len(endpoints))
	}
	for index, endpoint := range endpoints {
		want := seed.Managers[index].Address + "/p2p/" + seed.Managers[index].PeerID
		if endpoint != want {
			t.Fatalf("endpoint %d = %q, want %q", index, endpoint, want)
		}
	}
}
