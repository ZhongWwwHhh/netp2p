package config

import (
	"testing"

	"github.com/netp2p/netp2p/internal/model"
)

func TestFinalizeHashesSetupKeys(t *testing.T) {
	seed := Seed{
		NetworkID:   "net",
		OverlayCIDR: "100.64.0.0/24",
		Managers: []model.CommitteeMember{
			{ID: "m1", Address: "/ip4/127.0.0.1/udp/1", KeySeed: 1},
			{ID: "m2", Address: "/ip4/127.0.0.1/udp/2", KeySeed: 2},
			{ID: "m3", Address: "/ip4/127.0.0.1/udp/3", KeySeed: 3},
			{ID: "m4", Address: "/ip4/127.0.0.1/udp/4", KeySeed: 4},
		},
		SetupKeys: []model.SetupKey{{ID: "k", Token: "secret", Groups: []string{"g"}}},
	}
	seed.Finalize()
	if len(seed.SetupKeys[0].TokenHash) == 0 {
		t.Fatal("token hash not computed")
	}
	if seed.SetupKeys[0].Type != model.SetupKeyReusable {
		t.Fatalf("type = %q, want reusable", seed.SetupKeys[0].Type)
	}
}

func TestRelayAddrInfos(t *testing.T) {
	seed := Seed{
		NetworkID:   "net",
		OverlayCIDR: "100.64.0.0/24",
		Managers: []model.CommitteeMember{
			{ID: "m1", Address: "/ip4/127.0.0.1/udp/1", KeySeed: 1},
			{ID: "m2", Address: "/ip4/127.0.0.1/udp/2", KeySeed: 2},
			{ID: "m3", Address: "/ip4/127.0.0.1/udp/3", KeySeed: 3},
			{ID: "m4", Address: "/ip4/127.0.0.1/udp/4", KeySeed: 4},
		},
		Relays: []model.CommitteeMember{
			{ID: "m1", PeerID: "12D3KooWTest", Address: "/ip4/10.0.0.1/udp/4001/quic-v1"},
		},
	}
	infos, err := seed.RelayAddrInfos()
	if err != nil {
		t.Fatalf("relay addr infos: %v", err)
	}
	if len(infos) != 1 {
		t.Fatalf("got %d relays, want 1", len(infos))
	}
	if infos[0].ID.String() != "12D3KooWTest" {
		t.Fatalf("peer id = %s", infos[0].ID)
	}
}
