package config

import (
	"fmt"
	"testing"

	"github.com/netp2p/netp2p/internal/model"
)

func testSeed() Seed {
	managers := make([]model.CommitteeMember, 4)
	for index := range managers {
		managers[index] = model.CommitteeMember{
			ID:      fmt.Sprintf("manager-%d", index+1),
			Address: fmt.Sprintf("/dns4/manager-%d/udp/4001/quic-v1", index+1),
			KeySeed: int64(index + 101),
		}
	}
	return Seed{NetworkID: "net-test", OverlayCIDR: "100.64.0.0/24", Managers: managers}
}

// TestFinalizeDerivesDeterministicPeerIDs pins the seeded identity derivation
// so Docker multiaddr templates and clients stay stable across runs.
func TestFinalizeDerivesDeterministicPeerIDs(t *testing.T) {
	seed := testSeed()
	if err := seed.Validate(); err != nil {
		t.Fatal(err)
	}
	seed.Finalize()
	if seed.Managers[0].PeerID != "12D3KooWNC1cKisChtyY5ZbeJBV8Xqqaj1k8gxGJPt2u2JtCAPp4" {
		t.Fatalf("unexpected manager-1 peer id %s", seed.Managers[0].PeerID)
	}
	for _, manager := range seed.Managers {
		if manager.PeerID == "" {
			t.Fatalf("manager %s has no peer id", manager.ID)
		}
	}
}

func TestValidateRejectsWrongCommitteeSize(t *testing.T) {
	seed := testSeed()
	seed.Managers = seed.Managers[:3]
	if err := seed.Validate(); err == nil {
		t.Fatal("committee with three managers accepted")
	}
}

func TestNetworkStateCopiesConfiguration(t *testing.T) {
	seed := testSeed()
	seed.Groups = []model.Group{{ID: "clients-a"}}
	seed.SetupKeys = []model.SetupKey{{Key: "key-a", Groups: []string{"clients-a"}}}
	state := seed.NetworkState()
	if state.NetworkID != seed.NetworkID || state.OverlayCIDR != seed.OverlayCIDR {
		t.Fatalf("network state mismatch: %+v", state)
	}
	if len(state.Groups) != 1 || len(state.SetupKeys) != 1 {
		t.Fatalf("groups/setup keys not copied: %+v", state)
	}
}
