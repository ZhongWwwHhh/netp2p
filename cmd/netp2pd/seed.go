package main

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/netp2p/netp2p/internal/config"
	"github.com/netp2p/netp2p/internal/model"
)

func defaultSeed() config.Seed {
	managers := make([]model.CommitteeMember, 4)
	for index := range managers {
		managers[index] = model.CommitteeMember{
			ID:      fmt.Sprintf("manager-%d", index+1),
			Address: fmt.Sprintf("/dns4/manager-%d/udp/4001/quic-v1", index+1),
			KeySeed: int64(index + 101),
		}
	}
	return config.Seed{
		NetworkID:   "netp2p-test",
		OverlayCIDR: "100.64.0.0/24",
		AdminToken:  "netp2p-admin-v0",
		Managers:    managers,
		SetupKeys: []model.SetupKey{
			{Key: "setup-key-a", Groups: []string{"clients-a"}},
			{Key: "setup-key-b", Groups: []string{"clients-b"}},
		},
		Groups: []model.Group{
			{ID: "clients-a"},
			{ID: "clients-b"},
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
		NextIPOffset: 1,
	}
}

func writeSeed(path string) error {
	if path == "" {
		return fmt.Errorf("--config is required for seedgen")
	}
	seed := defaultSeed()
	seed.Finalize()
	encoded, err := json.MarshalIndent(seed, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, encoded, 0o600)
}
