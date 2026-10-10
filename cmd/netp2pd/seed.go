package main

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"

	"github.com/netp2p/netp2p/internal/config"
	"github.com/netp2p/netp2p/internal/model"
	"github.com/netp2p/netp2p/internal/oidc"
)

func defaultSeed() config.Seed {
	managers := make([]model.CommitteeMember, 3)
	for index := range managers {
		managers[index] = model.CommitteeMember{
			ID:         fmt.Sprintf("manager-%d", index+1),
			Address:    fmt.Sprintf("/dns4/manager-%d/udp/4001/quic-v1", index+1),
			KeySeed:    int64(index + 101),
			ListenAddr: fmt.Sprintf("/ip4/0.0.0.0/udp/%d/webrtc-direct", 4101+index),
		}
	}
	return config.Seed{
		Development:     true,
		NetworkID:       "netp2p-test",
		OverlayCIDR:     "100.64.0.0/24",
		CommitteeParams: model.DefaultCommitteeParams(),
		AdminToken:      "netp2p-admin-v0",
		Managers:        managers,
		SetupKeys: []model.SetupKey{
			{ID: "setup-key-a", Name: "Bootstrap A", Token: "setup-key-a", TokenPrefix: "setup-key-a"[:8], Type: model.SetupKeyReusable, Groups: []string{"clients-a"}},
			{ID: "setup-key-b", Name: "Bootstrap B", Token: "setup-key-b", TokenPrefix: "setup-key-b"[:8], Type: model.SetupKeyReusable, Groups: []string{"clients-b"}},
			{ID: "setup-key-exit", Name: "Bootstrap Exit", Token: "setup-key-exit", TokenPrefix: "setup-key-exit"[:8], Type: model.SetupKeyReusable, Groups: []string{"exit-gateways"}},
		},
		Groups: []model.Group{
			{ID: "clients-a"},
			{ID: "clients-b"},
			{ID: "exit-gateways"},
		},
		Policies: []model.Policy{
			{
				ID: "allow-a-to-b-icmp", SourceGroups: []string{"clients-a"}, DestinationGroups: []string{"clients-b"},
				Services: []model.Service{{Protocol: "icmp"}}, Effect: model.EffectAllow, Direction: model.DirectionUnidirectional,
			},
			{
				ID: "allow-a-to-b-tcp", SourceGroups: []string{"clients-a"}, DestinationGroups: []string{"clients-b"},
				Services: []model.Service{{Protocol: "tcp", StartPort: 0, EndPort: 65535}}, Effect: model.EffectAllow,
				Direction: model.DirectionUnidirectional,
			},
			{
				ID: "deny-b-to-a-icmp", SourceGroups: []string{"clients-b"}, DestinationGroups: []string{"clients-a"},
				Services: []model.Service{{Protocol: "icmp"}}, Effect: model.EffectDeny, Direction: model.DirectionUnidirectional, Priority: 100,
			},
			{
				ID: "allow-a-to-exit", SourceGroups: []string{"clients-a"}, DestinationGroups: []string{"exit-gateways"},
				Services: []model.Service{{Protocol: "icmp"}, {Protocol: "tcp", StartPort: 0, EndPort: 65535}},
				Effect:   model.EffectAllow, Direction: model.DirectionUnidirectional,
			},
		},
		Settings: model.NetworkSettings{
			DNSDomain:           "netp2p.internal",
			LoginExpirationDays: 30,
			JWTGroupsEnabled:    true,
			JWTGroupsClaimName:  "groups",
			ExitNodeEnabled:     true,
		},
		OIDC: oidc.Config{
			Issuer:      "http://mock-idp:9999",
			ClientID:    "netp2p",
			WebClientID: "netp2p-web",
			GroupsClaim: "groups",
			AdminGroups: []string{"netp2p-admins"},
		},
		NextIPOffset: 1,
	}
}

func writeSeed(path string) error {
	if path == "" {
		return fmt.Errorf("--config is required for seedgen")
	}
	seed := defaultSeed()
	sessionSecret := make([]byte, 32)
	if _, err := rand.Read(sessionSecret); err != nil {
		return fmt.Errorf("generate session secret: %w", err)
	}
	seed.SessionSecret = base64.RawStdEncoding.EncodeToString(sessionSecret)
	seed.FinalizeDev()
	encoded, err := json.MarshalIndent(seed, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, encoded, 0o600)
}
