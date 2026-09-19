// Package config loads the static v0 network seed.
package config

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/netp2p/netp2p/internal/bft"
	"github.com/netp2p/netp2p/internal/model"
	"github.com/netp2p/netp2p/internal/oidc"
)

type Seed struct {
	NetworkID    string                  `json:"networkId"`
	OverlayCIDR  string                  `json:"overlayCidr"`
	AdminToken   string                  `json:"adminToken,omitempty"`
	Managers     []model.CommitteeMember `json:"managers"`
	Relays       []model.CommitteeMember `json:"relays,omitempty"`
	Groups       []model.Group           `json:"groups"`
	Policies     []model.Policy          `json:"policies"`
	Routes       []model.Route           `json:"routes"`
	Budgets      []model.TrafficBudget   `json:"budgets"`
	SetupKeys    []model.SetupKey        `json:"setupKeys"`
	Nameservers  []model.Nameserver      `json:"nameservers,omitempty"`
	Zones        []model.DNSZone         `json:"zones,omitempty"`
	DNSSettings  model.DNSSettings       `json:"dnsSettings,omitempty"`
	Settings     model.NetworkSettings   `json:"settings,omitempty"`
	OIDC         oidc.Config             `json:"oidc,omitempty"`
	NextIPOffset uint32                  `json:"nextIpOffset"`
}

func Load(path string) (Seed, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Seed{}, fmt.Errorf("read seed: %w", err)
	}
	var seed Seed
	if err := json.Unmarshal(data, &seed); err != nil {
		return Seed{}, fmt.Errorf("decode seed: %w", err)
	}
	if err := seed.Validate(); err != nil {
		return Seed{}, err
	}
	seed.Finalize()
	return seed, nil
}

func (seed Seed) Validate() error {
	if seed.NetworkID == "" || seed.OverlayCIDR == "" {
		return fmt.Errorf("networkId and overlayCidr are required")
	}
	if len(seed.Managers) != 4 {
		return fmt.Errorf("v0 requires exactly 4 committee managers, got %d", len(seed.Managers))
	}
	seen := make(map[string]struct{})
	for _, manager := range seed.Managers {
		if manager.ID == "" || manager.Address == "" {
			return fmt.Errorf("manager id and address are required")
		}
		if manager.KeySeed == 0 && len(manager.PublicKey) == 0 {
			return fmt.Errorf("manager %q needs keySeed or publicKey", manager.ID)
		}
		if _, exists := seen[manager.ID]; exists {
			return fmt.Errorf("duplicate manager id %q", manager.ID)
		}
		seen[manager.ID] = struct{}{}
	}
	if seed.NextIPOffset == 0 {
		seed.NextIPOffset = 11
	}
	return nil
}

func (seed *Seed) Finalize() {
	if seed.NextIPOffset == 0 {
		seed.NextIPOffset = 11
	}
	for index := range seed.Managers {
		if seed.Managers[index].PeerID != "" {
			continue
		}
		privateKey := bft.SeededPrivateKey(seed.Managers[index].KeySeed)
		libp2pPrivateKey, _, err := crypto.KeyPairFromStdKey(&privateKey)
		if err != nil {
			return
		}
		peerID, err := peer.IDFromPrivateKey(libp2pPrivateKey)
		if err != nil {
			return
		}
		seed.Managers[index].PeerID = peerID.String()
	}
	for index := range seed.SetupKeys {
		if seed.SetupKeys[index].TokenHash == nil && seed.SetupKeys[index].Token != "" {
			seed.SetupKeys[index].TokenHash = model.SetupKeyHash(seed.SetupKeys[index].Token)
		}
		if seed.SetupKeys[index].Type == "" {
			seed.SetupKeys[index].Type = model.SetupKeyReusable
		}
	}
}

func (seed Seed) NetworkState() model.NetworkState {
	return model.NetworkState{
		NetworkID:    seed.NetworkID,
		OverlayCIDR:  seed.OverlayCIDR,
		Groups:       append([]model.Group(nil), seed.Groups...),
		Policies:     append([]model.Policy(nil), seed.Policies...),
		Routes:       append([]model.Route(nil), seed.Routes...),
		Budgets:      append([]model.TrafficBudget(nil), seed.Budgets...),
		SetupKeys:    append([]model.SetupKey(nil), seed.SetupKeys...),
		Nameservers:  append([]model.Nameserver(nil), seed.Nameservers...),
		Zones:        append([]model.DNSZone(nil), seed.Zones...),
		DNSSettings:  seed.DNSSettings,
		Settings:     seed.Settings,
		NextIPOffset: seed.NextIPOffset,
	}
}

// RelayAddrInfos converts seed relay entries into libp2p AddrInfo. Entries
// without a valid multiaddr are skipped; clients that get no relay candidates
// simply do not enable AutoRelay.
func (seed Seed) RelayAddrInfos() ([]peer.AddrInfo, error) {
	result := make([]peer.AddrInfo, 0, len(seed.Relays))
	for _, relay := range seed.Relays {
		if relay.PeerID == "" || relay.Address == "" {
			continue
		}
		addr, err := peer.AddrInfoFromString(relay.Address + "/p2p/" + relay.PeerID)
		if err != nil {
			return nil, fmt.Errorf("invalid relay address %q: %w", relay.Address, err)
		}
		result = append(result, *addr)
	}
	return result, nil
}
