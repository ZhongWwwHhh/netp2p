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
	// Development marks the legacy all-in-one seed as an explicit test
	// fixture. Production managers must use NetworkManifest and ManagerBundle.
	Development     bool                    `json:"development,omitempty"`
	NetworkID       string                  `json:"networkId"`
	OverlayCIDR     string                  `json:"overlayCidr"`
	CommitteeParams model.CommitteeParams   `json:"committeeParams,omitempty"`
	AdminToken      string                  `json:"adminToken,omitempty"`
	SessionSecret   string                  `json:"sessionSecret,omitempty"`
	Users           []model.User            `json:"users,omitempty"`
	Managers        []model.CommitteeMember `json:"managers"`
	Relays          []model.CommitteeMember `json:"relays,omitempty"`
	Groups          []model.Group           `json:"groups"`
	Policies        []model.Policy          `json:"policies"`
	Routes          []model.Route           `json:"routes"`
	Budgets         []model.TrafficBudget   `json:"budgets"`
	SetupKeys       []model.SetupKey        `json:"setupKeys"`
	Nameservers     []model.Nameserver      `json:"nameservers,omitempty"`
	Zones           []model.DNSZone         `json:"zones,omitempty"`
	DNSSettings     model.DNSSettings       `json:"dnsSettings,omitempty"`
	Settings        model.NetworkSettings   `json:"settings,omitempty"`
	OIDC            oidc.Config             `json:"oidc,omitempty"`
	NextIPOffset    uint32                  `json:"nextIpOffset"`
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
	seed.FinalizeDev()
	return seed, nil
}

func (seed *Seed) Validate() error {
	if seed.NetworkID == "" || seed.OverlayCIDR == "" {
		return fmt.Errorf("networkId and overlayCidr are required")
	}
	if len(seed.Managers) != model.DefaultCommitteeSize {
		return fmt.Errorf("requires exactly %d committee managers, got %d", model.DefaultCommitteeSize, len(seed.Managers))
	}
	if seed.CommitteeParams == (model.CommitteeParams{}) {
		seed.CommitteeParams = model.DefaultCommitteeParams()
	}
	if seed.CommitteeParams != model.DefaultCommitteeParams() {
		return fmt.Errorf("development fixture committee parameters must be 3/0/3, got %d/%d/%d", seed.CommitteeParams.Size, seed.CommitteeParams.FaultLimit, seed.CommitteeParams.QuorumSize)
	}
	for index := range seed.Managers {
		// The legacy development seed predates per-manager forwarding flags.
		// Its committee managers are intentionally all forwarding-capable.
		seed.Managers[index].ForwardingEnabled = true
	}
	known := make(map[string]struct{}, len(seed.Managers))
	for _, manager := range seed.Managers {
		known[manager.ID] = struct{}{}
	}
	knownPeerIDs := make(map[string]struct{}, len(seed.Managers))
	for _, manager := range seed.Managers {
		if manager.PeerID != "" {
			knownPeerIDs[manager.PeerID] = struct{}{}
		}
	}
	for _, legacyRelay := range seed.Relays {
		if _, managerKnown := known[legacyRelay.ID]; managerKnown {
			continue
		}
		if legacyRelay.PeerID != "" {
			if _, peerKnown := knownPeerIDs[legacyRelay.PeerID]; peerKnown {
				continue
			}
		}
		return fmt.Errorf("unknown legacy relay %q: relay identity was removed; forwarding nodes must be committee managers", legacyRelay.ID)
	}
	seed.Relays = nil
	seen := make(map[string]struct{})
	for _, manager := range seed.Managers {
		if manager.ID == "" || manager.Address == "" {
			return fmt.Errorf("manager id and address are required")
		}
		if manager.KeySeed != 0 && !seed.Development {
			return fmt.Errorf("manager %q uses deterministic keySeed outside a development fixture", manager.ID)
		}
		if manager.KeySeed == 0 && len(manager.PublicKey) == 0 {
			return fmt.Errorf("manager %q needs publicKey (or keySeed in a development fixture)", manager.ID)
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

// FinalizeDev derives deterministic identities and setup-key hashes only for
// an explicitly marked development fixture. Production configuration never
// calls this path.
func (seed *Seed) FinalizeDev() {
	if !seed.Development {
		return
	}
	if seed.CommitteeParams == (model.CommitteeParams{}) {
		seed.CommitteeParams = model.DefaultCommitteeParams()
	}
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
		NetworkID:       seed.NetworkID,
		OverlayCIDR:     seed.OverlayCIDR,
		Users:           append([]model.User(nil), seed.Users...),
		Groups:          append([]model.Group(nil), seed.Groups...),
		Policies:        append([]model.Policy(nil), seed.Policies...),
		Routes:          append([]model.Route(nil), seed.Routes...),
		Budgets:         append([]model.TrafficBudget(nil), seed.Budgets...),
		SetupKeys:       append([]model.SetupKey(nil), seed.SetupKeys...),
		Nameservers:     append([]model.Nameserver(nil), seed.Nameservers...),
		Zones:           append([]model.DNSZone(nil), seed.Zones...),
		DNSSettings:     seed.DNSSettings,
		Settings:        seed.Settings,
		NextIPOffset:    seed.NextIPOffset,
		CommitteeConfig: seed.CommitteeParams.CommitteeConfig(0, nil),
	}
}

// BootstrapAddrInfos converts forwarding-capable committee managers into the
// libp2p addresses used for NAT traversal bootstrap. This preserves circuit
// relay only as a transport helper; it is no longer an overlay identity.
func (seed Seed) BootstrapAddrInfos() ([]peer.AddrInfo, error) {
	result := make([]peer.AddrInfo, 0, len(seed.Managers))
	for _, manager := range seed.Managers {
		if !manager.ForwardingEnabled || manager.PeerID == "" || manager.Address == "" {
			continue
		}
		addr, err := peer.AddrInfoFromString(manager.Address + "/p2p/" + manager.PeerID)
		if err != nil {
			return nil, fmt.Errorf("invalid manager address %q: %w", manager.Address, err)
		}
		result = append(result, *addr)
	}
	return result, nil
}
