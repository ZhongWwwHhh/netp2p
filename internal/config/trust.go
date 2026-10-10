package config

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/netip"
	"os"

	"github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/netp2p/netp2p/internal/model"
	"github.com/netp2p/netp2p/internal/oidc"
	"github.com/netp2p/netp2p/internal/version"
)

const (
	NetworkManifestVersion = 1
	ManagerBundleVersion   = 1
	ClientTrustVersion     = 1
)

// NetworkManifest is the public, secret-free description of a network. It is
// safe to distribute to every manager and to publish for operator reference.
type NetworkManifest struct {
	Version         int                     `json:"version"`
	NetworkID       string                  `json:"networkId"`
	OverlayCIDR     string                  `json:"overlayCidr"`
	ProtocolVersion string                  `json:"protocolVersion"`
	CommitteeParams model.CommitteeParams   `json:"committeeParams"`
	Managers        []model.CommitteeMember `json:"managers"`
	Groups          []model.Group           `json:"groups,omitempty"`
	Policies        []model.Policy          `json:"policies,omitempty"`
	Routes          []model.Route           `json:"routes,omitempty"`
	Budgets         []model.TrafficBudget   `json:"budgets,omitempty"`
	Nameservers     []model.Nameserver      `json:"nameservers,omitempty"`
	Zones           []model.DNSZone         `json:"zones,omitempty"`
	DNSSettings     model.DNSSettings       `json:"dnsSettings,omitempty"`
	Settings        model.NetworkSettings   `json:"settings,omitempty"`
	OIDC            oidc.Config             `json:"oidc,omitempty"`
	NextIPOffset    uint32                  `json:"nextIpOffset"`
}

// ManagerBundle contains only the private material one manager needs. It must
// never contain another manager's key or a setup-key secret.
type ManagerBundle struct {
	Version   int    `json:"version"`
	NetworkID string `json:"networkId"`
	ManagerID string `json:"managerId"`
	// PrivateKey is base64(libp2p MarshalPrivateKey) for an Ed25519 key.
	PrivateKey string `json:"privateKey"`
	AdminToken string `json:"adminToken"`
	// SessionSecret is the only other shared token a manager needs locally.
	SessionSecret string `json:"sessionSecret"`

	key crypto.PrivKey
}

// ClientTrust is the minimal bootstrap material distributed to clients. It
// contains no seed, admin token, setup key, password hash, or private key.
type ClientTrust struct {
	Version         int                     `json:"version"`
	NetworkID       string                  `json:"networkId"`
	ProtocolVersion string                  `json:"protocolVersion"`
	Managers        []model.CommitteeMember `json:"managers"`
}

func LoadNetworkManifest(path string) (NetworkManifest, error) {
	var manifest NetworkManifest
	if err := decodeStrictFile(path, &manifest); err != nil {
		return NetworkManifest{}, fmt.Errorf("decode network manifest: %w", err)
	}
	if err := manifest.Validate(); err != nil {
		return NetworkManifest{}, fmt.Errorf("invalid network manifest: %w", err)
	}
	return manifest, nil
}

func LoadManagerBundle(path string, manifest NetworkManifest) (ManagerBundle, error) {
	var bundle ManagerBundle
	if err := decodeStrictFile(path, &bundle); err != nil {
		return ManagerBundle{}, fmt.Errorf("decode manager bundle: %w", err)
	}
	if err := bundle.Validate(manifest); err != nil {
		return ManagerBundle{}, fmt.Errorf("invalid manager bundle: %w", err)
	}
	return bundle, nil
}

func LoadClientTrust(path string) (ClientTrust, error) {
	var trust ClientTrust
	if err := decodeStrictFile(path, &trust); err != nil {
		return ClientTrust{}, fmt.Errorf("decode client trust bundle: %w", err)
	}
	if err := trust.Validate(); err != nil {
		return ClientTrust{}, fmt.Errorf("invalid client trust bundle: %w", err)
	}
	return trust, nil
}

func decodeStrictFile(path string, value any) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	return decoder.Decode(value)
}

func (manifest NetworkManifest) Validate() error {
	if manifest.Version != NetworkManifestVersion {
		return fmt.Errorf("unsupported version %d (want %d)", manifest.Version, NetworkManifestVersion)
	}
	if manifest.NetworkID == "" || manifest.OverlayCIDR == "" {
		return fmt.Errorf("networkId and overlayCidr are required")
	}
	if _, err := netip.ParsePrefix(manifest.OverlayCIDR); err != nil {
		return fmt.Errorf("invalid overlayCidr %q: %w", manifest.OverlayCIDR, err)
	}
	if manifest.ProtocolVersion != version.ProtocolVersion {
		return fmt.Errorf("protocol version %q does not match binary %q", manifest.ProtocolVersion, version.ProtocolVersion)
	}
	params := manifest.CommitteeParams
	if params == (model.CommitteeParams{}) {
		params = model.DefaultCommitteeParams()
	}
	if err := params.Validate(); err != nil {
		return err
	}
	if len(manifest.Managers) != params.Size {
		return fmt.Errorf("committee has %d managers, want %d", len(manifest.Managers), params.Size)
	}
	seenIDs := make(map[string]struct{}, len(manifest.Managers))
	seenPeers := make(map[string]struct{}, len(manifest.Managers))
	for index := range manifest.Managers {
		member := manifest.Managers[index]
		if member.ID == "" || member.Address == "" || member.PeerID == "" {
			return fmt.Errorf("manager %d needs id, address, and peerId", index)
		}
		if member.KeySeed != 0 {
			return fmt.Errorf("manager %q contains deterministic keySeed", member.ID)
		}
		if len(member.PublicKey) == 0 {
			return fmt.Errorf("manager %q needs publicKey", member.ID)
		}
		peerID, err := peer.Decode(member.PeerID)
		if err != nil {
			return fmt.Errorf("manager %q has invalid peerId: %w", member.ID, err)
		}
		publicKey, err := peerID.ExtractPublicKey()
		if err != nil || publicKey == nil {
			return fmt.Errorf("manager %q peerId does not carry a public key", member.ID)
		}
		publicKeyRaw, err := publicKey.Raw()
		if err != nil || !bytes.Equal(publicKeyRaw, member.PublicKey) {
			return fmt.Errorf("manager %q publicKey does not match peerId", member.ID)
		}
		if _, exists := seenIDs[member.ID]; exists {
			return fmt.Errorf("duplicate manager id %q", member.ID)
		}
		if _, exists := seenPeers[member.PeerID]; exists {
			return fmt.Errorf("duplicate manager peerId %q", member.PeerID)
		}
		seenIDs[member.ID] = struct{}{}
		seenPeers[member.PeerID] = struct{}{}
		if _, err := peer.AddrInfoFromString(member.Address + "/p2p/" + member.PeerID); err != nil {
			return fmt.Errorf("manager %q has invalid address: %w", member.ID, err)
		}
	}
	return nil
}

func (manifest NetworkManifest) Manager(managerID string) (model.CommitteeMember, bool) {
	for _, member := range manifest.Managers {
		if member.ID == managerID {
			return sanitizeCommitteeMember(member), true
		}
	}
	return model.CommitteeMember{}, false
}

func (manifest NetworkManifest) NetworkState(committeeConfig model.CommitteeConfig) model.NetworkState {
	managers := make([]model.CommitteeMember, 0, len(manifest.Managers))
	for _, member := range manifest.Managers {
		managers = append(managers, sanitizeCommitteeMember(member))
	}
	nextIPOffset := manifest.NextIPOffset
	if nextIPOffset == 0 {
		nextIPOffset = 11
	}
	return model.NetworkState{
		NetworkID: manifest.NetworkID, OverlayCIDR: manifest.OverlayCIDR,
		Groups:      append([]model.Group(nil), manifest.Groups...),
		Policies:    append([]model.Policy(nil), manifest.Policies...),
		Routes:      append([]model.Route(nil), manifest.Routes...),
		Budgets:     append([]model.TrafficBudget(nil), manifest.Budgets...),
		Nameservers: append([]model.Nameserver(nil), manifest.Nameservers...),
		Zones:       append([]model.DNSZone(nil), manifest.Zones...),
		DNSSettings: manifest.DNSSettings, Settings: manifest.Settings,
		NextIPOffset: nextIPOffset, CommitteeConfig: committeeConfig,
		EngineCommittee: managers,
	}
}

func (manifest NetworkManifest) BootstrapAddrInfos() ([]peer.AddrInfo, error) {
	result := make([]peer.AddrInfo, 0, len(manifest.Managers))
	for _, manager := range manifest.Managers {
		if !manager.ForwardingEnabled || manager.PeerID == "" || manager.Address == "" {
			continue
		}
		info, err := peer.AddrInfoFromString(manager.Address + "/p2p/" + manager.PeerID)
		if err != nil {
			return nil, fmt.Errorf("invalid manager address %q: %w", manager.Address, err)
		}
		result = append(result, *info)
	}
	return result, nil
}

func (manifest NetworkManifest) ClientTrust() ClientTrust {
	return ClientTrust{
		Version: ClientTrustVersion, NetworkID: manifest.NetworkID,
		ProtocolVersion: manifest.ProtocolVersion,
		Managers:        sanitizeCommittee(manifest.Managers),
	}
}

func (bundle *ManagerBundle) Validate(manifest NetworkManifest) error {
	if bundle.Version != ManagerBundleVersion {
		return fmt.Errorf("unsupported version %d (want %d)", bundle.Version, ManagerBundleVersion)
	}
	if bundle.NetworkID == "" || bundle.ManagerID == "" || bundle.PrivateKey == "" {
		return fmt.Errorf("networkId, managerId, and privateKey are required")
	}
	if bundle.AdminToken == "" || bundle.SessionSecret == "" {
		return fmt.Errorf("adminToken and sessionSecret are required")
	}
	if len(bundle.AdminToken) < 32 {
		return fmt.Errorf("adminToken must be at least 32 bytes")
	}
	if len(bundle.SessionSecret) < 32 {
		return fmt.Errorf("sessionSecret must be at least 32 bytes")
	}
	if bundle.NetworkID != manifest.NetworkID {
		return fmt.Errorf("bundle network %q does not match manifest %q", bundle.NetworkID, manifest.NetworkID)
	}
	member, ok := manifest.Manager(bundle.ManagerID)
	if !ok {
		return fmt.Errorf("manager %q is not in the network manifest", bundle.ManagerID)
	}
	encoded, err := base64.StdEncoding.DecodeString(bundle.PrivateKey)
	if err != nil {
		return fmt.Errorf("privateKey is not valid base64: %w", err)
	}
	key, err := crypto.UnmarshalPrivateKey(encoded)
	if err != nil {
		return fmt.Errorf("privateKey is not a libp2p private key: %w", err)
	}
	if key.Type() != crypto.Ed25519 {
		return fmt.Errorf("privateKey must be Ed25519")
	}
	peerID, err := peer.IDFromPrivateKey(key)
	if err != nil {
		return fmt.Errorf("derive privateKey peerId: %w", err)
	}
	if peerID.String() != member.PeerID {
		return fmt.Errorf("privateKey belongs to %s, not manager %s", peerID, member.PeerID)
	}
	bundle.key = key
	return nil
}

// IdentityKey returns the parsed local libp2p identity key.
func (bundle ManagerBundle) IdentityKey() crypto.PrivKey { return bundle.key }

func (trust ClientTrust) Validate() error {
	if trust.Version != ClientTrustVersion {
		return fmt.Errorf("unsupported version %d (want %d)", trust.Version, ClientTrustVersion)
	}
	if trust.NetworkID == "" || trust.ProtocolVersion == "" || len(trust.Managers) == 0 {
		return fmt.Errorf("networkId, protocolVersion, and managers are required")
	}
	if trust.ProtocolVersion != version.ProtocolVersion {
		return fmt.Errorf("protocol version %q does not match binary %q", trust.ProtocolVersion, version.ProtocolVersion)
	}
	seen := make(map[string]struct{}, len(trust.Managers))
	for index, member := range trust.Managers {
		if member.ID == "" || member.Address == "" || member.PeerID == "" {
			return fmt.Errorf("manager %d needs id, address, and peerId", index)
		}
		if member.KeySeed != 0 || len(member.PublicKey) == 0 {
			return fmt.Errorf("manager %q must carry publicKey and no keySeed", member.ID)
		}
		peerID, err := peer.Decode(member.PeerID)
		if err != nil {
			return fmt.Errorf("manager %q has invalid peerId: %w", member.ID, err)
		}
		publicKey, err := peerID.ExtractPublicKey()
		if err != nil || publicKey == nil {
			return fmt.Errorf("manager %q peerId does not carry a public key", member.ID)
		}
		publicKeyRaw, err := publicKey.Raw()
		if err != nil || !bytes.Equal(publicKeyRaw, member.PublicKey) {
			return fmt.Errorf("manager %q publicKey does not match peerId", member.ID)
		}
		if _, err := peer.AddrInfoFromString(member.Address + "/p2p/" + member.PeerID); err != nil {
			return fmt.Errorf("manager %q has invalid address: %w", member.ID, err)
		}
		if _, exists := seen[member.ID]; exists {
			return fmt.Errorf("duplicate manager id %q", member.ID)
		}
		seen[member.ID] = struct{}{}
	}
	return nil
}

func sanitizeCommittee(members []model.CommitteeMember) []model.CommitteeMember {
	result := make([]model.CommitteeMember, 0, len(members))
	for _, member := range members {
		result = append(result, sanitizeCommitteeMember(member))
	}
	return result
}

func sanitizeCommitteeMember(member model.CommitteeMember) model.CommitteeMember {
	member.KeySeed = 0
	return member
}
