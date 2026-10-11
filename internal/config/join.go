package config

import (
	"encoding/base64"
	"fmt"
	"strings"

	"github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/multiformats/go-multiaddr"
	"github.com/netp2p/netp2p/internal/model"
	"github.com/netp2p/netp2p/internal/oidc"
)

const ManagerJoinBundleVersion = 1

// ManagerJoinBundle is the private document staged on a candidate manager
// before an administrator approves it. It carries the candidate identity, the
// one-time enrollment token, and the shared manager runtime secrets needed after
// activation. It must never be published or copied into client trust.
type ManagerJoinBundle struct {
	Version       int                     `json:"version"`
	NetworkID     string                  `json:"networkId"`
	ManagerID     string                  `json:"managerId"`
	PrivateKey    string                  `json:"privateKey"`
	AdminToken    string                  `json:"adminToken"`
	SessionSecret string                  `json:"sessionSecret"`
	JoinToken     string                  `json:"joinToken"`
	InitDomain    string                  `json:"initDomain"`
	Address       string                  `json:"address"`
	QuicListen    string                  `json:"quicListen"`
	ListenAddr    string                  `json:"listenAddr"`
	TrustManagers []model.CommitteeMember `json:"trustManagers"`
	OIDC          oidc.Config             `json:"oidc,omitempty"`

	key crypto.PrivKey
}

func LoadManagerJoinBundle(path string) (ManagerJoinBundle, error) {
	var bundle ManagerJoinBundle
	if err := decodeStrictFile(path, &bundle); err != nil {
		return ManagerJoinBundle{}, fmt.Errorf("decode manager join bundle: %w", err)
	}
	if err := bundle.Validate(); err != nil {
		return ManagerJoinBundle{}, fmt.Errorf("invalid manager join bundle: %w", err)
	}
	return bundle, nil
}

func (bundle *ManagerJoinBundle) Validate() error {
	if bundle.Version != ManagerJoinBundleVersion {
		return fmt.Errorf("unsupported version %d (want %d)", bundle.Version, ManagerJoinBundleVersion)
	}
	if bundle.NetworkID == "" || bundle.ManagerID == "" || bundle.PrivateKey == "" {
		return fmt.Errorf("networkId, managerId, and privateKey are required")
	}
	if len(bundle.AdminToken) < 32 || len(bundle.SessionSecret) < 32 || len(bundle.JoinToken) < 32 {
		return fmt.Errorf("adminToken, sessionSecret, and joinToken must each be at least 32 bytes")
	}
	if bundle.InitDomain == "" || bundle.Address == "" || bundle.QuicListen == "" || bundle.ListenAddr == "" {
		return fmt.Errorf("initDomain, address, quicListen, and listenAddr are required")
	}
	if strings.ContainsAny(bundle.JoinToken, " \t\r\n") {
		return fmt.Errorf("joinToken must not contain whitespace")
	}
	if _, err := multiaddr.NewMultiaddr(bundle.Address); err != nil {
		return fmt.Errorf("invalid manager address %q: %w", bundle.Address, err)
	}
	if _, err := multiaddr.NewMultiaddr(bundle.ListenAddr); err != nil {
		return fmt.Errorf("invalid manager listen address %q: %w", bundle.ListenAddr, err)
	}
	if _, err := multiaddr.NewMultiaddr(bundle.QuicListen); err != nil {
		return fmt.Errorf("invalid manager QUIC listen address %q: %w", bundle.QuicListen, err)
	}
	if len(bundle.TrustManagers) == 0 {
		return fmt.Errorf("trustManagers are required")
	}
	seen := make(map[string]struct{}, len(bundle.TrustManagers))
	for _, member := range bundle.TrustManagers {
		if member.ID == "" || member.Address == "" || member.PeerID == "" || len(member.PublicKey) == 0 {
			return fmt.Errorf("trust manager %q needs id, address, peerId, and publicKey", member.ID)
		}
		if _, err := peer.AddrInfoFromString(member.Address + "/p2p/" + member.PeerID); err != nil {
			return fmt.Errorf("invalid trust manager address for %q: %w", member.ID, err)
		}
		if member.KeySeed != 0 {
			return fmt.Errorf("trust manager %q must not carry a keySeed", member.ID)
		}
		if _, exists := seen[member.ID]; exists {
			return fmt.Errorf("duplicate trust manager %q", member.ID)
		}
		seen[member.ID] = struct{}{}
	}
	if _, exists := seen[bundle.ManagerID]; exists {
		return fmt.Errorf("candidate manager %q is already in trustManagers", bundle.ManagerID)
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
	bundle.key = key
	return nil
}

// IdentityKey returns the parsed candidate libp2p identity.
func (bundle ManagerJoinBundle) IdentityKey() crypto.PrivKey { return bundle.key }

// PublicCommitteeMember is the certified shape advertised in the join request.
func (bundle ManagerJoinBundle) PublicCommitteeMember() (model.CommitteeMember, error) {
	key := bundle.IdentityKey()
	if key == nil {
		return model.CommitteeMember{}, fmt.Errorf("manager join bundle is not initialized")
	}
	peerID, err := peer.IDFromPrivateKey(key)
	if err != nil {
		return model.CommitteeMember{}, fmt.Errorf("derive candidate peerId: %w", err)
	}
	publicKey, err := key.GetPublic().Raw()
	if err != nil {
		return model.CommitteeMember{}, fmt.Errorf("encode candidate publicKey: %w", err)
	}
	return model.CommitteeMember{
		ID: bundle.ManagerID, PeerID: peerID.String(), Address: bundle.Address,
		PublicKey: publicKey, ListenAddr: bundle.ListenAddr, ForwardingEnabled: true,
	}, nil
}

// PublicKeyBytes returns the raw candidate public key for the join request.
func (bundle ManagerJoinBundle) PublicKeyBytes() ([]byte, error) {
	member, err := bundle.PublicCommitteeMember()
	if err != nil {
		return nil, err
	}
	if len(member.PublicKey) == 0 {
		return nil, fmt.Errorf("candidate publicKey is empty")
	}
	return append([]byte(nil), member.PublicKey...), nil
}
