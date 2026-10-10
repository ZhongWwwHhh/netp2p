package config

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"net/netip"
	"strings"

	"github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/netp2p/netp2p/internal/model"
	"github.com/netp2p/netp2p/internal/version"
)

const productionSecretBytes = 32

// ProductionManagerSpec is the operator input for one committee manager.
type ProductionManagerSpec struct {
	ID         string
	DNSName    string
	PublicIPv4 string
	Port       int
	WebRTCPort int
}

// ProductionMaterial is the complete set of documents needed to bootstrap a
// three-manager production network.
type ProductionMaterial struct {
	Manifest    NetworkManifest
	Bundles     []ManagerBundle
	ClientTrust ClientTrust
}

// GenerateProductionMaterial creates random Ed25519 manager identities and the
// shared manager tokens for a 3/0/3 committee. It never derives a key from a
// seed.
func GenerateProductionMaterial(networkID, overlayCIDR string, specs []ProductionManagerSpec) (ProductionMaterial, error) {
	if strings.TrimSpace(networkID) == "" {
		return ProductionMaterial{}, fmt.Errorf("network id is required")
	}
	if strings.TrimSpace(overlayCIDR) == "" {
		return ProductionMaterial{}, fmt.Errorf("overlay cidr is required")
	}
	if len(specs) != model.DefaultCommitteeSize {
		return ProductionMaterial{}, fmt.Errorf("production bootstrap requires exactly %d managers, got %d", model.DefaultCommitteeSize, len(specs))
	}
	if err := validateProductionSpecs(specs); err != nil {
		return ProductionMaterial{}, err
	}

	adminToken, err := randomProductionSecret()
	if err != nil {
		return ProductionMaterial{}, fmt.Errorf("generate admin token: %w", err)
	}
	sessionSecret, err := randomProductionSecret()
	if err != nil {
		return ProductionMaterial{}, fmt.Errorf("generate session secret: %w", err)
	}

	params := model.CommitteeParams{Size: 3, FaultLimit: 0, QuorumSize: 3}
	manifest := NetworkManifest{
		Version:         NetworkManifestVersion,
		NetworkID:       strings.TrimSpace(networkID),
		OverlayCIDR:     strings.TrimSpace(overlayCIDR),
		ProtocolVersion: version.ProtocolVersion,
		CommitteeParams: params,
		NextIPOffset:    11,
		Settings: model.NetworkSettings{
			DirectPathEnabled: true,
			ViaManagerEnabled: true,
			MaxManagerHops:    2,
		},
	}
	bundles := make([]ManagerBundle, 0, len(specs))

	for _, spec := range specs {
		privateKey, _, err := crypto.GenerateEd25519Key(rand.Reader)
		if err != nil {
			return ProductionMaterial{}, fmt.Errorf("generate identity for manager %q: %w", spec.ID, err)
		}
		peerID, err := peer.IDFromPrivateKey(privateKey)
		if err != nil {
			return ProductionMaterial{}, fmt.Errorf("derive peer id for manager %q: %w", spec.ID, err)
		}
		publicKey, err := privateKey.GetPublic().Raw()
		if err != nil {
			return ProductionMaterial{}, fmt.Errorf("encode public key for manager %q: %w", spec.ID, err)
		}
		encodedPrivateKey, err := crypto.MarshalPrivateKey(privateKey)
		if err != nil {
			return ProductionMaterial{}, fmt.Errorf("marshal private key for manager %q: %w", spec.ID, err)
		}

		webRTCPort := spec.WebRTCPort
		if webRTCPort == 0 {
			webRTCPort = 4101
		}
		manifest.Managers = append(manifest.Managers, model.CommitteeMember{
			ID:                spec.ID,
			PeerID:            peerID.String(),
			Address:           fmt.Sprintf("/dns4/%s/udp/%d/quic-v1", spec.DNSName, spec.Port),
			PublicKey:         publicKey,
			ListenAddr:        fmt.Sprintf("/ip4/0.0.0.0/udp/%d/webrtc-direct", webRTCPort),
			ForwardingEnabled: true,
		})
		bundles = append(bundles, ManagerBundle{
			Version:       ManagerBundleVersion,
			NetworkID:     manifest.NetworkID,
			ManagerID:     spec.ID,
			PrivateKey:    base64.StdEncoding.EncodeToString(encodedPrivateKey),
			AdminToken:    adminToken,
			SessionSecret: sessionSecret,
		})
	}

	if err := manifest.Validate(); err != nil {
		return ProductionMaterial{}, fmt.Errorf("validate generated manifest: %w", err)
	}
	clientTrust := manifest.ClientTrust()
	if err := clientTrust.Validate(); err != nil {
		return ProductionMaterial{}, fmt.Errorf("validate generated client trust: %w", err)
	}
	for index := range bundles {
		if err := bundles[index].Validate(manifest); err != nil {
			return ProductionMaterial{}, fmt.Errorf("validate generated manager bundle: %w", err)
		}
	}
	return ProductionMaterial{Manifest: manifest, Bundles: bundles, ClientTrust: clientTrust}, nil
}

func validateProductionSpecs(specs []ProductionManagerSpec) error {
	seenIDs := make(map[string]struct{}, len(specs))
	seenDNS := make(map[string]struct{}, len(specs))
	seenIPs := make(map[string]struct{}, len(specs))
	for index, spec := range specs {
		if err := validateManagerID(spec.ID); err != nil {
			return fmt.Errorf("manager %d: %w", index+1, err)
		}
		if err := validateDNSName(spec.DNSName); err != nil {
			return fmt.Errorf("manager %q: %w", spec.ID, err)
		}
		address, err := netip.ParseAddr(strings.TrimSpace(spec.PublicIPv4))
		if err != nil || !address.Is4() || !address.IsGlobalUnicast() || address.IsPrivate() || address.IsLoopback() || address.IsLinkLocalUnicast() {
			return fmt.Errorf("manager %q needs a public IPv4 address, got %q", spec.ID, spec.PublicIPv4)
		}
		if spec.Port < 1 || spec.Port > 65535 {
			return fmt.Errorf("manager %q port must be between 1 and 65535", spec.ID)
		}
		if spec.WebRTCPort < 0 || spec.WebRTCPort > 65535 {
			return fmt.Errorf("manager %q WebRTC port must be between 0 and 65535", spec.ID)
		}
		if spec.Port == spec.WebRTCPort {
			return fmt.Errorf("manager %q QUIC and WebRTC ports must differ", spec.ID)
		}
		if _, exists := seenIDs[spec.ID]; exists {
			return fmt.Errorf("duplicate manager id %q", spec.ID)
		}
		if _, exists := seenDNS[spec.DNSName]; exists {
			return fmt.Errorf("duplicate manager DNS name %q", spec.DNSName)
		}
		if _, exists := seenIPs[spec.PublicIPv4]; exists {
			return fmt.Errorf("duplicate manager IPv4 address %q", spec.PublicIPv4)
		}
		seenIDs[spec.ID] = struct{}{}
		seenDNS[spec.DNSName] = struct{}{}
		seenIPs[spec.PublicIPv4] = struct{}{}
	}
	return nil
}

func validateManagerID(value string) error {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" {
		return fmt.Errorf("id is required")
	}
	if len(trimmed) > 64 {
		return fmt.Errorf("id must be at most 64 characters")
	}
	for index, char := range trimmed {
		switch {
		case char >= 'a' && char <= 'z', char >= '0' && char <= '9':
		case char == '-':
			if index == 0 || index == len(trimmed)-1 {
				return fmt.Errorf("id %q must not begin or end with a hyphen", value)
			}
		default:
			return fmt.Errorf("id %q may contain only lowercase letters, digits, and hyphens", value)
		}
	}
	return nil
}

func validateDNSName(value string) error {
	trimmed := strings.ToLower(strings.TrimSpace(value))
	if trimmed == "" {
		return fmt.Errorf("dns name is required")
	}
	if len(trimmed) > 253 {
		return fmt.Errorf("dns name must be at most 253 characters")
	}
	labels := strings.Split(trimmed, ".")
	if len(labels) < 2 {
		return fmt.Errorf("dns name %q must be fully qualified", value)
	}
	for _, label := range labels {
		if label == "" || len(label) > 63 {
			return fmt.Errorf("dns name %q has an invalid label", value)
		}
		for index, char := range label {
			switch {
			case char >= 'a' && char <= 'z', char >= '0' && char <= '9':
			case char == '-':
				if index == 0 || index == len(label)-1 {
					return fmt.Errorf("dns name %q has a label with a leading or trailing hyphen", value)
				}
			default:
				return fmt.Errorf("dns name %q may contain only letters, digits, hyphens, and dots", value)
			}
		}
	}
	return nil
}

func randomProductionSecret() (string, error) {
	buffer := make([]byte, productionSecretBytes)
	if _, err := rand.Read(buffer); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(buffer), nil
}
