package main

import (
	stdrand "crypto/rand"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"strings"

	"github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/netp2p/netp2p/internal/config"
)

func runInitManagerJoin(args []string) error {
	flags := flag.NewFlagSet("init manager-join", flag.ContinueOnError)
	manifestPath := flags.String("manifest", "", "current public network manifest JSON")
	managerBundlePath := flags.String("manager-bundle", "", "an existing manager private bundle JSON")
	joinTokenFile := flags.String("join-token-file", "", "file containing the manager join token")
	output := flags.String("output", "", "output manager join bundle JSON")
	initDomain := flags.String("init-domain", "", "DNS name used to discover the current committee")
	webRTCPort := flags.Int("webrtc-port", 4101, "candidate public WebRTC UDP port")
	force := flags.Bool("force", false, "overwrite an existing output bundle")
	var manager productionManagerFlags
	flags.Var(&manager, "manager", "candidate manager input: id,dns-name,public-ipv4,quic-port")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if *manifestPath == "" || *managerBundlePath == "" || *joinTokenFile == "" ||
		*output == "" || *initDomain == "" || len(manager) != 1 {
		return fmt.Errorf("--manifest, --manager-bundle, --join-token-file, --output, --init-domain, and exactly one --manager are required")
	}

	manifest, err := config.LoadNetworkManifest(*manifestPath)
	if err != nil {
		return err
	}
	existingBundle, err := config.LoadManagerBundle(*managerBundlePath, manifest)
	if err != nil {
		return err
	}
	joinTokenData, err := os.ReadFile(*joinTokenFile)
	if err != nil {
		return fmt.Errorf("read manager join token: %w", err)
	}
	joinToken := strings.TrimSpace(string(joinTokenData))
	if len(joinToken) < 32 {
		return fmt.Errorf("manager join token must be at least 32 bytes")
	}

	spec := manager[0]
	spec.WebRTCPort = *webRTCPort
	if err := validateProductionManagerSpec(spec); err != nil {
		return err
	}
	privateKey, _, err := crypto.GenerateEd25519Key(stdrand.Reader)
	if err != nil {
		return fmt.Errorf("generate candidate identity: %w", err)
	}
	peerID, err := peer.IDFromPrivateKey(privateKey)
	if err != nil {
		return fmt.Errorf("derive candidate peer id: %w", err)
	}
	encodedPrivateKey, err := crypto.MarshalPrivateKey(privateKey)
	if err != nil {
		return fmt.Errorf("marshal candidate identity: %w", err)
	}
	bundle := config.ManagerJoinBundle{
		Version:       config.ManagerJoinBundleVersion,
		NetworkID:     manifest.NetworkID,
		ManagerID:     spec.ID,
		PrivateKey:    base64.StdEncoding.EncodeToString(encodedPrivateKey),
		AdminToken:    existingBundle.AdminToken,
		SessionSecret: existingBundle.SessionSecret,
		JoinToken:     joinToken,
		InitDomain:    strings.TrimSpace(*initDomain),
		Address:       fmt.Sprintf("/dns4/%s/udp/%d/quic-v1", spec.DNSName, spec.Port),
		QuicListen:    fmt.Sprintf("/ip4/0.0.0.0/udp/%d/quic-v1", spec.Port),
		ListenAddr:    fmt.Sprintf("/ip4/0.0.0.0/udp/%d/webrtc-direct", spec.WebRTCPort),
		TrustManagers: manifest.ClientTrust().Managers,
		OIDC:          manifest.OIDC,
	}
	if err := bundle.Validate(); err != nil {
		return err
	}
	if _, err := peer.Decode(peerID.String()); err != nil {
		return fmt.Errorf("validate candidate peer id: %w", err)
	}
	encoded, err := json.MarshalIndent(bundle, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(*output), 0o700); err != nil {
		return fmt.Errorf("create output directory: %w", err)
	}
	if err := writeProductionFile(*output, append(encoded, '\n'), 0o600, *force); err != nil {
		return fmt.Errorf("write manager join bundle: %w", err)
	}
	loaded, err := config.LoadManagerJoinBundle(*output)
	if err != nil {
		return err
	}
	member, err := loaded.PublicCommitteeMember()
	if err != nil {
		return err
	}
	if member.ID != spec.ID || member.PeerID != peerID.String() {
		return fmt.Errorf("written manager join bundle failed round-trip validation")
	}
	fmt.Printf("Manager join bundle: %s (0600)\n", *output)
	fmt.Printf("Candidate manager: %s\n", spec.ID)
	fmt.Printf("Committee discovery: %s\n", loaded.InitDomain)
	return nil
}

func validateProductionManagerSpec(spec config.ProductionManagerSpec) error {
	if spec.ID == "" || spec.DNSName == "" || spec.PublicIPv4 == "" || spec.Port == 0 {
		return fmt.Errorf("manager id, dns-name, public-ipv4, and quic-port are required")
	}
	if spec.WebRTCPort == 0 {
		spec.WebRTCPort = 4101
	}
	if spec.Port < 1 || spec.Port > 65535 || spec.WebRTCPort < 1 || spec.WebRTCPort > 65535 {
		return fmt.Errorf("manager ports must be between 1 and 65535")
	}
	address, err := netip.ParseAddr(strings.TrimSpace(spec.PublicIPv4))
	if err != nil || !address.Is4() || !address.IsGlobalUnicast() {
		return fmt.Errorf("public-ipv4 must be a global unicast IPv4 address")
	}
	return nil
}
