package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/netp2p/netp2p/internal/config"
	"github.com/netp2p/netp2p/internal/model"
)

type productionManagerFlags []config.ProductionManagerSpec

func (managers *productionManagerFlags) String() string {
	values := make([]string, 0, len(*managers))
	for _, manager := range *managers {
		values = append(values, fmt.Sprintf("%s,%s,%s,%d", manager.ID, manager.DNSName, manager.PublicIPv4, manager.Port))
	}
	return strings.Join(values, " ")
}

func (managers *productionManagerFlags) Set(value string) error {
	fields := strings.Split(value, ",")
	if len(fields) != 4 {
		return fmt.Errorf("manager must be id,dns-name,public-ipv4,quic-port")
	}
	port, err := strconv.Atoi(strings.TrimSpace(fields[3]))
	if err != nil {
		return fmt.Errorf("manager QUIC port: %w", err)
	}
	*managers = append(*managers, config.ProductionManagerSpec{
		ID: strings.TrimSpace(fields[0]), DNSName: strings.TrimSpace(fields[1]),
		PublicIPv4: strings.TrimSpace(fields[2]), Port: port,
	})
	return nil
}

func runInitProduction(args []string) error {
	flags := flag.NewFlagSet("init production", flag.ContinueOnError)
	network := flags.String("network", "netp2p-production", "network id")
	overlayCIDR := flags.String("overlay-cidr", "100.64.0.0/24", "overlay CIDR")
	outputDir := flags.String("output-dir", "", "output directory for bootstrap documents")
	webRTCPort := flags.Int("webrtc-port", 4101, "public WebRTC UDP port")
	showSecrets := flags.Bool("show-secrets", false, "print shared admin and session tokens once")
	force := flags.Bool("force", false, "overwrite existing output documents")
	var managers productionManagerFlags
	flags.Var(&managers, "manager", "manager input: id,dns-name,public-ipv4,quic-port (repeat at least three times)")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if *outputDir == "" {
		return fmt.Errorf("--output-dir is required")
	}
	if len(managers) < 3 {
		return fmt.Errorf("at least three --manager inputs are required, got %d", len(managers))
	}
	specs := make([]config.ProductionManagerSpec, len(managers))
	for index, manager := range managers {
		manager.WebRTCPort = *webRTCPort
		specs[index] = manager
	}

	material, err := config.GenerateProductionMaterial(*network, *overlayCIDR, specs)
	if err != nil {
		return err
	}
	params := material.Manifest.CommitteeParams
	manifestPath := filepath.Join(*outputDir, "network.json")
	clientTrustPath := filepath.Join(*outputDir, "client-trust.json")
	ownerBootstrapPath := filepath.Join(*outputDir, "owner-bootstrap.txt")
	instructionsPath := filepath.Join(*outputDir, "README.txt")
	managerJoinTokenPath := filepath.Join(*outputDir, "manager-join-token.txt")
	bundlePaths := make([]string, len(material.Bundles))
	for index, bundle := range material.Bundles {
		bundlePaths[index] = filepath.Join(*outputDir, "manager-"+bundle.ManagerID+".json")
	}
	expected := append([]string{manifestPath, clientTrustPath, ownerBootstrapPath, instructionsPath, managerJoinTokenPath}, bundlePaths...)
	if !*force {
		for _, path := range expected {
			if _, err := os.Lstat(path); err == nil {
				return fmt.Errorf("%s already exists; use --force to replace it", path)
			} else if !os.IsNotExist(err) {
				return err
			}
		}
	}
	if err := os.MkdirAll(*outputDir, 0o700); err != nil {
		return fmt.Errorf("create output directory: %w", err)
	}

	writeJSON := func(path string, value any, mode fs.FileMode) error {
		encoded, err := json.MarshalIndent(value, "", "  ")
		if err != nil {
			return err
		}
		return writeProductionFile(path, append(encoded, '\n'), mode, *force)
	}
	if err := writeJSON(manifestPath, material.Manifest, 0o644); err != nil {
		return fmt.Errorf("write network manifest: %w", err)
	}
	if err := writeJSON(clientTrustPath, material.ClientTrust, 0o644); err != nil {
		return fmt.Errorf("write client trust: %w", err)
	}
	for index, bundle := range material.Bundles {
		if err := writeJSON(bundlePaths[index], bundle, 0o600); err != nil {
			return fmt.Errorf("write manager bundle: %w", err)
		}
	}
	if err := writeProductionFile(ownerBootstrapPath, []byte(ownerBootstrapInstructions(specs)), 0o644, *force); err != nil {
		return fmt.Errorf("write owner bootstrap instructions: %w", err)
	}
	if err := writeProductionFile(managerJoinTokenPath, []byte(material.ManagerJoinToken+"\n"), 0o600, *force); err != nil {
		return fmt.Errorf("write manager join token: %w", err)
	}
	if err := writeProductionFile(instructionsPath, []byte(productionInstructions(*network, specs, params)), 0o644, *force); err != nil {
		return fmt.Errorf("write deployment instructions: %w", err)
	}

	if _, err := config.LoadNetworkManifest(manifestPath); err != nil {
		return fmt.Errorf("validate written manifest: %w", err)
	}
	if _, err := config.LoadClientTrust(clientTrustPath); err != nil {
		return fmt.Errorf("validate written client trust: %w", err)
	}
	for index, spec := range specs {
		bundle, err := config.LoadManagerBundle(bundlePaths[index], material.Manifest)
		if err != nil {
			return fmt.Errorf("validate written manager bundle: %w", err)
		}
		if bundle.ManagerID != spec.ID {
			return fmt.Errorf("manager bundle order changed while writing")
		}
	}

	fmt.Printf("Production network %s initialized with committee %d/%d/%d.\n",
		*network, params.Size, params.FaultLimit, params.QuorumSize)
	fmt.Printf("Output directory: %s\n", *outputDir)
	fmt.Printf("Public manifest: %s (0644)\n", manifestPath)
	fmt.Printf("Client trust: %s (0644)\n", clientTrustPath)
	fmt.Printf("Manager join token: %s (0600)\n", managerJoinTokenPath)
	for index, path := range bundlePaths {
		fmt.Printf("Manager bundle: %s (0600, %s only)\n", path, material.Bundles[index].ManagerID)
	}
	fmt.Printf("Owner bootstrap: %s\n", ownerBootstrapPath)
	fmt.Printf("Deployment instructions: %s\n", instructionsPath)
	if *showSecrets {
		fmt.Printf("\nShared admin token (shown once):\n  %s\n", material.Bundles[0].AdminToken)
		fmt.Printf("Shared session secret (shown once):\n  %s\n", material.Bundles[0].SessionSecret)
	}
	return nil
}

func writeProductionFile(path string, data []byte, mode fs.FileMode, overwrite bool) error {
	if !overwrite {
		if _, err := os.Lstat(path); err == nil {
			return fmt.Errorf("file already exists")
		} else if !os.IsNotExist(err) {
			return err
		}
	}
	temporary, err := os.CreateTemp(filepath.Dir(path), ".netp2p-bootstrap-*")
	if err != nil {
		return err
	}
	temporaryPath := temporary.Name()
	defer os.Remove(temporaryPath)
	if err := temporary.Chmod(mode); err != nil {
		temporary.Close()
		return err
	}
	if _, err := temporary.Write(data); err != nil {
		temporary.Close()
		return err
	}
	if err := temporary.Sync(); err != nil {
		temporary.Close()
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	if overwrite {
		if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
			return err
		}
	}
	return os.Rename(temporaryPath, path)
}

func ownerBootstrapInstructions(specs []config.ProductionManagerSpec) string {
	var builder strings.Builder
	builder.WriteString("NetP2P first owner bootstrap\n\n")
	builder.WriteString("This generator intentionally stores no owner password and creates no owner bootstrap token.\n")
	builder.WriteString("Use the existing first-run Web/API owner setup flow after every manager is healthy.\n\n")
	builder.WriteString("Web:\n")
	fmt.Fprintf(&builder, "  https://%s:9443\n", specs[0].DNSName)
	builder.WriteString("\nAPI:\n")
	builder.WriteString("  GET  /api/v1/bootstrap/status\n")
	builder.WriteString("  POST /api/v1/bootstrap/owner\n")
	builder.WriteString("  Content-Type: application/json\n")
	builder.WriteString("  {\"email\":\"owner@example.com\",\"name\":\"Owner\",\"password\":\"at-least-12-characters\"}\n\n")
	builder.WriteString("The endpoint is available only while no owner exists. Creating the first owner disables it\n")
	builder.WriteString("permanently for that certified network; later calls return HTTP 409.\n")
	return builder.String()
}

func productionInstructions(network string, specs []config.ProductionManagerSpec, params model.CommitteeParams) string {
	var builder strings.Builder
	fmt.Fprintf(&builder, "NetP2P production bootstrap for %s\n\n", network)
	builder.WriteString("Files:\n")
	builder.WriteString("  network.json       public NetworkManifest (0644)\n")
	builder.WriteString("  client-trust.json  public ClientTrust (0644)\n")
	builder.WriteString("  manager-join-token.txt private manager enrollment token (0600)\n")
	builder.WriteString("  manager-<id>.json  private ManagerBundle (0600)\n")
	builder.WriteString("  owner-bootstrap.txt first-owner setup guide (0644)\n\n")
	builder.WriteString("The output directory is created with mode 0700. Manager bundles contain that manager's\n")
	builder.WriteString("Ed25519 private key plus the shared admin and session tokens. Do not commit or archive\n")
	builder.WriteString("this directory in source control. If any bundle is exposed before deployment, discard this\n")
	builder.WriteString("material and generate a new bootstrap set.\n\n")
	builder.WriteString("Cloudflare DNS (grey cloud, not proxied):\n")
	for _, spec := range specs {
		fmt.Fprintf(&builder, "  %-32s A %s\n", spec.DNSName, spec.PublicIPv4)
	}
	builder.WriteString("\nAnsible vault variables in ansible/netp2p/vaults/secrets.yaml:\n")
	builder.WriteString("  vault_netp2p_manifest_json: contents of network.json\n")
	builder.WriteString("  vault_netp2p_client_trust_json: contents of client-trust.json\n")
	builder.WriteString("  vault_netp2p_manager_bundles:\n")
	for _, spec := range specs {
		fmt.Fprintf(&builder, "    %s: contents of manager-%s.json\n", spec.ID, spec.ID)
	}
	builder.WriteString("\nThe vault map keys must equal each inventory host's netp2p_manager_id. Only the matching\n")
	builder.WriteString("bundle is copied to a manager. Keep the Cloudflare DNS token in the same encrypted vault.\n\n")
	builder.WriteString("Deployment:\n")
	builder.WriteString("  ansible-playbook netp2p/playbooks/dns.yaml\n")
	builder.WriteString("  ansible-playbook netp2p/playbooks/install.yaml\n\n")
	fmt.Fprintf(&builder, "The committee is %d/%d/%d. It tolerates %d manager outages for reads and writes, but upgrades and\n",
		params.Size, params.FaultLimit, params.QuorumSize, params.FaultLimit)
	builder.WriteString("rollbacks must still pre-create every manager container and start or stop them together. Treat this\n")
	builder.WriteString("as a maintenance window and validate quorum health before making changes.\n\n")
	builder.WriteString("After health validation, complete owner setup using owner-bootstrap.txt. No owner secret is\n")
	builder.WriteString("written to the manifest, a manager bundle, or client trust.\n")
	return builder.String()
}
