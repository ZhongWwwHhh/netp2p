package main

import (
	"bufio"
	"crypto/rand"
	"encoding/binary"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/netp2p/netp2p/internal/config"
	"github.com/netp2p/netp2p/internal/model"
)

type bootstrapRecord struct {
	NetworkID string         `json:"networkId"`
	Owner     model.User     `json:"owner"`
	Group     model.Group    `json:"group"`
	Policy    model.Policy   `json:"policy"`
	SetupKey  model.SetupKey `json:"setupKey"`
}

func runInitNetwork(args []string) error {
	flags := flag.NewFlagSet("init network", flag.ContinueOnError)
	network := flags.String("network", "netp2p", "network id")
	dataDir := flags.String("data-dir", defaultDataDir(), "data directory")
	ownerEmail := flags.String("owner-email", "", "owner account email")
	ownerName := flags.String("owner-name", "Network Owner", "owner account name")
	ownerPasswordFile := flags.String("owner-password-file", "", "file containing the owner password; generated when empty")
	seedPath := flags.String("seed", "", "output seed JSON path")
	configPath := flags.String("config", "", "output runtime YAML path")
	setupKeyPath := flags.String("setup-key-file", "", "output setup key file path")
	showSecrets := flags.Bool("show-secrets", false, "print generated secrets once")
	nonInteractive := flags.Bool("yes", false, "do not prompt for missing values")
	if err := flags.Parse(args); err != nil {
		return err
	}
	reader := bufio.NewReader(os.Stdin)
	if !*nonInteractive {
		if *ownerEmail == "" {
			fmt.Print("Owner email: ")
			value, _ := reader.ReadString('\n')
			*ownerEmail = strings.TrimSpace(value)
		}
		if *ownerName == "Network Owner" {
			fmt.Print("Owner name [Network Owner]: ")
			value, _ := reader.ReadString('\n')
			if trimmed := strings.TrimSpace(value); trimmed != "" {
				*ownerName = trimmed
			}
		}
	}
	if *ownerEmail == "" {
		return fmt.Errorf("--owner-email is required")
	}
	if *seedPath == "" {
		*seedPath = filepath.Join(*dataDir, "seed.json")
	}
	if *configPath == "" {
		*configPath = filepath.Join(*dataDir, "runtime.yaml")
	}
	ownerPassword, err := resolveOwnerPassword(*ownerPasswordFile, *nonInteractive, reader)
	if err != nil {
		return err
	}
	if *setupKeyPath == "" {
		*setupKeyPath = filepath.Join(*dataDir, "setup-key.txt")
	}

	seed, token, err := buildInitialSeed(*network)
	if err != nil {
		return err
	}
	owner := model.User{
		ID: "owner", Email: *ownerEmail, Name: *ownerName, Role: model.RoleOwner,
		AutoGroups: []string{"owners"}, Issued: model.GroupIssuedAPI,
		PasswordVerifier: model.HashPassword(ownerPassword),
	}
	group := model.Group{
		ID: "owners", Name: "Owners", UserIDs: []string{owner.ID}, Issued: model.GroupIssuedAPI,
	}
	policy := model.Policy{
		ID: "allow-owners-all", SourceGroups: []string{"owners"}, DestinationGroups: []string{"owners"},
		Services: []model.Service{
			{Protocol: "icmp"},
			{Protocol: "tcp", StartPort: 0, EndPort: 65535},
			{Protocol: "udp", StartPort: 0, EndPort: 65535},
		},
		Effect: model.EffectAllow, Direction: model.DirectionBidirectional,
	}
	seed.Groups = []model.Group{group}
	seed.Users = []model.User{owner}
	seed.Policies = []model.Policy{policy}
	seed.SetupKeys = []model.SetupKey{{
		ID: "initial-setup-key", Name: "Initial setup key", Token: token,
		TokenPrefix: token[:8], Type: model.SetupKeyReusable, Groups: []string{"owners"},
	}}
	seed.FinalizeDev()
	seed.SetupKeys[0].Token = ""

	if err := os.MkdirAll(*dataDir, 0o700); err != nil {
		return err
	}
	seedBody, err := json.MarshalIndent(seed, "", "  ")
	if err != nil {
		return err
	}
	if err := os.WriteFile(*seedPath, seedBody, 0o600); err != nil {
		return fmt.Errorf("write seed: %w", err)
	}
	ownerCredentialsPath := filepath.Join(*dataDir, "owner-credentials.txt")
	if err := writeSecretFile(ownerCredentialsPath, fmt.Sprintf(
		"NetP2P owner credentials\nEmail: %s\nPassword: %s\n", *ownerEmail, ownerPassword,
	)); err != nil {
		return fmt.Errorf("write owner credentials: %w", err)
	}
	if err := writeSecretFile(*setupKeyPath, token+"\n"); err != nil {
		return fmt.Errorf("write setup key: %w", err)
	}
	runtime := defaultRuntimeConfig()
	runtime.Role = "manager"
	runtime.DataDir = *dataDir
	runtime.NetworkID = *network
	runtime.ConfigPath = *seedPath
	runtime.DNSDomain = seed.Settings.DNSDomain
	if err := writeRuntimeConfig(*configPath, runtime); err != nil {
		return fmt.Errorf("write runtime config: %w", err)
	}
	bootstrap := bootstrapRecord{NetworkID: *network, Owner: owner, Group: group, Policy: policy, SetupKey: seed.SetupKeys[0]}
	bootstrapBody, err := json.MarshalIndent(bootstrap, "", "  ")
	if err != nil {
		return err
	}
	bootstrapPath := filepath.Join(*dataDir, "bootstrap.json")
	if err := os.WriteFile(bootstrapPath, bootstrapBody, 0o600); err != nil {
		return fmt.Errorf("write bootstrap record: %w", err)
	}

	fmt.Printf("Network %s initialized.\n", *network)
	fmt.Printf("Seed: %s\nRuntime config: %s\n", *seedPath, *configPath)
	fmt.Printf("Owner credentials: %s\nSetup key: %s\n", ownerCredentialsPath, *setupKeyPath)
	if *showSecrets {
		fmt.Printf("\nOwner password (shown once):\n  %s\nSetup key (shown once):\n  %s\n\n", ownerPassword, token)
	}
	managerAddr := seed.Managers[0].Address + "/p2p/" + seed.Managers[0].PeerID
	fmt.Println("Join commands:")
	fmt.Printf("  Linux/macOS: netp2p login --manager %s --setup-key-file %q\n", managerAddr, *setupKeyPath)
	fmt.Printf("  Windows:     netp2p.exe login --manager %s --setup-key-file %q\n", managerAddr, *setupKeyPath)
	return nil
}

func resolveOwnerPassword(path string, nonInteractive bool, reader *bufio.Reader) (string, error) {
	password := ""
	if path != "" {
		raw, err := os.ReadFile(path)
		if err != nil {
			return "", fmt.Errorf("read owner password file: %w", err)
		}
		password = strings.TrimSpace(string(raw))
	} else if !nonInteractive {
		fmt.Print("Owner password [generate]: ")
		value, _ := reader.ReadString('\n')
		password = strings.TrimSpace(value)
	}
	if password == "" {
		generated, err := randomToken("netp2p-owner-")
		if err != nil {
			return "", err
		}
		password = generated
	}
	if len(password) < 12 {
		return "", fmt.Errorf("owner password must contain at least 12 characters")
	}
	return password, nil
}

func writeSecretFile(path, value string) error {
	return os.WriteFile(path, []byte(value), 0o600)
}

func buildInitialSeed(network string) (config.Seed, string, error) {
	if strings.TrimSpace(network) == "" {
		return config.Seed{}, "", fmt.Errorf("network id is required")
	}
	managers := make([]model.CommitteeMember, 3)
	for index := range managers {
		keySeed, err := randomKeySeed()
		if err != nil {
			return config.Seed{}, "", err
		}
		managers[index] = model.CommitteeMember{
			ID:                fmt.Sprintf("manager-%d", index+1),
			Address:           fmt.Sprintf("/dns4/manager-%d/udp/4001/quic-v1", index+1),
			KeySeed:           keySeed,
			ListenAddr:        fmt.Sprintf("/ip4/0.0.0.0/udp/%d/webrtc-direct", 4101+index),
			ForwardingEnabled: true,
		}
	}
	token, err := randomToken("netp2p-setup-")
	if err != nil {
		return config.Seed{}, "", err
	}
	adminToken, err := randomToken("netp2p-admin-")
	if err != nil {
		return config.Seed{}, "", err
	}
	sessionSecret, err := randomToken("netp2p-session-")
	if err != nil {
		return config.Seed{}, "", err
	}
	return config.Seed{
		Development:     true,
		NetworkID:       network,
		OverlayCIDR:     "100.64.0.0/24",
		CommitteeParams: model.DefaultCommitteeParams(),
		AdminToken:      adminToken,
		SessionSecret:   sessionSecret,
		Managers:        managers,
		Settings: model.NetworkSettings{
			DNSDomain:           sanitizeDomain(network) + ".internal",
			LoginExpirationDays: 30,
			JWTGroupsEnabled:    true,
			JWTGroupsClaimName:  "groups",
			ExitNodeEnabled:     true,
		},
		NextIPOffset: 11,
	}, token, nil
}

func defaultDataDir() string {
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".netp2p")
}

func randomKeySeed() (int64, error) {
	var buffer [8]byte
	if _, err := rand.Read(buffer[:]); err != nil {
		return 0, err
	}
	value := binary.BigEndian.Uint64(buffer[:]) & uint64(^uint64(0)>>1)
	if value == 0 {
		value = 1
	}
	return int64(value), nil
}

func randomToken(prefix string) (string, error) {
	var buffer [24]byte
	if _, err := rand.Read(buffer[:]); err != nil {
		return "", err
	}
	return prefix + fmt.Sprintf("%x", buffer), nil
}

func sanitizeDomain(value string) string {
	lower := strings.ToLower(strings.TrimSpace(value))
	var builder strings.Builder
	for _, char := range lower {
		if (char >= 'a' && char <= 'z') || (char >= '0' && char <= '9') || char == '-' {
			builder.WriteRune(char)
		} else {
			builder.WriteRune('-')
		}
	}
	return strings.Trim(builder.String(), "-")
}
