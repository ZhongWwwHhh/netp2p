package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"time"

	"github.com/netp2p/netp2p/internal/version"
	"gopkg.in/yaml.v3"
)

func runVersion() error {
	fmt.Printf("netp2p %s (protocol %s, %s/%s)\n", version.Version, version.ProtocolVersion, runtime.GOOS, runtime.GOARCH)
	return nil
}

func defaultConfigPath() string {
	if value := os.Getenv("NETP2P_CONFIG"); value != "" {
		return value
	}
	if runtime.GOOS == "windows" {
		if programData := os.Getenv("ProgramData"); programData != "" {
			candidate := filepath.Join(programData, "netp2p", "runtime.yaml")
			if _, err := os.Stat(candidate); err == nil {
				return candidate
			}
		}
		home, _ := os.UserHomeDir()
		return filepath.Join(home, ".netp2p", "runtime.yaml")
	}
	if _, err := os.Stat("/etc/netp2p/runtime.yaml"); err == nil {
		return "/etc/netp2p/runtime.yaml"
	}
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".netp2p", "runtime.yaml")
}

func configFlag(name string) string {
	value := flag.String("config", defaultConfigPath(), "runtime config path")
	flag.Parse()
	return *value
}

func runUp(args []string) error {
	flags := flag.NewFlagSet("up", flag.ContinueOnError)
	configPath := flags.String("config", defaultConfigPath(), "runtime config path")
	if err := flags.Parse(args); err != nil {
		return err
	}
	cfg, err := loadRuntimeConfig(*configPath)
	if err != nil {
		return err
	}
	client := newIPCClient(cfg.IPC.Path)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if err := client.call(ctx, "GET", "/v1/ping", nil, nil); err != nil {
		if _, err := startDaemon(*configPath); err != nil {
			return err
		}
		if err := waitForDaemon(ctx, client); err != nil {
			return err
		}
	}
	if err := client.call(ctx, "POST", "/v1/up", map[string]any{}, nil); err != nil {
		return err
	}
	fmt.Println("NetP2P is up")
	return nil
}

func runDown(args []string) error {
	flags := flag.NewFlagSet("down", flag.ContinueOnError)
	configPath := flags.String("config", defaultConfigPath(), "runtime config path")
	if err := flags.Parse(args); err != nil {
		return err
	}
	cfg, err := loadRuntimeConfig(*configPath)
	if err != nil {
		return err
	}
	client := newIPCClient(cfg.IPC.Path)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := client.call(ctx, "POST", "/v1/down", map[string]any{}, nil); err != nil {
		fmt.Println("NetP2P daemon is not running")
		return nil
	}
	fmt.Println("NetP2P is down")
	return nil
}

func runStatus(args []string) error {
	flags := flag.NewFlagSet("status", flag.ContinueOnError)
	configPath := flags.String("config", defaultConfigPath(), "runtime config path")
	asJSON := flags.Bool("json", false, "emit raw JSON")
	if err := flags.Parse(args); err != nil {
		return err
	}
	cfg, err := loadRuntimeConfig(*configPath)
	if err != nil {
		return err
	}
	client := newIPCClient(cfg.IPC.Path)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	var payload map[string]any
	if err := client.call(ctx, "GET", "/v1/status", nil, &payload); err != nil {
		return err
	}
	if *asJSON {
		encoded, err := json.MarshalIndent(payload, "", "  ")
		if err != nil {
			return err
		}
		fmt.Println(string(encoded))
		return nil
	}
	fmt.Printf("NetP2P %s\n", fmt.Sprint(payload["version"]))
	fmt.Printf("State: %s\n", fmt.Sprint(payload["state"]))
	if clientStatus, ok := payload["client"].(map[string]any); ok {
		fmt.Printf("Overlay IP: %s\n", fmt.Sprint(clientStatus["overlayIP"]))
		fmt.Printf("Mode: %s\n", fmt.Sprint(clientStatus["mode"]))
		fmt.Printf("Height: %v\n", clientStatus["height"])
	}
	return nil
}

func runIP(args []string) error {
	flags := flag.NewFlagSet("ip", flag.ContinueOnError)
	configPath := flags.String("config", defaultConfigPath(), "runtime config path")
	if err := flags.Parse(args); err != nil {
		return err
	}
	cfg, err := loadRuntimeConfig(*configPath)
	if err != nil {
		return err
	}
	client := newIPCClient(cfg.IPC.Path)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	var payload map[string]any
	if err := client.call(ctx, "GET", "/v1/status", nil, &payload); err != nil {
		return err
	}
	clientStatus, _ := payload["client"].(map[string]any)
	if clientStatus == nil || clientStatus["overlayIP"] == nil {
		return fmt.Errorf("overlay IP is not assigned yet")
	}
	fmt.Println(clientStatus["overlayIP"])
	return nil
}

func runLogin(args []string) error {
	flags := flag.NewFlagSet("login", flag.ContinueOnError)
	configPath := flags.String("config", defaultConfigPath(), "runtime config path")
	manager := flags.String("manager", "", "manager libp2p multiaddr")
	setupKey := flags.String("setup-key", "", "setup key")
	setupKeyFile := flags.String("setup-key-file", "", "file containing the setup key")
	sso := flags.Bool("sso", false, "use OIDC device flow")
	issuer := flags.String("sso-issuer", "", "OIDC issuer")
	clientID := flags.String("sso-client-id", "", "OIDC client id")
	if err := flags.Parse(args); err != nil {
		return err
	}
	cfg, err := loadRuntimeConfig(*configPath)
	if err != nil {
		return err
	}
	cfg.Role = "client"
	if *manager != "" {
		cfg.Manager = *manager
	}
	if *setupKey != "" {
		cfg.SetupKey = *setupKey
		cfg.SetupKeyFile = ""
	}
	if *setupKeyFile != "" {
		cfg.SetupKeyFile = *setupKeyFile
		cfg.SetupKey = ""
	}
	if *sso {
		cfg.SSO = true
	}
	if *issuer != "" {
		cfg.SSOIssuer = *issuer
	}
	if *clientID != "" {
		cfg.SSOClientID = *clientID
	}
	if cfg.Manager == "" {
		return fmt.Errorf("--manager is required")
	}
	if cfg.SetupKey == "" && cfg.SetupKeyFile == "" && !cfg.SSO {
		return fmt.Errorf("--setup-key, --setup-key-file or --sso is required")
	}
	if cfg.SSO && (cfg.SSOIssuer == "" || cfg.SSOClientID == "") {
		return fmt.Errorf("--sso-issuer and --sso-client-id are required with --sso")
	}
	if err := writeRuntimeConfig(*configPath, cfg); err != nil {
		return err
	}
	// Restart so a daemon that is already running picks up the new credentials.
	if err := runDown([]string{"--config", *configPath}); err != nil {
		return err
	}
	return runUp([]string{"--config", *configPath})
}

func runLogout(args []string) error {
	flags := flag.NewFlagSet("logout", flag.ContinueOnError)
	configPath := flags.String("config", defaultConfigPath(), "runtime config path")
	if err := flags.Parse(args); err != nil {
		return err
	}
	cfg, err := loadRuntimeConfig(*configPath)
	if err != nil {
		return err
	}
	cfg.SetupKey = ""
	cfg.SetupKeyFile = ""
	cfg.SSO = false
	cfg.SSOIssuer = ""
	cfg.SSOClientID = ""
	if err := writeRuntimeConfig(*configPath, cfg); err != nil {
		return err
	}
	return runDown([]string{"--config", *configPath})
}

func writeRuntimeConfig(path string, cfg runtimeConfig) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	encoded, err := yaml.Marshal(cfg)
	if err != nil {
		return err
	}
	return os.WriteFile(path, encoded, 0o600)
}
