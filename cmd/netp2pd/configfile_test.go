package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/netp2p/netp2p/internal/config"
)

func TestLoadRuntimeConfigStrictYAML(t *testing.T) {
	directory := t.TempDir()
	path := filepath.Join(directory, "runtime.yaml")
	body := `version: 1
role: manager
dataDir: /var/lib/netp2p
listen: /ip4/0.0.0.0/udp/4001/quic-v1
webListen: 0.0.0.0:9000
config: /etc/netp2p/seed.json
metricsListen: 127.0.0.1:9100
alert:
  webhook: https://hooks.example/netp2p
  interval: 30s
  dropCount: 250
  dropRatePercent: 7.5
`
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := loadRuntimeConfig(path)
	if err != nil {
		t.Fatalf("loadRuntimeConfig: %v", err)
	}
	if cfg.Version != 1 || cfg.Role != "manager" || cfg.DataDir != "/var/lib/netp2p" {
		t.Fatalf("config = %+v", cfg)
	}
	if cfg.Listen != "/ip4/0.0.0.0/udp/4001/quic-v1" || cfg.WebListen != "0.0.0.0:9000" {
		t.Fatalf("addresses not loaded: %+v", cfg)
	}
	if cfg.Alert.Webhook != "https://hooks.example/netp2p" || cfg.Alert.Interval != 30*time.Second {
		t.Fatalf("alert config not loaded: %+v", cfg.Alert)
	}
	if cfg.Alert.DropCount != 250 || cfg.Alert.DropRatePercent != 7.5 {
		t.Fatalf("alert thresholds not loaded: %+v", cfg.Alert)
	}
}

func TestRuntimeConfigMetricsListenReachesClientOptions(t *testing.T) {
	directory := t.TempDir()
	path := filepath.Join(directory, "runtime.yaml")
	body := `version: 1
role: client
dataDir: /var/lib/netp2p
manager: /ip4/127.0.0.1/udp/4001/quic-v1
setupKey: test-setup-key
metricsListen: 127.0.0.1:9100
`
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := loadRuntimeConfig(path)
	if err != nil {
		t.Fatalf("loadRuntimeConfig: %v", err)
	}
	options, err := clientOptionsFromRuntimeConfig(cfg)
	if err != nil {
		t.Fatalf("clientOptionsFromRuntimeConfig: %v", err)
	}
	if options.metricsListen != "127.0.0.1:9100" {
		t.Fatalf("client metrics listen = %q, want 127.0.0.1:9100", options.metricsListen)
	}
}

func TestClientOptionsFromRuntimeConfigDefaultsMetricsListen(t *testing.T) {
	cfg, err := loadRuntimeConfig("")
	if err != nil {
		t.Fatalf("load default runtime config: %v", err)
	}
	options, err := clientOptionsFromRuntimeConfig(cfg)
	if err != nil {
		t.Fatalf("clientOptionsFromRuntimeConfig: %v", err)
	}
	if options.metricsListen != "127.0.0.1:0" {
		t.Fatalf("default client metrics listen = %q, want 127.0.0.1:0", options.metricsListen)
	}
}

func TestClientOptionsFromRuntimeConfigUsesClientTrustManagers(t *testing.T) {
	material, err := config.GenerateProductionMaterial("netp2p-production", "100.64.0.0/24", []config.ProductionManagerSpec{
		{ID: "fr", DNSName: "fr.netp2p.zhongwwhhhh.cc", PublicIPv4: "193.42.62.111", Port: 4001, WebRTCPort: 4101},
		{ID: "sg", DNSName: "sg.netp2p.zhongwwhhhh.cc", PublicIPv4: "45.127.32.84", Port: 4001, WebRTCPort: 4101},
		{ID: "us-phx", DNSName: "us-phx.netp2p.zhongwwhhhh.cc", PublicIPv4: "129.146.72.228", Port: 4001, WebRTCPort: 4101},
	})
	if err != nil {
		t.Fatal(err)
	}
	trustJSON, err := json.Marshal(material.ClientTrust)
	if err != nil {
		t.Fatal(err)
	}
	directory := t.TempDir()
	trustPath := filepath.Join(directory, "trust.json")
	if err := os.WriteFile(trustPath, trustJSON, 0o600); err != nil {
		t.Fatal(err)
	}

	cfg := defaultRuntimeConfig()
	cfg.Role = "client"
	cfg.NetworkID = material.ClientTrust.NetworkID
	cfg.TrustPath = trustPath
	cfg.SetupKey = "test-setup-key"
	options, err := clientOptionsFromRuntimeConfig(cfg)
	if err != nil {
		t.Fatalf("clientOptionsFromRuntimeConfig: %v", err)
	}
	if len(options.managerEndpoints) != 3 || options.managerAddr != options.managerEndpoints[0] {
		t.Fatalf("manager failover was not loaded from trust: %+v", options)
	}
	if options.trustPath != trustPath {
		t.Fatalf("trust path = %q, want %q", options.trustPath, trustPath)
	}

	cfg.Manager = "/ip4/127.0.0.1/udp/4001/quic-v1/p2p/12D3KooWInvalid"
	if _, err := clientOptionsFromRuntimeConfig(cfg); err == nil {
		t.Fatal("a manager outside the client trust bundle was accepted")
	}

	cfg.Manager = ""
	cfg.NetworkID = "other-network"
	if _, err := clientOptionsFromRuntimeConfig(cfg); err == nil {
		t.Fatal("a runtime network mismatch was accepted")
	}
}

func TestValidateRuntimeConfigClientTrust(t *testing.T) {
	cfg := defaultRuntimeConfig()
	cfg.Role = "client"
	cfg.TrustPath = "/etc/netp2p/trust.json"
	cfg.SetupKey = "test-setup-key"
	if err := validateRuntimeConfig(cfg); err != nil {
		t.Fatalf("client trust without an explicit manager: %v", err)
	}

	cfg.SeedPath = "/etc/netp2p/seed.json"
	if err := validateRuntimeConfig(cfg); err == nil {
		t.Fatal("client trust combined with a legacy seed was accepted")
	}
}

func TestValidateRuntimeConfigClientMetricsListen(t *testing.T) {
	cfg := defaultRuntimeConfig()
	cfg.Role = "client"
	cfg.Manager = "/ip4/127.0.0.1/udp/4001/quic-v1"
	cfg.SetupKey = "test-setup-key"

	for _, address := range []string{"", "127.0.0.1:9100"} {
		cfg.MetricsListen = address
		if err := validateRuntimeConfig(cfg); err != nil {
			t.Fatalf("validate client metrics address %q: %v", address, err)
		}
	}
	for _, address := range []string{"0.0.0.0:9100", "192.0.2.1:9100", "[::1]:9100", "localhost:9100", "127.0.0.1"} {
		cfg.MetricsListen = address
		if err := validateRuntimeConfig(cfg); err == nil {
			t.Fatalf("client metrics address %q was accepted", address)
		}
	}

	cfg.Role = "manager"
	cfg.ConfigPath = "/etc/netp2p/seed.json"
	cfg.SetupKey = ""
	cfg.MetricsListen = "0.0.0.0:9101"
	if err := validateRuntimeConfig(cfg); err != nil {
		t.Fatalf("manager metrics address should not use the client loopback restriction: %v", err)
	}
}

func TestLoadRuntimeConfigRejectsUnknownKey(t *testing.T) {
	directory := t.TempDir()
	path := filepath.Join(directory, "runtime.yaml")
	if err := os.WriteFile(path, []byte("version: 1\nunknownKey: 1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadRuntimeConfig(path); err == nil {
		t.Fatal("unknown config key should be rejected")
	}
}

func TestLoadRuntimeConfigRejectsWrongVersion(t *testing.T) {
	directory := t.TempDir()
	path := filepath.Join(directory, "runtime.yaml")
	if err := os.WriteFile(path, []byte("version: 2\nrole: node\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadRuntimeConfig(path); err == nil {
		t.Fatal("unsupported config version should be rejected")
	}
}

func TestValidateRuntimeConfigProductionManager(t *testing.T) {
	cfg := defaultRuntimeConfig()
	cfg.Role = "manager"
	cfg.ManifestPath = "/etc/netp2p/network.json"
	cfg.ManagerBundlePath = "/etc/netp2p/manager.json"
	cfg.DKG = true
	if err := validateRuntimeConfig(cfg); err != nil {
		t.Fatalf("validate production manager: %v", err)
	}

	cfg.DKG = false
	if err := validateRuntimeConfig(cfg); err == nil {
		t.Fatal("production manager without DKG was accepted")
	}

	cfg.DKG = true
	cfg.ConfigPath = "/etc/netp2p/dev-seed.json"
	if err := validateRuntimeConfig(cfg); err == nil {
		t.Fatal("legacy config combined with production trust files was accepted")
	}
}
