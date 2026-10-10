package main

import (
	"bytes"
	"fmt"
	"os"
	"runtime"
	"time"

	"gopkg.in/yaml.v3"
)

const runtimeConfigVersion = 1

// runtimeConfig is the typed, versioned schema for netp2pd runtime settings.
// Every supported file key is declared here; unknown keys are rejected instead
// of being silently mapped onto flags.
type runtimeConfig struct {
	Version int `yaml:"version" json:"version"`

	Role              string `yaml:"role" json:"role"`
	DataDir           string `yaml:"dataDir" json:"dataDir"`
	Listen            string `yaml:"listen" json:"listen"`
	WebListen         string `yaml:"webListen" json:"webListen"`
	ConfigPath        string `yaml:"config" json:"config"`
	ManifestPath      string `yaml:"manifest" json:"manifest"`
	ManagerBundlePath string `yaml:"managerBundle" json:"managerBundle"`
	SeedPath          string `yaml:"seed" json:"seed"`
	TrustPath         string `yaml:"trust" json:"trust"`
	Manager           string `yaml:"manager" json:"manager"`
	SetupKey          string `yaml:"setupKey" json:"setupKey"`
	SetupKeyFile      string `yaml:"setupKeyFile" json:"setupKeyFile"`
	PacketListen      string `yaml:"packetListen" json:"packetListen"`

	TunName string `yaml:"tun" json:"tun"`
	TunMTU  int    `yaml:"tunMtu" json:"tunMtu"`
	NoTun   bool   `yaml:"noTun" json:"noTun"`

	DNSListen           string `yaml:"dnsListen" json:"dnsListen"`
	DNSManageResolvConf bool   `yaml:"dnsManageResolvConf" json:"dnsManageResolvConf"`
	NoDNS               bool   `yaml:"noDns" json:"noDns"`
	DNSDomain           string `yaml:"dnsDomain" json:"dnsDomain"`

	NoForward          bool `yaml:"noForward" json:"noForward"`
	DKG                bool `yaml:"dkg" json:"dkg"`
	RotateCommitteeKey bool `yaml:"rotateCommitteeKeys" json:"rotateCommitteeKeys"`

	SSO         bool     `yaml:"sso" json:"sso"`
	SSOIssuer   string   `yaml:"ssoIssuer" json:"ssoIssuer"`
	SSOClientID string   `yaml:"ssoClientId" json:"ssoClientId"`
	StatusFile  string   `yaml:"statusFile" json:"statusFile"`
	Hostname    string   `yaml:"hostname" json:"hostname"`
	Posture     []string `yaml:"posture" json:"posture"`
	NetworkID   string   `yaml:"network" json:"network"`

	AdminToken  string `yaml:"adminToken" json:"adminToken"`
	AdminAction string `yaml:"action" json:"action"`
	AdminFile   string `yaml:"file" json:"file"`
	AdminTarget string `yaml:"target" json:"target"`

	MetricsListen string          `yaml:"metricsListen" json:"metricsListen"`
	Telemetry     telemetryConfig `yaml:"telemetry" json:"telemetry"`
	Alert         alertConfig     `yaml:"alert" json:"alert"`
	IPC           ipcConfig       `yaml:"ipc" json:"ipc"`
}

type telemetryConfig struct {
	OTLPEndpoint string `yaml:"endpoint" json:"endpoint"`
}

type alertConfig struct {
	Webhook              string        `yaml:"webhook" json:"webhook"`
	WebhookSecret        string        `yaml:"webhookSecret" json:"webhookSecret"`
	Interval             time.Duration `yaml:"interval" json:"interval"`
	DropCount            uint64        `yaml:"dropCount" json:"dropCount"`
	DropRatePercent      float64       `yaml:"dropRatePercent" json:"dropRatePercent"`
	AllowInsecureWebhook bool          `yaml:"allowInsecureWebhook" json:"allowInsecureWebhook"`
}

type ipcConfig struct {
	Path string `yaml:"path" json:"path"`
}

func defaultRuntimeConfig() runtimeConfig {
	return runtimeConfig{
		Version:             runtimeConfigVersion,
		Role:                "node",
		DataDir:             ".netp2p",
		Listen:              "/ip4/0.0.0.0/udp/0/quic-v1",
		WebListen:           "0.0.0.0:8080",
		PacketListen:        "127.0.0.1:51820",
		TunName:             "netp2p0",
		TunMTU:              1280,
		DNSListen:           "127.0.0.1:53",
		DNSManageResolvConf: true,
		NetworkID:           "netp2p-test",
		Alert: alertConfig{
			Interval:        15 * time.Second,
			DropCount:       100,
			DropRatePercent: 5,
		},
		IPC: ipcConfig{Path: defaultIPCPath()},
	}
}

func defaultIPCPath() string {
	if runtime.GOOS == "windows" {
		return `\\.\pipe\netp2pd`
	}
	return "/var/run/netp2p/netp2pd.sock"
}

// loadRuntimeConfig decodes strict YAML or JSON. JSON is a YAML subset, so the
// same decoder handles both formats.
func loadRuntimeConfig(path string) (runtimeConfig, error) {
	cfg := defaultRuntimeConfig()
	if path == "" {
		return cfg, nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return runtimeConfig{}, fmt.Errorf("read config file: %w", err)
	}
	cfg.Version = 0
	decoder := yaml.NewDecoder(bytes.NewReader(data))
	decoder.KnownFields(true)
	if err := decoder.Decode(&cfg); err != nil {
		return runtimeConfig{}, fmt.Errorf("decode config file: %w", err)
	}
	if cfg.Version != runtimeConfigVersion {
		return runtimeConfig{}, fmt.Errorf("unsupported runtime config version %d (want %d)", cfg.Version, runtimeConfigVersion)
	}
	if err := validateRuntimeConfig(cfg); err != nil {
		return runtimeConfig{}, err
	}
	return cfg, nil
}

func validateRuntimeConfig(cfg runtimeConfig) error {
	switch cfg.Role {
	case "node", "manager", "client", "admin", "doctor", "seedgen", "daemon":
	default:
		return fmt.Errorf("unknown role %q", cfg.Role)
	}
	if cfg.DataDir == "" {
		return fmt.Errorf("dataDir is required")
	}
	if cfg.NetworkID == "" {
		return fmt.Errorf("network is required")
	}
	if cfg.TunMTU <= 0 {
		return fmt.Errorf("tunMtu must be positive")
	}
	if cfg.IPC.Path == "" {
		return fmt.Errorf("ipc.path is required")
	}
	if cfg.Role == "manager" {
		production := cfg.ManifestPath != "" || cfg.ManagerBundlePath != ""
		if production {
			if cfg.ConfigPath != "" {
				return fmt.Errorf("config cannot be combined with manifest and managerBundle")
			}
			if cfg.ManifestPath == "" || cfg.ManagerBundlePath == "" {
				return fmt.Errorf("manifest and managerBundle are required together for manager role")
			}
			if !cfg.DKG {
				return fmt.Errorf("dkg is required for production manager configuration")
			}
			if cfg.RotateCommitteeKey {
				return fmt.Errorf("rotateCommitteeKeys must use DKG in production")
			}
		} else if cfg.ConfigPath == "" {
			return fmt.Errorf("config is required for manager role")
		}
	}
	if cfg.Role == "client" || cfg.Role == "daemon" {
		if cfg.Manager == "" && cfg.TrustPath == "" {
			return fmt.Errorf("manager or trust is required for %s role", cfg.Role)
		}
		if cfg.TrustPath != "" && cfg.SeedPath != "" {
			return fmt.Errorf("trust cannot be combined with seed for %s role", cfg.Role)
		}
	}
	if (cfg.Role == "client" || cfg.Role == "daemon") && cfg.SetupKey == "" && cfg.SetupKeyFile == "" && !cfg.SSO {
		return fmt.Errorf("setupKey, setupKeyFile or sso is required for %s role", cfg.Role)
	}
	if cfg.Role == "client" || cfg.Role == "daemon" {
		if _, err := clientMetricsListen(cfg.MetricsListen); err != nil {
			return err
		}
	}
	if cfg.SSO && (cfg.SSOIssuer == "" || cfg.SSOClientID == "") {
		return fmt.Errorf("ssoIssuer and ssoClientId are required with sso")
	}
	if cfg.Role == "admin" && (cfg.Manager == "" || cfg.AdminToken == "" || cfg.AdminAction == "") {
		return fmt.Errorf("manager, adminToken and action are required for admin role")
	}
	if cfg.Role == "seedgen" && cfg.ConfigPath == "" {
		return fmt.Errorf("config is required for seedgen role")
	}
	if cfg.Alert.Interval <= 0 {
		return fmt.Errorf("alert.interval must be positive")
	}
	return nil
}
