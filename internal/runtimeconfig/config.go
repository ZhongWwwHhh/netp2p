// Package runtimeconfig defines the shared, versioned runtime configuration
// consumed by both the long-running daemon and the user-facing CLI.
package runtimeconfig

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"runtime"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

const Version = 1

// maxConfigFileSize keeps a corrupt or oversized local file from becoming a
// whole-process allocation before YAML validation can run.
const maxConfigFileSize = 1 << 20

type Config struct {
	Version int `yaml:"version" json:"version"`

	Role              string   `yaml:"role" json:"role"`
	DataDir           string   `yaml:"dataDir" json:"dataDir"`
	Listen            string   `yaml:"listen" json:"listen"`
	WebListen         string   `yaml:"webListen" json:"webListen"`
	ConfigPath        string   `yaml:"config" json:"config"`
	ManifestPath      string   `yaml:"manifest" json:"manifest"`
	ManagerBundlePath string   `yaml:"managerBundle" json:"managerBundle"`
	SeedPath          string   `yaml:"seed" json:"seed"`
	TrustPath         string   `yaml:"trust" json:"trust"`
	Manager           string   `yaml:"manager" json:"manager"`
	ManagerEndpoints  []string `yaml:"managerEndpoints" json:"managerEndpoints"`
	SetupKey          string   `yaml:"setupKey" json:"setupKey"`
	SetupKeyFile      string   `yaml:"setupKeyFile" json:"setupKeyFile"`
	PacketListen      string   `yaml:"packetListen" json:"packetListen"`

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

	SSO         bool   `yaml:"sso" json:"sso"`
	SSOIssuer   string `yaml:"ssoIssuer" json:"ssoIssuer"`
	SSOClientID string `yaml:"ssoClientId" json:"ssoClientId"`
	// ResumeFromState is set after daemon startup validates state.json. A
	// resumable peer does not need a setup key; registration already happened.
	ResumeFromState bool     `yaml:"-" json:"-"`
	StatusFile      string   `yaml:"statusFile" json:"statusFile"`
	Hostname        string   `yaml:"hostname" json:"hostname"`
	Posture         []string `yaml:"posture" json:"posture"`
	NetworkID       string   `yaml:"network" json:"network"`

	AdminToken  string `yaml:"adminToken" json:"adminToken"`
	AdminAction string `yaml:"action" json:"action"`
	AdminFile   string `yaml:"file" json:"file"`
	AdminTarget string `yaml:"target" json:"target"`

	MetricsListen string          `yaml:"metricsListen" json:"metricsListen"`
	Telemetry     TelemetryConfig `yaml:"telemetry" json:"telemetry"`
	Alert         AlertConfig     `yaml:"alert" json:"alert"`
	IPC           IPCConfig       `yaml:"ipc" json:"ipc"`
}

type TelemetryConfig struct {
	OTLPEndpoint string `yaml:"endpoint" json:"endpoint"`
}

type AlertConfig struct {
	Webhook              string        `yaml:"webhook" json:"webhook"`
	WebhookSecret        string        `yaml:"webhookSecret" json:"webhookSecret"`
	Interval             time.Duration `yaml:"interval" json:"interval"`
	DropCount            uint64        `yaml:"dropCount" json:"dropCount"`
	DropRatePercent      float64       `yaml:"dropRatePercent" json:"dropRatePercent"`
	AllowInsecureWebhook bool          `yaml:"allowInsecureWebhook" json:"allowInsecureWebhook"`
}

type IPCConfig struct {
	Path string `yaml:"path" json:"path"`
}

func Default() Config {
	return Config{
		Version:             Version,
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
		Alert: AlertConfig{
			Interval:        15 * time.Second,
			DropCount:       100,
			DropRatePercent: 5,
		},
		IPC: IPCConfig{Path: DefaultIPCPath()},
	}
}

func DefaultIPCPath() string {
	if runtime.GOOS == "windows" {
		return `\\.\pipe\netp2pd`
	}
	return "/var/run/netp2p/netp2pd.sock"
}

// Parse decodes strict YAML or JSON without semantic validation. The CLI uses
// this before mutating an intentionally incomplete first-run client profile.
func Parse(path string) (Config, error) {
	cfg := Default()
	if path == "" {
		return cfg, nil
	}
	file, err := os.Open(path)
	if err != nil {
		return Config{}, fmt.Errorf("read config file: %w", err)
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, maxConfigFileSize+1))
	if err != nil {
		return Config{}, fmt.Errorf("read config file: %w", err)
	}
	if len(data) > maxConfigFileSize {
		return Config{}, fmt.Errorf("config file exceeds %d bytes", maxConfigFileSize)
	}
	return parse(data)
}

func parse(data []byte) (Config, error) {
	cfg := Default()
	cfg.Version = 0
	decoder := yaml.NewDecoder(bytes.NewReader(data))
	decoder.KnownFields(true)
	if err := decoder.Decode(&cfg); err != nil {
		return Config{}, fmt.Errorf("decode config file: %w", err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return Config{}, fmt.Errorf("config file must contain exactly one document")
	}
	if cfg.Version != Version {
		return Config{}, fmt.Errorf("unsupported runtime config version %d (want %d)", cfg.Version, Version)
	}
	return cfg, nil
}

// Load decodes and applies the daemon's semantic validation rules.
func Load(path string) (Config, error) {
	cfg, err := Parse(path)
	if err != nil {
		return Config{}, err
	}
	if err := Validate(cfg); err != nil {
		return Config{}, err
	}
	return cfg, nil
}

func Validate(cfg Config) error {
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
		if cfg.Manager == "" && cfg.TrustPath == "" && len(cfg.ManagerEndpoints) == 0 {
			return fmt.Errorf("manager, trust or managerEndpoints is required for %s role", cfg.Role)
		}
		if cfg.TrustPath != "" && cfg.SeedPath != "" {
			return fmt.Errorf("trust cannot be combined with seed for %s role", cfg.Role)
		}
	}
	if (cfg.Role == "client" || cfg.Role == "daemon") && !cfg.ResumeFromState && cfg.SetupKey == "" && cfg.SetupKeyFile == "" && !cfg.SSO {
		return fmt.Errorf("setupKey, setupKeyFile or sso is required for %s role", cfg.Role)
	}
	if cfg.Role == "client" || cfg.Role == "daemon" {
		if _, err := ClientMetricsListen(cfg.MetricsListen); err != nil {
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

// IsUnprovisionedClientError reports whether the only validation failure is
// missing credentials. An idle first-run client may start before login, but it
// cannot connect until those fields are supplied and fully validated.
func IsUnprovisionedClientError(err error) bool {
	if err == nil {
		return false
	}
	message := err.Error()
	return strings.Contains(message, "manager, trust or managerEndpoints is required for client role") ||
		strings.Contains(message, "setupKey, setupKeyFile or sso is required for client role")
}

// ClientMetricsListen constrains the client metrics endpoint to IPv4 loopback.
func ClientMetricsListen(address string) (string, error) {
	if address == "" {
		return "127.0.0.1:9102", nil
	}
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return "", fmt.Errorf("invalid client metrics listen address %q", address)
	}
	// Preserve the daemon's original rule: only a literal dotted IPv4 address
	// is accepted. IPv4-mapped IPv6 spellings do not silently widen it.
	ip := net.ParseIP(host)
	if ip == nil || strings.Contains(host, ":") || ip.To4() == nil || !ip.Equal(net.IPv4(127, 0, 0, 1)) || port == "" {
		return "", fmt.Errorf("client metrics listen address must be an IPv4 loopback host and port")
	}
	return address, nil
}
