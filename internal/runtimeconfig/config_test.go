package runtimeconfig

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestParseProductionClientRuntime(t *testing.T) {
	path := filepath.Join("testdata", "client-runtime.yaml")
	cfg, err := Parse(path)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if err := Validate(cfg); err != nil {
		t.Fatalf("Validate production client runtime: %v", err)
	}
	if cfg.Role != "client" || cfg.TrustPath != "/etc/netp2p/trust.json" {
		t.Fatalf("unexpected client runtime: %+v", cfg)
	}
}

func TestParseFullSharedSchema(t *testing.T) {
	body := `version: 1
role: manager
dataDir: /var/lib/netp2p
listen: /ip4/0.0.0.0/udp/4001/quic-v1
webListen: 127.0.0.1:18080
config: /etc/netp2p/seed.json
manifest: /etc/netp2p/network.json
managerBundle: /etc/netp2p/manager.json
seed: /etc/netp2p/seed.json
trust: /etc/netp2p/trust.json
manager: /ip4/192.0.2.1/udp/4001/quic-v1
setupKey: unused
setupKeyFile: /etc/netp2p/setup-key
packetListen: 127.0.0.1:51820
tun: netp2p0
tunMtu: 1420
noTun: false
dnsListen: 127.0.0.1:5353
dnsManageResolvConf: false
noDns: false
dnsDomain: overlay.invalid
noForward: false
dkg: true
rotateCommitteeKeys: false
sso: false
ssoIssuer: https://sso.invalid
ssoClientId: netp2p
statusFile: /var/lib/netp2p/status
hostname: client-a
posture: [os=linux]
network: netp2p-production
adminToken: redacted
action: upsert-setup-key
file: /tmp/input
target: key-a
metricsListen: 127.0.0.1:9100
telemetry:
  endpoint: localhost:4317
alert:
  webhook: https://hooks.invalid
  webhookSecret: redacted
  interval: 15s
  dropCount: 20
  dropRatePercent: 2.5
  allowInsecureWebhook: false
ipc:
  path: /var/run/netp2p/netp2pd.sock
`
	path := filepath.Join(t.TempDir(), "runtime.yaml")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := Parse(path)
	if err != nil {
		t.Fatalf("Parse full schema: %v", err)
	}
	if cfg.ManagerBundlePath == "" || cfg.Alert.Interval != 15*time.Second || cfg.IPC.Path == "" {
		t.Fatalf("shared fields were not decoded: %+v", cfg)
	}
}

func TestPackagedRuntimeIsUnprovisionedClientProfile(t *testing.T) {
	cfg, err := Parse("../../packaging/runtime.example.yaml")
	if err != nil {
		t.Fatalf("parse packaged runtime: %v", err)
	}
	if cfg.Role != "client" {
		t.Fatalf("packaged role = %q, want client", cfg.Role)
	}
	if err := Validate(cfg); err == nil || !strings.Contains(err.Error(), "manager, trust or managerEndpoints") {
		t.Fatalf("unprovisioned client profile validation = %v, want missing manager/trust", err)
	}

	cfg.Manager = "/ip4/192.0.2.1/udp/4001/quic-v1/p2p/12D3KooWExample"
	cfg.NetworkID = "netp2p-production"
	cfg.SetupKeyFile = "/etc/netp2p/setup-key"
	if err := Validate(cfg); err != nil {
		t.Fatalf("provisioned packaged profile should validate: %v", err)
	}
}

func TestManagerEndpointFailoverProfileValidates(t *testing.T) {
	cfg := Default()
	cfg.Role = "client"
	cfg.NetworkID = "netp2p-production"
	cfg.ManagerEndpoints = []string{
		"/ip4/192.0.2.1/udp/4001/quic-v1/p2p/12D3KooWExample1",
		"/ip4/192.0.2.2/udp/4001/quic-v1/p2p/12D3KooWExample2",
	}
	cfg.SetupKeyFile = "/etc/netp2p/setup-key"
	if err := Validate(cfg); err != nil {
		t.Fatalf("Validate manager-endpoint profile: %v", err)
	}
}

func TestRecoveredClientProfileDoesNotNeedSetupKey(t *testing.T) {
	cfg := Default()
	cfg.Role = "client"
	cfg.NetworkID = "netp2p-production"
	cfg.ManagerEndpoints = []string{"/ip4/192.0.2.1/udp/4001/quic-v1/p2p/12D3KooWExample"}
	cfg.ResumeFromState = true
	if err := Validate(cfg); err != nil {
		t.Fatalf("Validate recovered profile: %v", err)
	}
	cfg.ResumeFromState = false
	err := Validate(cfg)
	if err == nil || !IsUnprovisionedClientError(err) {
		t.Fatalf("Validate non-recovered profile = %v, want unprovisioned error", err)
	}
}

func TestClientMetricsListenOnlyAllowsIPv4Loopback(t *testing.T) {
	if address, err := ClientMetricsListen(""); err != nil || address != "127.0.0.1:9102" {
		t.Fatalf("default = %q, %v", address, err)
	}
	for _, address := range []string{"127.0.0.1:9100", "127.0.0.1:0"} {
		if _, err := ClientMetricsListen(address); err != nil {
			t.Fatalf("validate %q: %v", address, err)
		}
	}
	for _, address := range []string{"0.0.0.0:9100", "localhost:9100", "[::1]:9100", "127.0.0.1"} {
		if _, err := ClientMetricsListen(address); err == nil {
			t.Fatalf("accepted invalid client metrics address %q", address)
		}
	}
}

func TestUnprovisionedClientErrorsAllowIdleStartup(t *testing.T) {
	cfg := Default()
	cfg.Role = "client"
	err := Validate(cfg)
	if err == nil || !IsUnprovisionedClientError(err) {
		t.Fatalf("Validate() = %v, want unprovisioned client error", err)
	}

	cfg.Role = "invalid-role"
	err = Validate(cfg)
	if err == nil || IsUnprovisionedClientError(err) {
		t.Fatalf("Validate() = %v, want a different client validation failure", err)
	}
}
