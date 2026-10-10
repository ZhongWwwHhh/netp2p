package main

import (
	"path/filepath"
	"testing"

	"github.com/netp2p/netp2p/internal/runtimeconfig"
)

func TestCLIParsesAnsibleRenderedClientRuntime(t *testing.T) {
	path := filepath.Join("..", "..", "internal", "runtimeconfig", "testdata", "client-runtime.yaml")
	cfg, err := parseRuntimeConfig(path)
	if err != nil {
		t.Fatalf("CLI could not parse Ansible-rendered client runtime: %v", err)
	}
	if err := validateRuntimeConfig(cfg); err != nil {
		t.Fatalf("CLI rejected Ansible-rendered client runtime: %v", err)
	}
	if cfg.TrustPath == "" || cfg.SetupKeyFile == "" {
		t.Fatalf("production client fields missing: %+v", cfg)
	}
	if cfg.Manager != "" {
		t.Fatalf("production trust profile unexpectedly has manager = %q", cfg.Manager)
	}
}

func TestCLILoadsIPCConfigFromUnprovisionedClientRuntime(t *testing.T) {
	path := filepath.Join("..", "..", "packaging", "runtime.example.yaml")
	cfg, err := loadRuntimeConfigForIPC(path)
	if err != nil {
		t.Fatalf("IPC loader rejected first-run client profile: %v", err)
	}
	if cfg.IPC.Path == "" {
		t.Fatalf("IPC path missing from first-run profile: %+v", cfg)
	}
	if err := validateRuntimeConfig(cfg); err == nil || !runtimeconfig.IsUnprovisionedClientError(err) {
		t.Fatalf("profile should remain unprovisioned: %v", err)
	}
}
