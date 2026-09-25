package main

import (
	"flag"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// TestApplyConfigToFlags checks that YAML and JSON configs map onto flags, that
// explicit flags win, and that unknown keys are rejected rather than ignored.
func TestApplyConfigToFlags(t *testing.T) {
	directory := t.TempDir()
	yamlPath := filepath.Join(directory, "config.yaml")
	if err := os.WriteFile(yamlPath, []byte("listen: \"/ip4/0.0.0.0/udp/4001/quic-v1\"\nwebListen: 0.0.0.0:9000\nnoTun: true\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	jsonPath := filepath.Join(directory, "config.json")
	if err := os.WriteFile(jsonPath, []byte(`{"listen":"/ip4/127.0.0.1/udp/0/quic-v1","noTun":false}`), 0o644); err != nil {
		t.Fatal(err)
	}

	flags := flag.NewFlagSet("test", flag.ContinueOnError)
	listen := flags.String("listen", "default", "")
	webListen := flags.String("webListen", "default", "")
	noTun := flags.Bool("noTun", false, "")

	if err := applyConfigToFlags(flags, yamlPath, map[string]bool{}); err != nil {
		t.Fatal(err)
	}
	if *listen != "/ip4/0.0.0.0/udp/4001/quic-v1" || *webListen != "0.0.0.0:9000" || !*noTun {
		t.Fatalf("yaml config not applied: listen=%q web=%q noTun=%v", *listen, *webListen, *noTun)
	}

	if err := applyConfigToFlags(flags, jsonPath, map[string]bool{"listen": true}); err != nil {
		t.Fatal(err)
	}
	if *listen != "/ip4/0.0.0.0/udp/4001/quic-v1" {
		t.Fatalf("explicit flag was overridden by json: %q", *listen)
	}
	if *noTun {
		t.Fatal("json config should have cleared noTun")
	}

	unknownPath := filepath.Join(directory, "unknown.yaml")
	if err := os.WriteFile(unknownPath, []byte("nonexistentKey: 1\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := applyConfigToFlags(flags, unknownPath, map[string]bool{}); err == nil {
		t.Fatal("unknown config key should be rejected")
	}
}

// TestApplyAlertConfigBlock checks the nested alert block flattens onto its
// flags, that explicit flags still win, and that unknown alert keys are
// rejected instead of silently ignored.
func TestApplyAlertConfigBlock(t *testing.T) {
	directory := t.TempDir()
	path := filepath.Join(directory, "config.yaml")
	body := "alert:\n  webhook: https://hooks.example/netp2p\n  interval: 30s\n  dropCount: 250\n  dropRatePercent: 7.5\n"
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}

	flags := flag.NewFlagSet("test", flag.ContinueOnError)
	webhook := flags.String("alert-webhook", "", "")
	secret := flags.String("alert-webhook-secret", "", "")
	interval := flags.Duration("alert-interval", 15*time.Second, "")
	dropCount := flags.Uint64("alert-drop-count", 100, "")
	dropRate := flags.Float64("alert-drop-rate-percent", 5, "")

	if err := applyConfigToFlags(flags, path, map[string]bool{"alert-webhook": true}); err != nil {
		t.Fatal(err)
	}
	if *webhook != "" {
		t.Fatalf("explicit alert-webhook overridden: %q", *webhook)
	}
	if *secret != "" {
		t.Fatalf("unset secret changed: %q", *secret)
	}
	if *interval != 30*time.Second || *dropCount != 250 || *dropRate != 7.5 {
		t.Fatalf("alert block not applied: interval=%s dropCount=%d dropRate=%v", *interval, *dropCount, *dropRate)
	}

	if err := applyConfigToFlags(flags, path, map[string]bool{}); err != nil {
		t.Fatal(err)
	}
	if *webhook != "https://hooks.example/netp2p" {
		t.Fatalf("alert webhook not applied: %q", *webhook)
	}

	unknown := filepath.Join(directory, "unknown.yaml")
	if err := os.WriteFile(unknown, []byte("alert:\n  bogus: 1\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := applyConfigToFlags(flags, unknown, map[string]bool{}); err == nil {
		t.Fatal("unknown alert key should be rejected")
	}
}
