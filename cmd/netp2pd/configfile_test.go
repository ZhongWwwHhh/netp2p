package main

import (
	"flag"
	"os"
	"path/filepath"
	"testing"
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
