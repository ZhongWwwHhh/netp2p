package main

import (
	"archive/zip"
	"os"
	"path/filepath"
	"testing"
)

func TestDebugBundleIncludesAndRestoresClientProfile(t *testing.T) {
	dataDir := t.TempDir()
	profileDir := filepath.Join(dataDir, "client")
	if err := os.MkdirAll(profileDir, 0o700); err != nil {
		t.Fatal(err)
	}
	files := map[string][]byte{
		"identity.key": []byte("test-private-identity"),
		"state.json":   []byte(`{"version":1,"localPeerId":"peer-1"}`),
		"paths.json":   []byte(`{"version":1,"destinations":{}}`),
	}
	for name, body := range files {
		if err := os.WriteFile(filepath.Join(profileDir, name), body, 0o600); err != nil {
			t.Fatal(err)
		}
	}

	cfg := defaultRuntimeConfig()
	cfg.DataDir = dataDir
	configPath := filepath.Join(t.TempDir(), "runtime.yaml")
	if err := writeRuntimeConfig(configPath, cfg); err != nil {
		t.Fatal(err)
	}
	bundlePath := filepath.Join(t.TempDir(), "debug.zip")
	if err := runDebugBundle([]string{
		"--config", configPath, "--output", bundlePath, "--include-profile",
	}); err != nil {
		t.Fatal(err)
	}
	archive, err := zip.OpenReader(bundlePath)
	if err != nil {
		t.Fatal(err)
	}
	defer archive.Close()
	entries := make(map[string]bool)
	for _, entry := range archive.File {
		entries[entry.Name] = true
	}
	for name := range files {
		if !entries["profile/"+name] {
			t.Fatalf("debug bundle missing profile/%s", name)
		}
	}
	if !entries["profile/manifest.json"] {
		t.Fatal("debug bundle missing profile manifest")
	}

	restoreDir := t.TempDir()
	if err := runDebugProfileRestore([]string{
		"--archive", bundlePath, "--data-dir", restoreDir,
	}); err != nil {
		t.Fatal(err)
	}
	for name, expected := range files {
		actual, err := os.ReadFile(filepath.Join(restoreDir, "client", name))
		if err != nil {
			t.Fatal(err)
		}
		if string(actual) != string(expected) {
			t.Fatalf("restored %s = %q, want %q", name, actual, expected)
		}
	}
	if err := runDebugProfileRestore([]string{
		"--archive", bundlePath, "--data-dir", restoreDir,
	}); err == nil {
		t.Fatal("profile restore replaced existing files without --overwrite")
	}
	if err := runDebugProfileRestore([]string{
		"--archive", bundlePath, "--data-dir", restoreDir, "--overwrite",
	}); err != nil {
		t.Fatal(err)
	}
}
