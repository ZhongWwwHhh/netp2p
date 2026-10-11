package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func FuzzRuntimeConfigFile(f *testing.F) {
	f.Add([]byte("version: 1\nrole: node\ndataDir: .netp2p\nnetwork: fuzz\nipc:\n  path: test.sock\n"))
	f.Add([]byte(`{"version":1,"role":"node","dataDir":".netp2p","network":"fuzz","ipc":{"path":"test.sock"}}`))
	f.Add([]byte("version: 1\nrole: ../escaped\ndataDir: ../../../etc\n"))
	f.Add([]byte("version: one\n"))
	f.Add([]byte("version: 1\n---\nversion: 1\n"))
	f.Add([]byte(strings.Repeat("dataDir: ../../../../tmp\n", 512)))

	path := filepath.Join(f.TempDir(), "runtime.yaml")
	f.Fuzz(func(t *testing.T, data []byte) {
		if err := os.WriteFile(path, data, 0o600); err != nil {
			t.Fatal(err)
		}
		cfg, err := parseRuntimeConfig(path)
		if err == nil {
			_ = validateRuntimeConfig(cfg)
		}
	})
}
