package runtimeconfig

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func FuzzParse(f *testing.F) {
	f.Add([]byte("version: 1\nrole: node\ndataDir: .netp2p\n"))
	f.Add([]byte(`{"version":1,"role":"node","dataDir":".netp2p"}`))
	f.Add([]byte("version: 1\nrole: node\nunknown: value\n"))
	f.Add([]byte("version: 1\n---\nversion: 1\n"))
	f.Add([]byte("\xff\xfe\x00"))
	f.Add([]byte(strings.Repeat("a", 4096)))

	f.Fuzz(func(t *testing.T, data []byte) {
		cfg, err := parse(data)
		if err == nil {
			_ = Validate(cfg)
		}
	})
}

func TestParseRejectsOversizedConfig(t *testing.T) {
	path := filepath.Join(t.TempDir(), "runtime.yaml")
	if err := os.WriteFile(path, make([]byte, maxConfigFileSize+1), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Parse(path); err == nil || !strings.Contains(err.Error(), "exceeds") {
		t.Fatalf("Parse error = %v, want oversized-file rejection", err)
	}
}

func TestParseRejectsTrailingDocument(t *testing.T) {
	if _, err := parse([]byte("version: 1\n---\nversion: 1\n")); err == nil {
		t.Fatal("Parse accepted a second YAML document")
	}
	if _, err := parse([]byte("version: 1\n")); err != nil {
		t.Fatalf("Parse valid config: %v", err)
	}
}
