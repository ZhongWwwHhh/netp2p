package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestWriteSeedGeneratesUniqueSessionSecret(t *testing.T) {
	directory := t.TempDir()
	firstPath := filepath.Join(directory, "first.json")
	secondPath := filepath.Join(directory, "second.json")
	if err := writeSeed(firstPath); err != nil {
		t.Fatal(err)
	}
	if err := writeSeed(secondPath); err != nil {
		t.Fatal(err)
	}

	loadSecret := func(path string) string {
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		var seed struct {
			SessionSecret string `json:"sessionSecret"`
		}
		if err := json.Unmarshal(data, &seed); err != nil {
			t.Fatal(err)
		}
		return seed.SessionSecret
	}
	first := loadSecret(firstPath)
	second := loadSecret(secondPath)
	if len(first) < 32 {
		t.Fatalf("session secret length = %d, want at least 32", len(first))
	}
	if first == second || first == "netp2p-session-secret-v0-0123456789abcdef" {
		t.Fatal("seedgen wrote a fixed or repeated session secret")
	}
}
