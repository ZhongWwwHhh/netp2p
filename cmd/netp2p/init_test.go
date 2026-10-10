package main

import (
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/netp2p/netp2p/internal/config"
	"github.com/netp2p/netp2p/internal/model"
)

func TestBuildInitialSeedUsesThreeManagers(t *testing.T) {
	seed, _, err := buildInitialSeed("net-init-test")
	if err != nil {
		t.Fatal(err)
	}
	if len(seed.Managers) != 3 {
		t.Fatalf("manager count = %d, want 3", len(seed.Managers))
	}
}

func TestInitNetworkWritesManagerConsumableOwnerAndSetupKey(t *testing.T) {
	dir := t.TempDir()
	password := "correct horse battery staple"
	passwordPath := filepath.Join(dir, "owner-password.txt")
	if err := os.WriteFile(passwordPath, []byte(password), 0o600); err != nil {
		t.Fatal(err)
	}
	seedPath := filepath.Join(dir, "seed.json")
	configPath := filepath.Join(dir, "runtime.yaml")
	setupKeyPath := filepath.Join(dir, "setup-key.txt")

	var initErr error
	output := captureInitOutput(t, func() {
		initErr = runInitNetwork([]string{
			"--network", "net-init-test",
			"--data-dir", dir,
			"--owner-email", "owner@example.com",
			"--owner-password-file", passwordPath,
			"--seed", seedPath,
			"--config", configPath,
			"--setup-key-file", setupKeyPath,
			"--yes",
		})
	})
	if initErr != nil {
		t.Fatal(initErr)
	}

	seedRaw, err := os.ReadFile(seedPath)
	if err != nil {
		t.Fatal(err)
	}
	var seed config.Seed
	if err := json.Unmarshal(seedRaw, &seed); err != nil {
		t.Fatal(err)
	}
	if len(seed.Managers) != 3 {
		t.Fatalf("seed manager count = %d, want 3", len(seed.Managers))
	}
	if seed.CommitteeParams != model.DefaultCommitteeParams() {
		t.Fatalf("seed committee params = %+v, want 3/0/3", seed.CommitteeParams)
	}
	if state := seed.NetworkState(); state.CommitteeConfig.Size != 3 || state.CommitteeConfig.Threshold != 3 {
		t.Fatalf("seed committee config = %+v, want size and threshold 3", state.CommitteeConfig)
	}
	if len(seed.Users) != 1 || seed.Users[0].Role != model.RoleOwner {
		t.Fatalf("seed users = %+v, want one owner", seed.Users)
	}
	if !model.VerifyPassword(password, seed.Users[0].PasswordVerifier) {
		t.Fatal("seed owner password verifier does not match")
	}
	if len(seed.SetupKeys) != 1 || seed.SetupKeys[0].Token != "" || len(seed.SetupKeys[0].TokenHash) == 0 {
		t.Fatalf("seed setup key is not redacted and hashed: %+v", seed.SetupKeys)
	}

	tokenRaw, err := os.ReadFile(setupKeyPath)
	if err != nil {
		t.Fatal(err)
	}
	if len(tokenRaw) == 0 {
		t.Fatal("setup key file is empty")
	}
	credentialsRaw, err := os.ReadFile(filepath.Join(dir, "owner-credentials.txt"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(credentialsRaw), password) {
		t.Fatal("owner credentials file does not contain the owner password")
	}

	var bootstrap bootstrapRecord
	bootstrapRaw, err := os.ReadFile(filepath.Join(dir, "bootstrap.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(bootstrapRaw, &bootstrap); err != nil {
		t.Fatal(err)
	}
	if bootstrap.NetworkID != "net-init-test" || !model.VerifyPassword(password, bootstrap.Owner.PasswordVerifier) {
		t.Fatalf("bootstrap record is not manager-consumable: %+v", bootstrap)
	}
	if bootstrap.SetupKey.Token != "" || len(bootstrap.SetupKey.TokenHash) == 0 {
		t.Fatalf("bootstrap setup key is not redacted and hashed: %+v", bootstrap.SetupKey)
	}

	if runtime.GOOS != "windows" {
		for _, path := range []string{setupKeyPath, filepath.Join(dir, "owner-credentials.txt"), bootstrapPath(dir)} {
			info, err := os.Stat(path)
			if err != nil {
				t.Fatal(err)
			}
			if info.Mode().Perm() != 0o600 {
				t.Fatalf("%s mode = %o, want 600", path, info.Mode().Perm())
			}
		}
	}

	if strings.Contains(output, password) || strings.Contains(output, strings.TrimSpace(string(tokenRaw))) {
		t.Fatalf("init output leaked a secret:\n%s", output)
	}
}

func bootstrapPath(dataDir string) string {
	return filepath.Join(dataDir, "bootstrap.json")
}

func captureInitOutput(t *testing.T, run func()) string {
	t.Helper()
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	original := os.Stdout
	os.Stdout = writer
	defer func() { os.Stdout = original }()

	run()
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	output, err := io.ReadAll(reader)
	if err != nil {
		t.Fatal(err)
	}
	return string(output)
}
