package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/netp2p/netp2p/internal/config"
	"github.com/netp2p/netp2p/internal/model"
)

func TestInitProductionWritesValidatedTrustDocuments(t *testing.T) {
	outputDir := filepath.Join(t.TempDir(), "bootstrap")
	args := []string{
		"--network", "netp2p-production",
		"--output-dir", outputDir,
		"--manager", "fr,fr.netp2p.zhongwwhhhh.cc,193.42.62.111,4001",
		"--manager", "sg,sg.netp2p.zhongwwhhhh.cc,45.127.32.84,4001",
		"--manager", "us-phx,us-phx.netp2p.zhongwwhhhh.cc,129.146.72.228,4001",
	}
	var err error
	output := captureInitOutput(t, func() { err = runInitProduction(args) })
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(output, "admin token (shown once)") || strings.Contains(output, "session secret (shown once)") {
		t.Fatalf("production init printed a secret without --show-secrets:\n%s", output)
	}

	manifestPath := filepath.Join(outputDir, "network.json")
	trustPath := filepath.Join(outputDir, "client-trust.json")
	manifest, loadErr := config.LoadNetworkManifest(manifestPath)
	if loadErr != nil {
		t.Fatal(loadErr)
	}
	trust, loadErr := config.LoadClientTrust(trustPath)
	if loadErr != nil {
		t.Fatal(loadErr)
	}
	if manifest.CommitteeParams != (model.CommitteeParams{Size: 3, FaultLimit: 0, QuorumSize: 3}) {
		t.Fatalf("committee params = %+v", manifest.CommitteeParams)
	}
	if len(manifest.Managers) != 3 || len(trust.Managers) != 3 {
		t.Fatalf("public documents do not contain three managers")
	}

	var bundles [3]config.ManagerBundle
	paths := []string{
		filepath.Join(outputDir, "manager-fr.json"),
		filepath.Join(outputDir, "manager-sg.json"),
		filepath.Join(outputDir, "manager-us-phx.json"),
	}
	for index, path := range paths {
		bundle, loadErr := config.LoadManagerBundle(path, manifest)
		if loadErr != nil {
			t.Fatal(loadErr)
		}
		bundles[index] = bundle
	}
	for index := range bundles {
		raw, readErr := os.ReadFile(paths[index])
		if readErr != nil {
			t.Fatal(readErr)
		}
		for other, otherBundle := range bundles {
			if index == other {
				continue
			}
			if strings.Contains(string(raw), otherBundle.PrivateKey) {
				t.Fatalf("manager bundle %d contains manager %d private key", index, other)
			}
		}
	}
	if bundles[0].AdminToken != bundles[1].AdminToken || bundles[1].AdminToken != bundles[2].AdminToken {
		t.Fatal("admin token is not shared")
	}
	if bundles[0].SessionSecret != bundles[1].SessionSecret || bundles[1].SessionSecret != bundles[2].SessionSecret {
		t.Fatal("session secret is not shared")
	}

	for _, path := range []string{manifestPath, trustPath, filepath.Join(outputDir, "owner-bootstrap.txt"), filepath.Join(outputDir, "README.txt")} {
		raw, readErr := os.ReadFile(path)
		if readErr != nil {
			t.Fatal(readErr)
		}
		for _, secret := range []string{bundles[0].AdminToken, bundles[0].SessionSecret, bundles[0].PrivateKey} {
			if strings.Contains(string(raw), secret) {
				t.Fatalf("%s leaked private material", path)
			}
		}
	}
	ownerGuide, err := os.ReadFile(filepath.Join(outputDir, "owner-bootstrap.txt"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(ownerGuide), "no owner password") || !strings.Contains(string(ownerGuide), "/api/v1/bootstrap/owner") {
		t.Fatalf("owner bootstrap guide is incomplete:\n%s", ownerGuide)
	}

	if runtime.GOOS != "windows" {
		assertProductionMode(t, outputDir, 0o700)
		assertProductionMode(t, manifestPath, 0o644)
		assertProductionMode(t, trustPath, 0o644)
		assertProductionMode(t, filepath.Join(outputDir, "owner-bootstrap.txt"), 0o644)
		assertProductionMode(t, filepath.Join(outputDir, "README.txt"), 0o644)
		for _, path := range paths {
			assertProductionMode(t, path, 0o600)
		}
	}

	if err := runInitProduction(args); err == nil {
		t.Fatal("production init overwrote existing documents without --force")
	}
	args = append(args, "--force")
	if err := runInitProduction(args); err != nil {
		t.Fatalf("--force did not replace output: %v", err)
	}
}

func TestInitProductionRequiresThreeManagers(t *testing.T) {
	err := runInitProduction([]string{
		"--output-dir", filepath.Join(t.TempDir(), "bootstrap"),
		"--manager", "fr,fr.netp2p.zhongwwhhhh.cc,193.42.62.111,4001",
		"--manager", "sg,sg.netp2p.zhongwwhhhh.cc,45.127.32.84,4001",
	})
	if err == nil || !strings.Contains(err.Error(), "exactly three") {
		t.Fatalf("two-manager input error = %v", err)
	}
}

func TestInitProductionShowSecretsPrintsOnce(t *testing.T) {
	outputDir := filepath.Join(t.TempDir(), "bootstrap")
	var err error
	output := captureInitOutput(t, func() {
		err = runInitProduction([]string{
			"--output-dir", outputDir,
			"--manager", "fr,fr.netp2p.zhongwwhhhh.cc,193.42.62.111,4001",
			"--manager", "sg,sg.netp2p.zhongwwhhhh.cc,45.127.32.84,4001",
			"--manager", "us-phx,us-phx.netp2p.zhongwwhhhh.cc,129.146.72.228,4001",
			"--show-secrets",
		})
	})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(output, "Shared admin token (shown once)") || !strings.Contains(output, "Shared session secret (shown once)") {
		t.Fatalf("show-secrets output is missing tokens:\n%s", output)
	}
	var bundle config.ManagerBundle
	raw, err := os.ReadFile(filepath.Join(outputDir, "manager-fr.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(raw, &bundle); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(output, bundle.AdminToken) || !strings.Contains(output, bundle.SessionSecret) {
		t.Fatal("show-secrets did not print the generated shared tokens")
	}
}

func assertProductionMode(t *testing.T, path string, want os.FileMode) {
	t.Helper()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != want {
		t.Fatalf("%s mode = %o, want %o", path, info.Mode().Perm(), want)
	}
}
