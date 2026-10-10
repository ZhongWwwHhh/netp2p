package config

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/netp2p/netp2p/internal/model"
	"github.com/netp2p/netp2p/internal/version"
)

func TestTrustSplitLoadsAndRedactsSecrets(t *testing.T) {
	directory := t.TempDir()
	manifest, bundles := testTrustMaterial(t)

	manifestPath := filepath.Join(directory, "network.json")
	writeJSONFile(t, manifestPath, manifest)
	loadedManifest, err := LoadNetworkManifest(manifestPath)
	if err != nil {
		t.Fatalf("LoadNetworkManifest: %v", err)
	}
	if loadedManifest.NetworkID != manifest.NetworkID {
		t.Fatalf("network id = %q", loadedManifest.NetworkID)
	}

	bundlePath := filepath.Join(directory, "manager-fr.json")
	writeJSONFile(t, bundlePath, bundles[0])
	bundle, err := LoadManagerBundle(bundlePath, loadedManifest)
	if err != nil {
		t.Fatalf("LoadManagerBundle: %v", err)
	}
	if bundle.ManagerID != "fr" || bundle.IdentityKey() == nil {
		t.Fatalf("bundle = %+v", bundle)
	}

	trust := loadedManifest.ClientTrust()
	trustPath := filepath.Join(directory, "client-trust.json")
	writeJSONFile(t, trustPath, trust)
	loadedTrust, err := LoadClientTrust(trustPath)
	if err != nil {
		t.Fatalf("LoadClientTrust: %v", err)
	}
	if len(loadedTrust.Managers) != 3 || loadedTrust.ProtocolVersion != version.ProtocolVersion {
		t.Fatalf("trust = %+v", loadedTrust)
	}

	assertNoSecretFields(t, "manifest", manifestPath)
	assertNoSecretFields(t, "client trust", trustPath)
}

func TestManagerBundleRejectsWrongManager(t *testing.T) {
	directory := t.TempDir()
	manifest, bundles := testTrustMaterial(t)
	manifestPath := filepath.Join(directory, "network.json")
	bundlePath := filepath.Join(directory, "bundle.json")
	writeJSONFile(t, manifestPath, manifest)
	writeJSONFile(t, bundlePath, bundles[0])
	bundles[0].ManagerID = "sg"
	writeJSONFile(t, bundlePath, bundles[0])

	if _, err := LoadManagerBundle(bundlePath, manifest); err == nil {
		t.Fatal("bundle for another manager was accepted")
	}
}

func TestManagerBundleRejectsShortSessionSecret(t *testing.T) {
	directory := t.TempDir()
	manifest, bundles := testTrustMaterial(t)
	manifestPath := filepath.Join(directory, "network.json")
	bundlePath := filepath.Join(directory, "bundle.json")
	writeJSONFile(t, manifestPath, manifest)
	bundles[0].SessionSecret = "too-short"
	writeJSONFile(t, bundlePath, bundles[0])

	if _, err := LoadManagerBundle(bundlePath, manifest); err == nil {
		t.Fatal("short session secret was accepted")
	}
}

func TestManagerBundleRejectsShortAdminToken(t *testing.T) {
	directory := t.TempDir()
	manifest, bundles := testTrustMaterial(t)
	manifestPath := filepath.Join(directory, "network.json")
	bundlePath := filepath.Join(directory, "bundle.json")
	writeJSONFile(t, manifestPath, manifest)
	bundles[0].AdminToken = "too-short"
	writeJSONFile(t, bundlePath, bundles[0])

	if _, err := LoadManagerBundle(bundlePath, manifest); err == nil {
		t.Fatal("short admin token was accepted")
	}
}

func TestNetworkManifestRejectsKeySeed(t *testing.T) {
	manifest, _ := testTrustMaterial(t)
	manifest.Managers[0].KeySeed = 101
	if err := manifest.Validate(); err == nil {
		t.Fatal("manifest with keySeed was accepted")
	}
}

func TestLegacySeedRejectsDeterministicKeysOutsideDevFixture(t *testing.T) {
	directory := t.TempDir()
	path := filepath.Join(directory, "seed.json")
	seed := Seed{
		NetworkID: "legacy", OverlayCIDR: "100.64.0.0/24",
		Managers: []model.CommitteeMember{
			{ID: "m1", Address: "/ip4/127.0.0.1/udp/4001/quic-v1", KeySeed: 1},
			{ID: "m2", Address: "/ip4/127.0.0.1/udp/4002/quic-v1", KeySeed: 2},
			{ID: "m3", Address: "/ip4/127.0.0.1/udp/4003/quic-v1", KeySeed: 3},
		},
	}
	writeJSONFile(t, path, seed)
	if _, err := Load(path); err == nil {
		t.Fatal("non-development deterministic seed was accepted")
	}
}

func testTrustMaterial(t *testing.T) (NetworkManifest, [3]ManagerBundle) {
	t.Helper()
	manifest := NetworkManifest{
		Version: NetworkManifestVersion, NetworkID: "netp2p-production",
		OverlayCIDR: "100.64.0.0/24", ProtocolVersion: version.ProtocolVersion,
		CommitteeParams: model.DefaultCommitteeParams(), NextIPOffset: 11,
		Settings: model.NetworkSettings{DirectPathEnabled: true, ViaManagerEnabled: true},
	}
	var bundles [3]ManagerBundle
	names := []string{"fr", "sg", "us-phx"}
	for index, name := range names {
		privateKey, _, err := crypto.GenerateEd25519Key(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		peerID, err := peer.IDFromPrivateKey(privateKey)
		if err != nil {
			t.Fatal(err)
		}
		publicKey, err := privateKey.GetPublic().Raw()
		if err != nil {
			t.Fatal(err)
		}
		encoded, err := crypto.MarshalPrivateKey(privateKey)
		if err != nil {
			t.Fatal(err)
		}
		manifest.Managers = append(manifest.Managers, model.CommitteeMember{
			ID: name, PeerID: peerID.String(), PublicKey: publicKey,
			Address: "/ip4/127.0.0.1/udp/4001/quic-v1", ForwardingEnabled: true,
		})
		bundles[index] = ManagerBundle{
			Version: ManagerBundleVersion, NetworkID: manifest.NetworkID, ManagerID: name,
			PrivateKey: base64.StdEncoding.EncodeToString(encoded),
			AdminToken: "admin-token-0123456789abcdef0123456789", SessionSecret: "session-secret-0123456789abcdef0",
		}
	}
	return manifest, bundles
}

func writeJSONFile(t *testing.T, path string, value any) {
	t.Helper()
	encoded, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, encoded, 0o600); err != nil {
		t.Fatal(err)
	}
}

func assertNoSecretFields(t *testing.T, label, path string) {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	text := string(data)
	for _, field := range []string{"keySeed", "adminToken", "sessionSecret", "setupKeys", "privateKey"} {
		if strings.Contains(text, `"`+field+`"`) {
			t.Fatalf("%s contains secret field %q", label, field)
		}
	}
}
