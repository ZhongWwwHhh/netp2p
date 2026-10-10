package main

import (
	"crypto/hmac"
	"os"
	"path/filepath"
	"testing"

	"github.com/netp2p/netp2p/internal/bft"
	"github.com/netp2p/netp2p/internal/model"
)

// The admin CLI must be able to promote a registered peer to an exit node so
// operators (and the e2e script) do not need the web console.
func TestBuildTransitionUpdatePeer(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "peer.json")
	if err := os.WriteFile(path, []byte(`{"peerId":"peer-a","isExitNode":true}`), 0o600); err != nil {
		t.Fatal(err)
	}
	transition, err := buildTransition("update-peer", path, "")
	if err != nil {
		t.Fatalf("buildTransition: %v", err)
	}
	if transition.Type != bft.TransitionUpdatePeer {
		t.Fatalf("type = %q, want %q", transition.Type, bft.TransitionUpdatePeer)
	}
	if transition.Peer.PeerID != "peer-a" || !transition.Peer.IsExitNode {
		t.Fatalf("peer = %+v, want peer-a with isExitNode", transition.Peer)
	}
}

// The plaintext setup key crosses one trust boundary, is converted to its
// verifier at the CLI, and must never reach certified/client-visible state.
func TestBuildTransitionUpsertSetupKeyHashesToken(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "setup-key.json")
	payload := []byte("{\n  \"id\": \"key-a\",\n  \"token\": \"  netp2p-test-key  \",\n  \"groups\": [\"clients\"]\n}")
	if err := os.WriteFile(path, payload, 0o600); err != nil {
		t.Fatal(err)
	}
	transition, err := buildTransition("upsert-setup-key", path, "")
	if err != nil {
		t.Fatalf("buildTransition: %v", err)
	}
	key := transition.Record
	if key == nil {
		t.Fatal("record is nil, want *model.SetupKey")
	}
	if key.Token != "" {
		t.Fatal("plaintext token was not cleared")
	}
	if !hmac.Equal(key.TokenHash, model.SetupKeyHash("netp2p-test-key")) {
		t.Fatal("tokenHash does not match verifier for trimmed token")
	}
}

func TestBuildTransitionUpsertSetupKeyRequiresTokenOrHash(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "setup-key.json")
	payload := []byte("{\n  \"id\": \"key-a\",\n  \"groups\": [\"clients\"]\n}")
	if err := os.WriteFile(path, payload, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := buildTransition("upsert-setup-key", path, ""); err == nil {
		t.Fatal("buildTransition succeeded without token or tokenHash")
	}
}
