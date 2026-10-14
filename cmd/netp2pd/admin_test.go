package main

import (
	"crypto/hmac"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

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

func TestManagerJoinReviewTransitionApprovesPendingRequest(t *testing.T) {
	snapshot := model.SignedSnapshot{State: model.NetworkState{ManagerJoins: []model.ManagerJoinRequest{{
		ID: "join-manager-4", ManagerID: "manager-4", Status: model.ManagerJoinPending,
	}}}}
	reviewedAt := time.Date(2026, 10, 12, 12, 0, 0, 0, time.UTC)
	transition, err := managerJoinReviewTransition(
		snapshot, "manager-4", model.ManagerJoinApproved, "owner@example.com", reviewedAt,
	)
	if err != nil {
		t.Fatalf("managerJoinReviewTransition: %v", err)
	}
	if transition.Type != bft.TransitionReviewManagerJoin {
		t.Fatalf("type = %q, want %q", transition.Type, bft.TransitionReviewManagerJoin)
	}
	request := transition.ManagerJoin
	if request == nil || request.Status != model.ManagerJoinApproved {
		t.Fatalf("managerJoin = %+v, want approved request", request)
	}
	if request.ReviewedBy != "owner@example.com" || request.ReviewedAt != reviewedAt.Format(time.RFC3339Nano) {
		t.Fatalf("review audit fields were not set: %+v", request)
	}
}

func TestManagerJoinReviewTransitionRejectsMissingRequest(t *testing.T) {
	_, err := managerJoinReviewTransition(
		model.SignedSnapshot{}, "manager-4", model.ManagerJoinApproved,
		"owner@example.com", time.Now().UTC(),
	)
	if err == nil || !strings.Contains(err.Error(), "not found") {
		t.Fatalf("missing request error = %v", err)
	}
}

func TestBuildTransitionRotateManagerJoinTokenHashesToken(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "manager-join-token.json")
	payload := []byte("{\n  \"token\": \"  committee-e2e-token-0123456789abcdef  \"\n}")
	if err := os.WriteFile(path, payload, 0o600); err != nil {
		t.Fatal(err)
	}
	transition, err := buildTransition("rotate-manager-join-token", path, "")
	if err != nil {
		t.Fatalf("buildTransition: %v", err)
	}
	if transition.Type != bft.TransitionRotateManagerJoinToken {
		t.Fatalf("type = %q, want %q", transition.Type, bft.TransitionRotateManagerJoinToken)
	}
	if !hmac.Equal(transition.ManagerJoinTokenHash, model.ManagerJoinTokenHash("committee-e2e-token-0123456789abcdef")) {
		t.Fatal("managerJoinTokenHash does not match verifier for trimmed token")
	}
}

func TestBuildTransitionRequestCommitteeShrink(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "shrink.json")
	payload := []byte(`[{"id":"manager-1","peerId":"peer-1","address":"/dns4/manager-1.netp2p.example/udp/4001/quic-v1","publicKey":"AQI=","forwardingEnabled":true}]`)
	if err := os.WriteFile(path, payload, 0o600); err != nil {
		t.Fatal(err)
	}
	transition, err := buildTransition("request-committee-shrink", path, "")
	if err != nil {
		t.Fatalf("buildTransition: %v", err)
	}
	if transition.Type != bft.TransitionRequestCommitteeShrink {
		t.Fatalf("type = %q, want %q", transition.Type, bft.TransitionRequestCommitteeShrink)
	}
	if len(transition.Committee) != 1 || transition.Committee[0].ID != "manager-1" {
		t.Fatalf("committee = %+v", transition.Committee)
	}
}
