package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/netp2p/netp2p/internal/bft"
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
