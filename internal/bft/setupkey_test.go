package bft

import (
	"testing"
	"time"

	"github.com/netp2p/netp2p/internal/model"
)

func testSetupKeyState() model.NetworkState {
	return model.NetworkState{
		NetworkID:   "net-1",
		OverlayCIDR: "100.64.0.0/24",
		Groups:      []model.Group{{ID: "clients"}},
		SetupKeys: []model.SetupKey{
			{ID: "key-valid", Token: "valid-token", TokenHash: model.SetupKeyHash("valid-token"), Type: model.SetupKeyReusable, Groups: []string{"clients"}},
		},
	}
}

func TestSetupKeyValidTokenRegisters(t *testing.T) {
	state := testSetupKeyState()
	transition := model.StateTransition{Type: TransitionRegisterPeer, SetupKey: "valid-token", Peer: model.PeerRecord{PeerID: "peer-1"}}
	if err := ApplyTransition(&state, transition); err != nil {
		t.Fatalf("register: %v", err)
	}
	if len(state.Peers) != 1 || state.Peers[0].PeerID != "peer-1" {
		t.Fatalf("peer not registered: %+v", state.Peers)
	}
	if state.SetupKeys[0].UsedCount != 1 {
		t.Fatalf("used count = %d, want 1", state.SetupKeys[0].UsedCount)
	}
}

func TestSetupKeyInvalidTokenRejected(t *testing.T) {
	state := testSetupKeyState()
	transition := model.StateTransition{Type: TransitionRegisterPeer, SetupKey: "wrong-token", Peer: model.PeerRecord{PeerID: "peer-1"}}
	if err := ApplyTransition(&state, transition); err == nil {
		t.Fatal("invalid token accepted")
	}
}

func TestSetupKeyRevokedRejected(t *testing.T) {
	state := testSetupKeyState()
	state.SetupKeys[0].Revoked = true
	transition := model.StateTransition{Type: TransitionRegisterPeer, SetupKey: "valid-token", Peer: model.PeerRecord{PeerID: "peer-1"}}
	if err := ApplyTransition(&state, transition); err == nil {
		t.Fatal("revoked key accepted")
	}
}

func TestSetupKeyExpiredRejected(t *testing.T) {
	state := testSetupKeyState()
	state.SetupKeys[0].ExpiresAt = time.Now().UTC().Add(-time.Hour).Format(time.RFC3339)
	transition := model.StateTransition{Type: TransitionRegisterPeer, SetupKey: "valid-token", Peer: model.PeerRecord{PeerID: "peer-1"}}
	if err := ApplyTransition(&state, transition); err == nil {
		t.Fatal("expired key accepted")
	}
}

func TestSetupKeyOneOffSingleUse(t *testing.T) {
	state := testSetupKeyState()
	state.SetupKeys[0].Type = model.SetupKeyOneOff

	first := model.StateTransition{Type: TransitionRegisterPeer, SetupKey: "valid-token", Peer: model.PeerRecord{PeerID: "peer-1"}}
	if err := ApplyTransition(&state, first); err != nil {
		t.Fatalf("first use: %v", err)
	}

	second := model.StateTransition{Type: TransitionRegisterPeer, SetupKey: "valid-token", Peer: model.PeerRecord{PeerID: "peer-2"}}
	if err := ApplyTransition(&state, second); err == nil {
		t.Fatal("one-off key accepted second use")
	}
}

func TestSetupKeyUsageLimit(t *testing.T) {
	state := testSetupKeyState()
	state.SetupKeys[0].UsageLimit = 2

	for i, peerID := range []string{"peer-1", "peer-2"} {
		transition := model.StateTransition{Type: TransitionRegisterPeer, SetupKey: "valid-token", Peer: model.PeerRecord{PeerID: peerID}}
		if err := ApplyTransition(&state, transition); err != nil {
			t.Fatalf("use %d: %v", i+1, err)
		}
	}
	if state.SetupKeys[0].UsedCount != 2 {
		t.Fatalf("used count = %d, want 2", state.SetupKeys[0].UsedCount)
	}
	third := model.StateTransition{Type: TransitionRegisterPeer, SetupKey: "valid-token", Peer: model.PeerRecord{PeerID: "peer-3"}}
	if err := ApplyTransition(&state, third); err == nil {
		t.Fatal("key over limit accepted")
	}
}

func TestSetupKeyUnlimitedWhenLimitZero(t *testing.T) {
	state := testSetupKeyState()
	for i, peerID := range []string{"peer-1", "peer-2", "peer-3"} {
		transition := model.StateTransition{Type: TransitionRegisterPeer, SetupKey: "valid-token", Peer: model.PeerRecord{PeerID: peerID}}
		if err := ApplyTransition(&state, transition); err != nil {
			t.Fatalf("use %d: %v", i+1, err)
		}
	}
}

func TestRevokeSetupKey(t *testing.T) {
	state := testSetupKeyState()
	transition := model.StateTransition{Type: TransitionRevokeSetupKey, TargetID: "key-valid"}
	if err := ApplyTransition(&state, transition); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	if !state.SetupKeys[0].Revoked {
		t.Fatal("key not revoked")
	}

	// Registration must now fail.
	register := model.StateTransition{Type: TransitionRegisterPeer, SetupKey: "valid-token", Peer: model.PeerRecord{PeerID: "peer-1"}}
	if err := ApplyTransition(&state, register); err == nil {
		t.Fatal("revoked key accepted registration")
	}
}

func TestRevokeMissingKeyFails(t *testing.T) {
	state := testSetupKeyState()
	transition := model.StateTransition{Type: TransitionRevokeSetupKey, TargetID: "nope"}
	if err := ApplyTransition(&state, transition); err == nil {
		t.Fatal("revoking missing key should fail")
	}
}

func TestUpsertSetupKeyRequiresID(t *testing.T) {
	state := testSetupKeyState()
	transition := model.StateTransition{Type: TransitionUpsertSetupKey, Record: &model.SetupKey{Token: "x", Groups: []string{"clients"}}}
	if err := ApplyTransition(&state, transition); err == nil {
		t.Fatal("upsert without ID should fail")
	}
}

func TestUpsertSetupKeyRequiresGroups(t *testing.T) {
	state := testSetupKeyState()
	transition := model.StateTransition{Type: TransitionUpsertSetupKey, Record: &model.SetupKey{ID: "new"}}
	if err := ApplyTransition(&state, transition); err == nil {
		t.Fatal("upsert without groups should fail")
	}
}

func TestUpsertSetupKeyRejectsUnknownGroup(t *testing.T) {
	state := testSetupKeyState()
	transition := model.StateTransition{Type: TransitionUpsertSetupKey, Record: &model.SetupKey{ID: "new", Groups: []string{"ghost"}}}
	if err := ApplyTransition(&state, transition); err == nil {
		t.Fatal("upsert with unknown group should fail")
	}
}
