package bft

import (
	"testing"

	"github.com/netp2p/netp2p/internal/model"
)

func baseUserState() model.NetworkState {
	return model.NetworkState{
		NetworkID:   "net-1",
		OverlayCIDR: "100.64.0.0/24",
		Groups: []model.Group{
			{ID: "eng", Name: "Engineering", Issued: model.GroupIssuedJWT},
			{ID: "ops", Name: "Operations", Issued: model.GroupIssuedJWT},
			{ID: "servers", Name: "Servers", Issued: model.GroupIssuedAPI},
		},
		SetupKeys: []model.SetupKey{{ID: "key", Token: "key", TokenHash: model.SetupKeyHash("key"), Groups: []string{"servers"}}},
	}
}

func apply(t *testing.T, state *model.NetworkState, transition model.StateTransition) {
	t.Helper()
	if err := ApplyTransition(state, transition); err != nil {
		t.Fatalf("apply %s: %v", transition.Type, err)
	}
}

func TestRegisterUserAddsGroupMembership(t *testing.T) {
	state := baseUserState()
	apply(t, &state, model.StateTransition{
		Type: TransitionRegisterUser,
		User: &model.User{ID: "user-1", Email: "a@example.com", Role: model.RoleOwner, AutoGroups: []string{"eng", "eng"}},
	})
	if len(state.Users) != 1 {
		t.Fatalf("users = %d", len(state.Users))
	}
	if len(state.Users[0].AutoGroups) != 1 || state.Users[0].AutoGroups[0] != "eng" {
		t.Fatalf("auto groups = %v", state.Users[0].AutoGroups)
	}
	if !groupContainsUser(state, "eng", "user-1") {
		t.Fatal("user must join the eng group")
	}
}

func TestRegisterPeerUnionsSetupKeyAndUserGroups(t *testing.T) {
	state := baseUserState()
	apply(t, &state, model.StateTransition{
		Type: TransitionRegisterUser,
		User: &model.User{ID: "user-1", Role: model.RoleAdmin, AutoGroups: []string{"eng"}},
	})
	apply(t, &state, model.StateTransition{
		Type:     TransitionRegisterPeer,
		SetupKey: "key",
		Peer:     model.PeerRecord{PeerID: "peer-a", UserID: "user-1", Hostname: "laptop"},
	})
	peer := state.Peers[0]
	if len(peer.Groups) != 2 {
		t.Fatalf("peer groups = %v, want servers+eng", peer.Groups)
	}
	if !groupContainsPeer(state, "eng", "peer-a") || !groupContainsPeer(state, "servers", "peer-a") {
		t.Fatalf("peer not recorded in both groups: %+v", state.Groups)
	}
}

func TestRegisterPeerRejectsBlockedUser(t *testing.T) {
	state := baseUserState()
	apply(t, &state, model.StateTransition{
		Type: TransitionRegisterUser,
		User: &model.User{ID: "user-1", Role: model.RoleUser, AutoGroups: []string{"eng"}, Blocked: true},
	})
	err := ApplyTransition(&state, model.StateTransition{
		Type: TransitionRegisterPeer,
		Peer: model.PeerRecord{PeerID: "peer-a", UserID: "user-1", Hostname: "laptop"},
	})
	if err == nil {
		t.Fatal("a blocked user must not register a peer")
	}
}

func TestUpdateUserGroupsPropagatesToPeers(t *testing.T) {
	state := baseUserState()
	apply(t, &state, model.StateTransition{
		Type: TransitionRegisterUser,
		User: &model.User{ID: "user-1", Role: model.RoleUser, AutoGroups: []string{"eng"}},
	})
	apply(t, &state, model.StateTransition{
		Type: TransitionRegisterPeer,
		Peer: model.PeerRecord{PeerID: "peer-a", UserID: "user-1", Hostname: "laptop"},
	})

	// The IdP now reports ops instead of eng.
	apply(t, &state, model.StateTransition{
		Type: TransitionUpdateUserGroups,
		User: &model.User{ID: "user-1", AutoGroups: []string{"ops"}},
	})
	if groupContainsPeer(state, "eng", "peer-a") {
		t.Fatal("peer must leave the removed jwt group")
	}
	if !groupContainsPeer(state, "ops", "peer-a") {
		t.Fatalf("peer must join the new group: %+v", state.Groups)
	}
	peer := state.Peers[0]
	if len(peer.Groups) != 1 || peer.Groups[0] != "ops" {
		t.Fatalf("peer groups = %v", peer.Groups)
	}
}

func TestUserRoleAndOwnerInvariants(t *testing.T) {
	state := baseUserState()
	apply(t, &state, model.StateTransition{
		Type: TransitionRegisterUser,
		User: &model.User{ID: "owner-1", Role: model.RoleOwner},
	})
	if err := ApplyTransition(&state, model.StateTransition{
		Type: TransitionUpdateUserRole,
		User: &model.User{ID: "owner-1", Role: model.RoleUser},
	}); err == nil {
		t.Fatal("the last owner must not be demoted")
	}
	apply(t, &state, model.StateTransition{
		Type: TransitionRegisterUser,
		User: &model.User{ID: "owner-2", Role: model.RoleOwner},
	})
	apply(t, &state, model.StateTransition{
		Type: TransitionUpdateUserRole,
		User: &model.User{ID: "owner-1", Role: model.RoleAdmin},
	})
	if state.Users[0].Role != model.RoleAdmin {
		t.Fatalf("role = %q", state.Users[0].Role)
	}
}

func TestRemoveUserRemovesTheirPeers(t *testing.T) {
	state := baseUserState()
	apply(t, &state, model.StateTransition{
		Type: TransitionRegisterUser,
		User: &model.User{ID: "user-1", Role: model.RoleUser, AutoGroups: []string{"eng"}},
	})
	apply(t, &state, model.StateTransition{
		Type: TransitionRegisterPeer,
		Peer: model.PeerRecord{PeerID: "peer-a", UserID: "user-1", Hostname: "laptop"},
	})
	apply(t, &state, model.StateTransition{Type: TransitionRemoveUser, TargetID: "user-1"})
	if len(state.Users) != 0 {
		t.Fatalf("users = %d", len(state.Users))
	}
	if len(state.Peers) != 0 {
		t.Fatalf("peers = %d", len(state.Peers))
	}
	if groupContainsUser(state, "eng", "user-1") || groupContainsPeer(state, "eng", "peer-a") {
		t.Fatal("removed user must leave group membership")
	}
}

func TestRemoveJWTGroupIsRejected(t *testing.T) {
	state := baseUserState()
	if err := ApplyTransition(&state, model.StateTransition{Type: TransitionRemoveGroup, TargetID: "eng"}); err == nil {
		t.Fatal("a JWT-managed group must not be removed by hand")
	}
	apply(t, &state, model.StateTransition{Type: TransitionRemoveGroup, TargetID: "servers"})
}

func TestUpdateNetworkSettingsValidates(t *testing.T) {
	state := baseUserState()
	apply(t, &state, model.StateTransition{
		Type:     TransitionUpdateSettings,
		Settings: &model.NetworkSettings{DNSDomain: "netp2p.internal", LoginExpirationDays: 30},
	})
	if state.Settings.DNSDomain != "netp2p.internal" {
		t.Fatalf("settings = %+v", state.Settings)
	}
	if err := ApplyTransition(&state, model.StateTransition{
		Type:     TransitionUpdateSettings,
		Settings: &model.NetworkSettings{LoginExpirationDays: -1},
	}); err == nil {
		t.Fatal("negative expiration must be rejected")
	}
}

func TestUpdatePeerAssignsDNSLabelAndUser(t *testing.T) {
	state := baseUserState()
	apply(t, &state, model.StateTransition{
		Type: TransitionRegisterUser,
		User: &model.User{ID: "user-1", Role: model.RoleUser},
	})
	apply(t, &state, model.StateTransition{
		Type:     TransitionRegisterPeer,
		SetupKey: "key",
		Peer:     model.PeerRecord{PeerID: "peer-a", Hostname: "laptop"},
	})
	if state.Peers[0].DNSLabel != "laptop" {
		t.Fatalf("dns label = %q", state.Peers[0].DNSLabel)
	}
	apply(t, &state, model.StateTransition{
		Type: TransitionUpdatePeer,
		Peer: model.PeerRecord{PeerID: "peer-a", UserID: "user-1", LastLogin: "2026-09-19T00:00:00Z"},
	})
	if state.Peers[0].UserID != "user-1" || state.Peers[0].LastLogin == "" {
		t.Fatalf("peer = %+v", state.Peers[0])
	}
}

func groupContainsUser(state model.NetworkState, groupID, userID string) bool {
	for _, group := range state.Groups {
		if group.ID != groupID {
			continue
		}
		for _, member := range group.UserIDs {
			if member == userID {
				return true
			}
		}
	}
	return false
}

func groupContainsPeer(state model.NetworkState, groupID, peerID string) bool {
	for _, group := range state.Groups {
		if group.ID != groupID {
			continue
		}
		for _, member := range group.PeerIDs {
			if member == peerID {
				return true
			}
		}
	}
	return false
}
