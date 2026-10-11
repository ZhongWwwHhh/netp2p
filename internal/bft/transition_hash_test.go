package bft

import (
	"bytes"
	"testing"

	"github.com/netp2p/netp2p/internal/model"
	"github.com/netp2p/netp2p/internal/wire"
)

func TestTransitionHashKeepsHistoricalUserVerifierCompatibility(t *testing.T) {
	verifier := model.HashPassword("correct horse battery")
	register := model.StateTransition{
		Type: TransitionRegisterUser,
		User: &model.User{ID: "user-1", Email: "user@example.com", Role: model.RoleUser},
	}
	registerWithVerifier := register
	registerWithVerifier.User = &model.User{
		ID: "user-1", Email: "user@example.com", Role: model.RoleUser,
		PasswordVerifier: verifier,
	}
	if !bytes.Equal(TransitionHash(register), TransitionHash(registerWithVerifier)) {
		t.Fatal("historical register transition hash changed when a nested verifier is present")
	}

	update := model.StateTransition{
		Type:     TransitionUpdateUserCredentials,
		TargetID: "user-1",
		User:     &model.User{Email: "user@example.com", PasswordVerifier: verifier},
	}
	decoded := wire.StateTransitionFromProto(wire.StateTransitionToProto(update))
	if !bytes.Equal(TransitionHash(update), TransitionHash(decoded)) {
		t.Fatal("credential update verifier did not round-trip through the transition hash")
	}
	changed := update
	changed.User = &model.User{Email: "user@example.com", PasswordVerifier: model.HashPassword("another password")}
	if bytes.Equal(TransitionHash(update), TransitionHash(changed)) {
		t.Fatal("credential update did not bind its verifier into the transition hash")
	}
}

func TestStateWireKeepsManagerSidePasswordVerifier(t *testing.T) {
	state := model.NetworkState{
		NetworkID: "network", OverlayCIDR: "100.64.0.0/24",
		Users: []model.User{{
			ID: "user-1", Email: "user@example.com", Role: model.RoleOwner,
			PasswordVerifier: model.HashPassword("correct horse battery"),
		}},
	}
	decoded := wire.NetworkStateFromProto(wire.NetworkStateToProto(state))
	if len(decoded.Users) != 1 || !model.VerifyPassword("correct horse battery", decoded.Users[0].PasswordVerifier) {
		t.Fatal("manager snapshot wire dropped the password verifier")
	}
}
