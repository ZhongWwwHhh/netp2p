package wire_test

import (
	"bytes"
	"testing"

	"github.com/netp2p/netp2p/internal/bft"
	"github.com/netp2p/netp2p/internal/model"
	"github.com/netp2p/netp2p/internal/wire"
)

func TestCredentialVerifierRoundTrip(t *testing.T) {
	verifier := model.HashPassword("correct horse battery")
	transition := model.StateTransition{
		Type: "update_user_credentials", TargetID: "user-1",
		User: &model.User{
			ID: "user-1", Email: "user@example.com", Role: model.RoleUser,
			PasswordVerifier:     verifier,
			CredentialsChangedAt: "2026-01-01T00:00:00Z",
		},
	}
	encoded := wire.StateTransitionToProto(transition)
	if !bytes.Equal(encoded.GetUserPasswordVerifier(), verifier) {
		t.Fatal("wire transition dropped credential verifier")
	}
	if encoded.GetUser().GetCredentialsChangedAt() != transition.User.CredentialsChangedAt {
		t.Fatalf("credentials timestamp = %q", encoded.GetUser().GetCredentialsChangedAt())
	}
	decoded := wire.StateTransitionFromProto(encoded)
	if !bytes.Equal(decoded.User.PasswordVerifier, verifier) || decoded.User.CredentialsChangedAt != transition.User.CredentialsChangedAt {
		t.Fatalf("decoded transition = %+v", decoded)
	}
	client := model.ClientSnapshot(model.SignedSnapshot{
		State:      model.NetworkState{Users: []model.User{*transition.User}},
		Transition: transition,
	})
	if client.State.Users[0].PasswordVerifier != nil || client.Transition.User.PasswordVerifier != nil {
		t.Fatal("public snapshot retained password verifier")
	}
}

func TestRegisterUserCredentialVerifierRoundTrip(t *testing.T) {
	verifier := model.HashPassword("bootstrap-owner-password")
	transition := model.StateTransition{
		Type: bft.TransitionRegisterUser,
		User: &model.User{
			ID: "owner-1", Email: "owner@example.com", Role: model.RoleOwner,
			PasswordVerifier: verifier,
		},
	}
	decoded := wire.StateTransitionFromProto(wire.StateTransitionToProto(transition))
	if decoded.User == nil || !bytes.Equal(decoded.User.PasswordVerifier, verifier) {
		t.Fatalf("register_user dropped credential verifier: %+v", decoded.User)
	}
}

func TestRegisterUserKeepsHistoricalVerifierEncoding(t *testing.T) {
	verifier := model.HashPassword("bootstrap-owner-password")
	transition := model.StateTransition{
		Type: bft.TransitionRegisterUser,
		User: &model.User{
			ID: "owner-1", Email: "owner@example.com", Role: model.RoleOwner,
			PasswordVerifier: verifier,
		},
	}
	encoded := wire.StateTransitionToProto(transition)
	if len(encoded.GetUserPasswordVerifier()) != 0 {
		t.Fatal("register_user must not use the dedicated credential verifier field")
	}
	if !bytes.Equal(encoded.GetUser().GetPasswordVerifier(), verifier) {
		t.Fatal("register_user dropped the historical nested verifier")
	}
}
