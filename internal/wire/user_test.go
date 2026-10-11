package wire_test

import (
	"bytes"
	"testing"

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
