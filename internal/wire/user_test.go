package wire_test

import (
	"bytes"
	"testing"

	"github.com/netp2p/netp2p/internal/model"
	"github.com/netp2p/netp2p/internal/wire"
)

func TestUserVerifierRoundTrip(t *testing.T) {
	user := model.User{
		ID: "user-1", Email: "user@example.com", Role: model.RoleUser,
		PasswordVerifier:     model.HashPassword("correct horse battery"),
		CredentialsChangedAt: "2026-01-01T00:00:00Z",
	}
	encoded := wire.UserToProto(user)
	if !bytes.Equal(encoded.GetPasswordVerifier(), user.PasswordVerifier) {
		t.Fatal("wire User dropped password verifier")
	}
	if encoded.GetCredentialsChangedAt() != user.CredentialsChangedAt {
		t.Fatalf("credentials timestamp = %q", encoded.GetCredentialsChangedAt())
	}
	decoded := wire.UserFromProto(encoded)
	if !bytes.Equal(decoded.PasswordVerifier, user.PasswordVerifier) || decoded.CredentialsChangedAt != user.CredentialsChangedAt {
		t.Fatalf("decoded user = %+v", decoded)
	}
	client := model.ClientSnapshot(model.SignedSnapshot{
		State:      model.NetworkState{Users: []model.User{user}},
		Transition: model.StateTransition{User: &user},
	})
	if client.State.Users[0].PasswordVerifier != nil || client.Transition.User.PasswordVerifier != nil {
		t.Fatal("public snapshot retained password verifier")
	}
}
