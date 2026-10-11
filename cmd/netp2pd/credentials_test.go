package main

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/netp2p/netp2p/internal/bft"
	"github.com/netp2p/netp2p/internal/model"
)

func TestBuildAdminCredentialsTransitionHashesPasswordFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "password")
	if err := os.WriteFile(path, []byte("correct horse battery\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	transition, err := buildAdminCredentialsTransition(nil, nil, "", "", "user-1", adminCredentialOptions{
		newEmail: " New@Example.Com ", passwordFile: path,
	})
	if err != nil {
		t.Fatalf("buildAdminCredentialsTransition: %v", err)
	}
	if transition.Type != bft.TransitionUpdateUserCredentials || transition.TargetID != "user-1" {
		t.Fatalf("transition = %+v", transition)
	}
	if transition.User.Email != "new@example.com" {
		t.Fatalf("email = %q", transition.User.Email)
	}
	if !model.VerifyPassword("correct horse battery", transition.User.PasswordVerifier) {
		t.Fatal("password verifier does not match trimmed password")
	}
}

func TestBuildAdminCredentialsTransitionRequiresChange(t *testing.T) {
	if _, err := buildAdminCredentialsTransition(nil, nil, "", "", "user-1", adminCredentialOptions{}); err == nil {
		t.Fatal("empty credential update was accepted")
	}
}

func TestFindDirectoryUser(t *testing.T) {
	snapshot := model.SignedSnapshot{State: model.NetworkState{Users: []model.User{
		{ID: "user-1", PasswordVerifier: []byte("verifier")},
	}}}
	user := findDirectoryUser(snapshot, "user-1")
	if user == nil || !bytes.Equal(user.PasswordVerifier, []byte("verifier")) {
		t.Fatalf("user = %+v", user)
	}
	if findDirectoryUser(snapshot, "missing") != nil {
		t.Fatal("unknown directory user was returned")
	}
}
