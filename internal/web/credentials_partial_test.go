package web

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/netp2p/netp2p/internal/auth"
	"github.com/netp2p/netp2p/internal/model"
)

func TestEmailOnlyCredentialUpdatePreservesVerifier(t *testing.T) {
	server, accounts, _ := newLocalAuthTestServer(t)
	originalVerifier := model.HashPassword("original password")
	accounts.users = []model.User{{
		ID: "user-1", Email: "old@example.com", Role: model.RoleUser,
		PasswordVerifier: originalVerifier,
	}}
	token, _, err := server.sessions.Issue(auth.Identity{UserID: "user-1", Role: model.RoleUser}, time.Now().Add(-time.Second))
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodPost, "/api/v1/users/user-1/credentials",
		bytes.NewBufferString(`{"email":"new@example.com"}`))
	request.Header.Set("Authorization", "Bearer "+token)
	recorder := httptest.NewRecorder()
	server.handleAPI(recorder, request)
	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d body %q", recorder.Code, recorder.Body.String())
	}
	var response model.User
	if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	if response.Email != "new@example.com" {
		t.Fatalf("email = %q, want new@example.com", response.Email)
	}
	if !bytes.Equal(accounts.users[0].PasswordVerifier, originalVerifier) {
		t.Fatal("email-only update changed the password verifier")
	}
	if accounts.users[0].CredentialsChangedAt == "" {
		t.Fatal("email-only update did not refresh credential change time")
	}
	authenticated := httptest.NewRequest(http.MethodGet, "/api/v1/session", nil)
	authenticated.Header.Set("Authorization", "Bearer "+token)
	if _, ok := server.authenticate(authenticated); ok {
		t.Fatal("email-only update did not revoke the old session")
	}
}

func TestPasswordOnlyCredentialUpdatePreservesEmail(t *testing.T) {
	server, accounts, _ := newLocalAuthTestServer(t)
	accounts.users = []model.User{{
		ID: "user-1", Email: "user@example.com", Role: model.RoleUser,
		PasswordVerifier: model.HashPassword("original password"),
	}}
	token, _, err := server.sessions.Issue(auth.Identity{UserID: "user-1", Role: model.RoleUser}, time.Now().Add(-time.Second))
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodPost, "/api/v1/users/user-1/credentials",
		bytes.NewBufferString(`{"password":"correct horse battery"}`))
	request.Header.Set("Authorization", "Bearer "+token)
	recorder := httptest.NewRecorder()
	server.handleAPI(recorder, request)
	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d body %q", recorder.Code, recorder.Body.String())
	}
	if accounts.users[0].Email != "user@example.com" {
		t.Fatalf("email = %q, want user@example.com", accounts.users[0].Email)
	}
	if !model.VerifyPassword("correct horse battery", accounts.users[0].PasswordVerifier) {
		t.Fatal("password verifier was not replaced")
	}
	if accounts.users[0].CredentialsChangedAt == "" {
		t.Fatal("password-only update did not record session invalidation time")
	}
	authenticated := httptest.NewRequest(http.MethodGet, "/api/v1/session", nil)
	authenticated.Header.Set("Authorization", "Bearer "+token)
	if _, ok := server.authenticate(authenticated); ok {
		t.Fatal("password-only update did not revoke the old session")
	}
}
