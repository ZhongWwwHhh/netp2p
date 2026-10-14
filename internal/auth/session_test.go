package auth

import (
	"strings"
	"testing"
	"time"

	"github.com/netp2p/netp2p/internal/model"
)

func TestSessionManagerIssuesAndVerifies(t *testing.T) {
	manager, err := NewSessionManager("0123456789abcdef0123456789abcdef", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 10, 9, 12, 0, 0, 0, time.UTC)
	token, expires, err := manager.Issue(Identity{
		UserID: "user-1", Email: "user@example.com", Role: model.RoleOwner,
	}, now)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(token, LocalSessionPrefix) {
		t.Fatalf("token prefix = %q", token[:len(LocalSessionPrefix)])
	}
	sessionID, err := manager.SessionID(token)
	if err != nil {
		t.Fatal(err)
	}
	if len(sessionID) < 16 {
		t.Fatalf("session id = %q, want a random non-empty identifier", sessionID)
	}
	if _, err := manager.SessionID(token + "x"); err == nil {
		t.Fatal("tampered token should not expose a session id")
	}
	externalID := ExternalSessionID("external-token")
	if externalID == "" || externalID == ExternalSessionID("other-token") {
		t.Fatalf("external session id = %q, want a stable token-specific hash", externalID)
	}
	if !expires.Equal(now.Add(time.Hour)) {
		t.Fatalf("expires = %v, want %v", expires, now.Add(time.Hour))
	}
	identity, err := manager.Verify(token, now.Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if identity.UserID != "user-1" || identity.Role != model.RoleOwner {
		t.Fatalf("identity = %+v", identity)
	}
	if _, err := manager.Verify(token+"x", now.Add(time.Minute)); err == nil {
		t.Fatal("tampered token should fail")
	}
	if _, err := manager.Verify(token, now.Add(time.Hour+time.Second)); err == nil {
		t.Fatal("expired token should fail")
	}
}
