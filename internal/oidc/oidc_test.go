package oidc

import (
	"context"
	"testing"
	"time"

	"github.com/netp2p/netp2p/internal/model"
	"github.com/netp2p/netp2p/internal/oidctest"
)

func TestToGroupsAcceptsStringAndArrays(t *testing.T) {
	if got := ToGroups("eng"); len(got) != 1 || got[0] != "eng" {
		t.Fatalf("string claim = %v", got)
	}
	if got := ToGroups([]any{"eng", 42, "ops"}); len(got) != 2 || got[1] != "ops" {
		t.Fatalf("array claim = %v", got)
	}
	if got := ToGroups(42); got != nil {
		t.Fatalf("unexpected groups %v", got)
	}
}

func TestConfigRoleResolution(t *testing.T) {
	config := Config{AdminGroups: []string{"netp2p-admins"}}
	if role, ok := config.ConfigRole(Claims{Groups: []string{"netp2p-admins"}}); !ok || role != model.RoleAdmin {
		t.Fatalf("admin group should resolve to admin, got %q %v", role, ok)
	}
	if _, ok := config.ConfigRole(Claims{Groups: []string{"eng"}}); ok {
		t.Fatal("unrelated group must not resolve a role")
	}
	withRole := Config{RoleClaim: "role"}
	if role, ok := withRole.ConfigRole(Claims{Role: model.RoleAuditor}); !ok || role != model.RoleAuditor {
		t.Fatalf("role claim should win, got %q %v", role, ok)
	}
	if _, ok := withRole.ConfigRole(Claims{Role: "wizard"}); ok {
		t.Fatal("unknown role must be ignored")
	}
}

func TestAllowedRespectsAllowList(t *testing.T) {
	config := Config{AllowGroups: []string{"eng"}}
	if !config.Allowed(Claims{Groups: []string{"eng", "ops"}}) {
		t.Fatal("allowed group should pass")
	}
	if config.Allowed(Claims{Groups: []string{"ops"}}) {
		t.Fatal("group outside the allow list must be rejected")
	}
	if !(Config{}).Allowed(Claims{}) {
		t.Fatal("empty allow list admits everyone")
	}
}

func TestDeviceFlowAndVerificationEndToEnd(t *testing.T) {
	provider, err := oidctest.New("127.0.0.1:0", oidctest.Options{
		AutoApprove: true,
		Default: &oidctest.User{
			Subject: "user-1", Email: "user@example.com", Name: "User One",
			Groups: []string{"eng", "netp2p-admins"},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer provider.Close()

	config := Config{Issuer: provider.Issuer, ClientID: "netp2p", AdminGroups: []string{"netp2p-admins"}}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	flow, err := NewDeviceFlow(ctx, config)
	if err != nil {
		t.Fatalf("device flow: %v", err)
	}
	flow.Prompt = func(string, string) {}
	token, err := flow.IDToken(ctx)
	if err != nil {
		t.Fatalf("id token: %v", err)
	}

	verifier, err := NewVerifier(ctx, config)
	if err != nil {
		t.Fatalf("verifier: %v", err)
	}
	claims, err := verifier.Verify(ctx, token)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if claims.Subject != "user-1" || claims.Email != "user@example.com" {
		t.Fatalf("claims = %+v", claims)
	}
	if len(claims.Groups) != 2 || claims.Groups[1] != "netp2p-admins" {
		t.Fatalf("groups = %v", claims.Groups)
	}
	if role, ok := config.ConfigRole(claims); !ok || role != model.RoleAdmin {
		t.Fatalf("role = %q %v", role, ok)
	}
}

func TestVerifierRejectsForgedToken(t *testing.T) {
	provider, err := oidctest.New("127.0.0.1:0", oidctest.Options{
		AutoApprove: true,
		Default:     &oidctest.User{Subject: "user-1"},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer provider.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	verifier, err := NewVerifier(ctx, Config{Issuer: provider.Issuer, ClientID: "netp2p"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := verifier.Verify(ctx, "not.a.token"); err == nil {
		t.Fatal("forged token must not verify")
	}
}
