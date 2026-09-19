package web

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/netp2p/netp2p/internal/oidc"
	"github.com/netp2p/netp2p/internal/oidctest"
)

// TestOIDCProxyCompletesPKCEFlow walks the browser flow end to end: login
// redirect, authorization through the manager proxy, callback exchange and a
// token that the real verifier accepts.
func TestOIDCProxyCompletesPKCEFlow(t *testing.T) {
	provider, err := oidctest.New("127.0.0.1:0", oidctest.Options{
		AutoApprove: true,
		Default:     &oidctest.User{Subject: "browser-user", Email: "browser@example.com", Groups: []string{"eng"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer provider.Close()

	proxy := newOIDCProxy(&BootstrapOIDC{
		Issuer: provider.Issuer, ClientID: "netp2p-web",
		Scopes:                []string{"openid", "profile", "email"},
		AuthorizationEndpoint: provider.Issuer + "/authorize",
		TokenEndpoint:         provider.Issuer + "/token",
	})
	if proxy == nil {
		t.Fatal("proxy should be configured")
	}

	// Step 1: the SPA asks the manager to start the login.
	login := httptest.NewRequest(http.MethodGet, "http://manager.test/auth/login", nil)
	login.Host = "manager.test"
	recorder := httptest.NewRecorder()
	if !proxy.handle(recorder, login) {
		t.Fatal("login path not handled")
	}
	if recorder.Code != http.StatusFound {
		t.Fatalf("login status %d", recorder.Code)
	}
	authorizeLocation := recorder.Header().Get("Location")
	if !strings.HasPrefix(authorizeLocation, "/auth/idp/authorize") {
		t.Fatalf("authorize location = %q", authorizeLocation)
	}

	// Step 2: the browser hits the proxied authorization endpoint, which
	// bounces back to the manager callback with a code.
	authorizeURL, err := url.Parse(authorizeLocation)
	if err != nil {
		t.Fatal(err)
	}
	authorize := httptest.NewRequest(http.MethodGet, "http://manager.test"+authorizeURL.String(), nil)
	authorize.Host = "manager.test"
	recorder = httptest.NewRecorder()
	proxy.handle(recorder, authorize)
	if recorder.Code != http.StatusFound {
		t.Fatalf("authorize status %d body %q", recorder.Code, recorder.Body.String())
	}
	callbackLocation := recorder.Header().Get("Location")
	callbackURL, err := url.Parse(callbackLocation)
	if err != nil {
		t.Fatal(err)
	}
	if callbackURL.Path != "/auth/callback" || callbackURL.Query().Get("code") == "" {
		t.Fatalf("callback location = %q", callbackLocation)
	}

	// Step 3: the browser returns to the manager with the code.
	callback := httptest.NewRequest(http.MethodGet, callbackLocation, nil)
	callback.Host = "manager.test"
	recorder = httptest.NewRecorder()
	proxy.handle(recorder, callback)
	if recorder.Code != http.StatusFound {
		t.Fatalf("callback status %d body %q", recorder.Code, recorder.Body.String())
	}
	target, err := url.Parse(recorder.Header().Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	token := strings.TrimPrefix(target.Fragment, "id_token=")
	if token == "" {
		t.Fatalf("no id token in redirect %q", recorder.Header().Get("Location"))
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	verifier, err := oidc.NewVerifier(ctx, oidc.Config{Issuer: provider.Issuer, ClientID: "netp2p-web"})
	if err != nil {
		t.Fatal(err)
	}
	claims, err := verifier.Verify(ctx, token)
	if err != nil {
		t.Fatalf("verify exchanged token: %v", err)
	}
	if claims.Subject != "browser-user" {
		t.Fatalf("subject = %q", claims.Subject)
	}
}
