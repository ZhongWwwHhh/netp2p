package web

import (
	"context"
	"fmt"
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

	proxy, err := newOIDCProxy(&BootstrapOIDC{
		Issuer: provider.Issuer, ClientID: "netp2p-web",
		Scopes:                []string{"openid", "profile", "email"},
		AuthorizationEndpoint: provider.Issuer + "/authorize",
		TokenEndpoint:         provider.Issuer + "/token",
		RedirectURI:           "https://manager.test/auth/callback",
	})
	if err != nil {
		t.Fatal(err)
	}
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
	callback.AddCookie(&http.Cookie{
		Name: "netp2p_oidc_state", Value: callbackURL.Query().Get("state"),
	})
	recorder = httptest.NewRecorder()
	proxy.handle(recorder, callback)
	if recorder.Code != http.StatusFound {
		t.Fatalf("callback status %d body %q", recorder.Code, recorder.Body.String())
	}
	var token string
	for _, cookie := range recorder.Result().Cookies() {
		if cookie.Name == "netp2p_session" {
			token = cookie.Value
			break
		}
	}
	if token == "" {
		t.Fatal("no id token in session cookie")
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

func TestOIDCProxyRequiresExplicitExternalBase(t *testing.T) {
	proxy, err := newOIDCProxy(&BootstrapOIDC{
		Issuer: "https://issuer.example", ClientID: "netp2p-web",
		AuthorizationEndpoint: "https://issuer.example/authorize",
		TokenEndpoint:         "https://issuer.example/token",
	})
	if err == nil || proxy != nil {
		t.Fatalf("missing redirect URI created proxy = %+v err = %v", proxy, err)
	}
}

func TestOIDCProxyUsesConfiguredExternalBaseNotHostHeader(t *testing.T) {
	proxy, err := newOIDCProxy(&BootstrapOIDC{
		Issuer: "https://issuer.example", ClientID: "netp2p-web",
		AuthorizationEndpoint: "https://issuer.example/authorize",
		TokenEndpoint:         "https://issuer.example/token",
		RedirectURI:           "https://console.example/auth/callback",
	})
	if err != nil {
		t.Fatal(err)
	}
	login := httptest.NewRequest(http.MethodGet, "https://evil.example/auth/login", nil)
	login.Host = "evil.example"
	recorder := httptest.NewRecorder()
	if !proxy.handle(recorder, login) {
		t.Fatal("login path not handled")
	}
	location, err := url.Parse(recorder.Header().Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	if got := location.Query().Get("redirect_uri"); got != "https://console.example/auth/callback" {
		t.Fatalf("redirect_uri = %q, want configured external base", got)
	}
}

func TestOIDCProxyRejectsUnsafeRedirects(t *testing.T) {
	unsafe := []string{
		"//evil.example", "/\\evil.example", "https://evil.example",
		"http://evil.example", "javascript:alert(1)", "mailto:user@example.com",
	}
	for _, redirect := range unsafe {
		if got := safeRedirect(redirect); got != "/" {
			t.Fatalf("safeRedirect(%q) = %q, want /", redirect, got)
		}
	}
	if got := safeRedirect("/dashboard?next=%2Fpeers"); got != "/dashboard?next=%2Fpeers" {
		t.Fatalf("safeRedirect changed a same-origin path: %q", got)
	}
}

func TestOIDCProxyCapsPendingAuthRequests(t *testing.T) {
	proxy, err := newOIDCProxy(&BootstrapOIDC{
		Issuer: "https://issuer.example", ClientID: "netp2p-web",
		AuthorizationEndpoint: "https://issuer.example/authorize",
		TokenEndpoint:         "https://issuer.example/token",
		RedirectURI:           "https://console.example/auth/callback",
	})
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	for index := 0; index < maxPendingOIDCAuth; index++ {
		proxy.requests[fmt.Sprintf("pending-%d", index)] = pendingAuth{created: now}
	}
	recorder := httptest.NewRecorder()
	proxy.login(recorder, httptest.NewRequest(http.MethodGet, "https://console.example/auth/login", nil))
	if recorder.Code != http.StatusServiceUnavailable {
		t.Fatalf("login status = %d, want %d", recorder.Code, http.StatusServiceUnavailable)
	}
	if len(proxy.requests) != maxPendingOIDCAuth {
		t.Fatalf("pending auth count = %d, want capped count %d", len(proxy.requests), maxPendingOIDCAuth)
	}
}

func TestOIDCProxyUsesSecureStateCookieAndSessionCookie(t *testing.T) {
	provider, err := oidctest.New("127.0.0.1:0", oidctest.Options{
		AutoApprove: true,
		Default:     &oidctest.User{Subject: "browser-user"},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer provider.Close()

	proxy, err := newOIDCProxy(&BootstrapOIDC{
		Issuer: provider.Issuer, ClientID: "netp2p-web", Audience: "netp2p-web-audience",
		Scopes:                []string{"openid", "profile", "email"},
		AuthorizationEndpoint: provider.Issuer + "/authorize",
		TokenEndpoint:         provider.Issuer + "/token",
		RedirectURI:           "https://manager.test/auth/callback",
	})
	if err != nil {
		t.Fatal(err)
	}
	if proxy == nil {
		t.Fatal("proxy should be configured")
	}

	login := httptest.NewRequest(http.MethodGet, "http://manager.test/auth/login?redirect=/dashboard", nil)
	login.Host = "manager.test"
	recorder := httptest.NewRecorder()
	if !proxy.handle(recorder, login) {
		t.Fatal("login path not handled")
	}
	authorizeLocation := recorder.Header().Get("Location")
	authorizeURL, err := url.Parse(authorizeLocation)
	if err != nil {
		t.Fatal(err)
	}
	if authorizeURL.Query().Get("client_id") != "netp2p-web" {
		t.Fatalf("authorize client_id = %q", authorizeURL.Query().Get("client_id"))
	}
	if authorizeURL.Query().Get("audience") != "netp2p-web-audience" {
		t.Fatalf("authorize audience = %q", authorizeURL.Query().Get("audience"))
	}

	authorize := httptest.NewRequest(http.MethodGet, "http://manager.test"+authorizeLocation, nil)
	authorize.Host = "manager.test"
	recorder = httptest.NewRecorder()
	proxy.handle(recorder, authorize)
	callbackLocation := recorder.Header().Get("Location")
	callbackURL, err := url.Parse(callbackLocation)
	if err != nil {
		t.Fatal(err)
	}

	callback := httptest.NewRequest(http.MethodGet, callbackLocation, nil)
	callback.Host = "manager.test"
	callback.AddCookie(&http.Cookie{Name: "netp2p_oidc_state", Value: callbackURL.Query().Get("state")})
	recorder = httptest.NewRecorder()
	proxy.handle(recorder, callback)
	if recorder.Code != http.StatusFound {
		t.Fatalf("callback status = %d body %q", recorder.Code, recorder.Body.String())
	}
	if location := recorder.Header().Get("Location"); location != "/dashboard" || strings.Contains(location, "id_token") {
		t.Fatalf("callback location = %q", location)
	}

	var session *http.Cookie
	for _, cookie := range recorder.Result().Cookies() {
		if cookie.Name == "netp2p_session" {
			session = cookie
			break
		}
	}
	if session == nil || !session.HttpOnly || !session.Secure || session.Path != "/" || session.SameSite != http.SameSiteLaxMode {
		t.Fatalf("session cookie = %+v", session)
	}
	if session.Value == "" {
		t.Fatal("session cookie is empty")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	verifier, err := oidc.NewVerifier(ctx, oidc.Config{
		Issuer: provider.Issuer, ClientID: "netp2p", WebClientID: "netp2p-web",
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := verifier.Verify(ctx, session.Value); err != nil {
		t.Fatalf("web audience token should verify: %v", err)
	}
}
