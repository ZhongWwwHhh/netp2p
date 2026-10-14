package web

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"path"
	"strings"
	"sync"
	"time"
)

const (
	maxPendingOIDCAuth = 1024
	oidcPendingTTL     = 10 * time.Minute
)

// oidcProxy runs the browser PKCE authorization code flow through the manager's
// bootstrap listener.
//
// The browser only ever talks to the manager: authorization and token requests
// are proxied to the issuer. That keeps a lab IdP whose hostname is only
// resolvable inside the container network reachable from a laptop browser,
// without exposing the issuer's origin or its CORS policy to the console.
type oidcProxy struct {
	issuer       string
	clientID     string
	audience     string
	scopes       []string
	authURL      string
	tokenURL     string
	externalBase string

	mu       sync.Mutex
	requests map[string]pendingAuth
	// recordSession persists a server-side identifier for the exchanged OIDC
	// token before the browser receives the session cookie.
	recordSession func(ctx context.Context, token string, expires time.Time) error
}

type pendingAuth struct {
	verifier  string
	redirect  string
	stateHash []byte
	created   time.Time
}

func newOIDCProxy(config *BootstrapOIDC) (*oidcProxy, error) {
	if config == nil || config.Issuer == "" || config.AuthorizationEndpoint == "" || config.TokenEndpoint == "" {
		return nil, nil
	}
	redirect, err := url.Parse(config.RedirectURI)
	if err != nil || !redirect.IsAbs() || redirect.Host == "" ||
		redirect.Path != "/auth/callback" || redirect.RawQuery != "" || redirect.Fragment != "" ||
		(redirect.Scheme != "http" && redirect.Scheme != "https") {
		return nil, fmt.Errorf("oidc redirect URI must be an explicit absolute https/http URL ending in /auth/callback")
	}
	return &oidcProxy{
		issuer:       config.Issuer,
		clientID:     config.ClientID,
		audience:     strings.TrimSpace(config.Audience),
		scopes:       config.Scopes,
		authURL:      config.AuthorizationEndpoint,
		tokenURL:     config.TokenEndpoint,
		requests:     make(map[string]pendingAuth),
		externalBase: redirect.Scheme + "://" + redirect.Host,
	}, nil
}

// handle routes the three bootstrap auth endpoints. It returns false when the
// path is not part of the SSO flow.
func (proxy *oidcProxy) handle(writer http.ResponseWriter, request *http.Request) bool {
	switch {
	case request.URL.Path == "/auth/login":
		proxy.login(writer, request)
		return true
	case request.URL.Path == "/auth/callback":
		proxy.callback(writer, request)
		return true
	case strings.HasPrefix(request.URL.Path, "/auth/idp/"):
		proxy.forward(writer, request)
		return true
	}
	return false
}

func (proxy *oidcProxy) login(writer http.ResponseWriter, request *http.Request) {
	verifier, challenge, err := pkcePair()
	if err != nil {
		http.Error(writer, "cannot start login", http.StatusInternalServerError)
		return
	}
	state, err := randomState()
	if err != nil {
		http.Error(writer, "cannot start login", http.StatusInternalServerError)
		return
	}
	redirect := request.URL.Query().Get("redirect")
	redirect = safeRedirect(redirect)
	stateDigest := sha256.Sum256([]byte(state))
	proxy.mu.Lock()
	proxy.pruneLocked()
	if len(proxy.requests) >= maxPendingOIDCAuth {
		proxy.mu.Unlock()
		http.Error(writer, "too many pending logins", http.StatusServiceUnavailable)
		return
	}
	proxy.requests[state] = pendingAuth{
		verifier: verifier, redirect: redirect, stateHash: stateDigest[:], created: time.Now(),
	}
	proxy.mu.Unlock()
	http.SetCookie(writer, &http.Cookie{
		Name: "netp2p_oidc_state", Value: state, Path: "/auth/callback",
		MaxAge: int(oidcPendingTTL.Seconds()), HttpOnly: true, Secure: true, SameSite: http.SameSiteLaxMode,
	})

	authorize, err := url.Parse(proxy.authURL)
	if err != nil {
		http.Error(writer, "invalid issuer configuration", http.StatusInternalServerError)
		return
	}
	// Send the browser through the manager so the issuer never needs to be
	// reachable from the browser directly.
	authorize.Scheme = ""
	authorize.Host = ""
	authorize.Path = "/auth/idp" + authorize.Path
	query := authorize.Query()
	query.Set("client_id", proxy.clientID)
	query.Set("response_type", "code")
	query.Set("scope", strings.Join(proxy.scopes, " "))
	query.Set("redirect_uri", proxy.callbackURL(request))
	query.Set("state", state)
	query.Set("code_challenge", challenge)
	query.Set("code_challenge_method", "S256")
	if proxy.audience != "" {
		query.Set("audience", proxy.audience)
	}
	authorize.RawQuery = query.Encode()
	http.Redirect(writer, request, authorize.String(), http.StatusFound)
}

func (proxy *oidcProxy) callback(writer http.ResponseWriter, request *http.Request) {
	state := request.URL.Query().Get("state")
	code := request.URL.Query().Get("code")
	stateCookie, cookieErr := request.Cookie("netp2p_oidc_state")
	if code == "" || cookieErr != nil || stateCookie.Value == "" ||
		subtle.ConstantTimeCompare([]byte(stateCookie.Value), []byte(state)) != 1 {
		http.Error(writer, "missing authorization code", http.StatusBadRequest)
		return
	}
	proxy.mu.Lock()
	pending, ok := proxy.requests[state]
	delete(proxy.requests, state)
	proxy.mu.Unlock()
	if !ok {
		http.Error(writer, "unknown or expired login attempt", http.StatusBadRequest)
		return
	}
	stateDigest := sha256.Sum256([]byte(state))
	if subtle.ConstantTimeCompare(pending.stateHash, stateDigest[:]) != 1 {
		http.Error(writer, "invalid login state", http.StatusBadRequest)
		return
	}
	idToken, err := proxy.exchange(request, code, pending.verifier)
	if err != nil {
		http.Error(writer, fmt.Sprintf("token exchange failed: %v", err), http.StatusBadGateway)
		return
	}
	expires := time.Now().Add(time.Hour)
	if proxy.recordSession != nil {
		if err := proxy.recordSession(request.Context(), idToken, expires); err != nil {
			http.Error(writer, "cannot persist login session", http.StatusInternalServerError)
			return
		}
	}
	// Keep the browser session in an HttpOnly cookie. The ID token never
	// appears in a URL, referrer, browser history, or manager access log.
	http.SetCookie(writer, &http.Cookie{
		Name: "netp2p_session", Value: idToken, Path: "/",
		MaxAge: int(time.Until(expires).Seconds()), HttpOnly: true, Secure: true, SameSite: http.SameSiteLaxMode,
	})
	http.SetCookie(writer, &http.Cookie{
		Name: "netp2p_oidc_state", Value: "", Path: "/auth/callback",
		MaxAge: -1, HttpOnly: true, Secure: true, SameSite: http.SameSiteLaxMode,
	})
	http.Redirect(writer, request, safeRedirect(pending.redirect), http.StatusFound)
}

func (proxy *oidcProxy) exchange(request *http.Request, code, verifier string) (string, error) {
	form := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"redirect_uri":  {proxy.callbackURL(request)},
		"client_id":     {proxy.clientID},
		"code_verifier": {verifier},
	}
	response, err := http.PostForm(proxy.tokenURL, form)
	if err != nil {
		return "", err
	}
	defer response.Body.Close()
	body, err := io.ReadAll(io.LimitReader(response.Body, 1<<20))
	if err != nil {
		return "", err
	}
	var payload struct {
		IDToken string `json:"id_token"`
		Error   string `json:"error"`
	}
	if err := json.Unmarshal(body, &payload); err != nil {
		return "", fmt.Errorf("decode token response: %w", err)
	}
	if response.StatusCode != http.StatusOK || payload.IDToken == "" {
		return "", fmt.Errorf("issuer returned %d: %s", response.StatusCode, payload.Error)
	}
	return payload.IDToken, nil
}

// forward proxies authorization requests to the issuer so the browser can
// complete them through the manager.
func (proxy *oidcProxy) forward(writer http.ResponseWriter, request *http.Request) {
	target, err := url.Parse(proxy.issuer)
	if err != nil {
		http.Error(writer, "invalid issuer", http.StatusInternalServerError)
		return
	}
	target.Path = strings.TrimPrefix(request.URL.Path, "/auth/idp")
	target.RawQuery = request.URL.RawQuery
	if target.Path == "" {
		target.Path = "/"
	}
	forwarded, err := http.NewRequestWithContext(request.Context(), request.Method, target.String(), nil)
	if err != nil {
		http.Error(writer, "proxy request failed", http.StatusBadGateway)
		return
	}
	client := &http.Client{
		Timeout: 30 * time.Second,
		// The issuer redirects back to the manager; never follow it here.
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	response, err := client.Do(forwarded)
	if err != nil {
		http.Error(writer, "issuer unreachable", http.StatusBadGateway)
		return
	}
	defer response.Body.Close()
	for name, values := range response.Header {
		for _, value := range values {
			writer.Header().Add(name, value)
		}
	}
	writer.WriteHeader(response.StatusCode)
	_, _ = io.Copy(writer, io.LimitReader(response.Body, 1<<20))
}

func (proxy *oidcProxy) callbackURL(request *http.Request) string {
	if proxy.externalBase != "" {
		return strings.TrimSuffix(proxy.externalBase, "/") + "/auth/callback"
	}
	scheme := "http"
	if request.TLS != nil {
		scheme = "https"
	}
	return scheme + "://" + request.Host + "/auth/callback"
}

func safeRedirect(raw string) string {
	if raw == "" || strings.ContainsAny(raw, "\r\n\\") {
		return "/"
	}
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Scheme != "" || parsed.Host != "" ||
		parsed.User != nil || parsed.Opaque != "" {
		return "/"
	}
	if !strings.HasPrefix(parsed.Path, "/") || strings.HasPrefix(parsed.Path, "//") {
		return "/"
	}
	parsed.Path = path.Clean(parsed.Path)
	if parsed.Path == "." || parsed.Path == "" {
		parsed.Path = "/"
	}
	parsed.Fragment = ""
	parsed.RawFragment = ""
	return parsed.String()
}

func (proxy *oidcProxy) pruneLocked() {
	cutoff := time.Now().Add(-oidcPendingTTL)
	for state, pending := range proxy.requests {
		if pending.created.Before(cutoff) {
			delete(proxy.requests, state)
		}
	}
}

func pkcePair() (verifier, challenge string, err error) {
	buffer := make([]byte, 32)
	if _, err := rand.Read(buffer); err != nil {
		return "", "", err
	}
	verifier = base64.RawURLEncoding.EncodeToString(buffer)
	digest := sha256.Sum256([]byte(verifier))
	return verifier, base64.RawURLEncoding.EncodeToString(digest[:]), nil
}

func randomState() (string, error) {
	buffer := make([]byte, 32)
	if _, err := rand.Read(buffer); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(buffer), nil
}
