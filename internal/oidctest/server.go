// Package oidctest provides an in-process OIDC provider for tests and for the
// Docker end-to-end stack. It implements just enough of discovery, JWKS, the
// device authorization grant and the token endpoint to exercise the real
// client and manager code paths.
package oidctest

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// User is an identity the mock IdP can mint tokens for.
type User struct {
	Subject string
	Email   string
	Name    string
	Groups  []string
	// ExtraClaims are merged into the ID token, letting tests exercise the
	// role claim and custom group claim names.
	ExtraClaims map[string]any
}

type Options struct {
	// Issuer overrides the advertised issuer URL. When empty it is derived
	// from the listen address.
	Issuer string
	// AutoApprove immediately authorizes every device flow request.
	AutoApprove bool
	// Default is the user issued to auto-approved device flows.
	Default *User
	// WebUser is the user issued to the browser authorization code flow. It
	// defaults to Default when unset.
	WebUser *User
	// GroupsClaim is the claim name carrying groups. Defaults to "groups".
	GroupsClaim string
}

// Server is a running mock provider.
type Server struct {
	Issuer string

	listener   net.Listener
	httpServer *http.Server
	key        *rsa.PrivateKey
	keyID      string
	options    Options

	mu        sync.Mutex
	pending   map[string]*deviceGrant
	byCode    map[string]*deviceGrant
	authCodes map[string]authGrant
	users     map[string]User
}

type deviceGrant struct {
	deviceCode string
	userCode   string
	clientID   string
	approved   bool
	user       User
}

type authGrant struct {
	clientID string
	user     User
}

// New starts a mock provider listening on listen (e.g. "127.0.0.1:0").
func New(listen string, options Options) (*Server, error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}
	listener, err := net.Listen("tcp", listen)
	if err != nil {
		return nil, err
	}
	issuer := options.Issuer
	if issuer == "" {
		issuer = "http://" + listener.Addr().String()
	}
	server := &Server{
		Issuer:    issuer,
		listener:  listener,
		key:       key,
		keyID:     keyID(key),
		options:   options,
		pending:   make(map[string]*deviceGrant),
		byCode:    make(map[string]*deviceGrant),
		authCodes: make(map[string]authGrant),
		users:     make(map[string]User),
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", server.handleDiscovery)
	mux.HandleFunc("/keys", server.handleJWKS)
	mux.HandleFunc("/authorize", server.handleAuthorize)
	mux.HandleFunc("/device_authorization", server.handleDeviceAuthorization)
	mux.HandleFunc("/token", server.handleToken)
	server.httpServer = &http.Server{Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	go func() { _ = server.httpServer.Serve(listener) }()
	return server, nil
}

// Close stops the provider.
func (server *Server) Close() error {
	if server.httpServer == nil {
		return nil
	}
	return server.httpServer.Close()
}

// AddUser registers an identity and returns the user code that selects it in a
// device flow. The primary device flow test path is SetDefaultUser.
func (server *Server) AddUser(user User) {
	server.mu.Lock()
	defer server.mu.Unlock()
	server.users[user.Subject] = user
}

// Approve authorizes a pending device flow identified by its user code.
func (server *Server) Approve(userCode string, user User) bool {
	server.mu.Lock()
	defer server.mu.Unlock()
	grant, ok := server.byCode[strings.ToUpper(userCode)]
	if !ok {
		return false
	}
	grant.approved = true
	grant.user = user
	return true
}

func (server *Server) handleDiscovery(writer http.ResponseWriter, request *http.Request) {
	writeJSON(writer, map[string]any{
		"issuer":                                server.Issuer,
		"authorization_endpoint":                server.Issuer + "/authorize",
		"token_endpoint":                        server.Issuer + "/token",
		"jwks_uri":                              server.Issuer + "/keys",
		"device_authorization_endpoint":         server.Issuer + "/device_authorization",
		"id_token_signing_alg_values_supported": []string{"RS256"},
		"response_types_supported":              []string{"code"},
		"subject_types_supported":               []string{"public"},
	})
}

func (server *Server) handleJWKS(writer http.ResponseWriter, request *http.Request) {
	publicKey := server.key.PublicKey
	writeJSON(writer, map[string]any{
		"keys": []map[string]any{{
			"kty": "RSA",
			"alg": "RS256",
			"use": "sig",
			"kid": server.keyID,
			"n":   base64.RawURLEncoding.EncodeToString(publicKey.N.Bytes()),
			"e":   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(publicKey.E)).Bytes()),
		}},
	})
}

func (server *Server) handleDeviceAuthorization(writer http.ResponseWriter, request *http.Request) {
	if err := request.ParseForm(); err != nil {
		http.Error(writer, "invalid form", http.StatusBadRequest)
		return
	}
	deviceCode := randomToken()
	userCode := randomUserCode()
	grant := &deviceGrant{deviceCode: deviceCode, userCode: userCode, clientID: request.Form.Get("client_id")}
	if server.options.AutoApprove && server.options.Default != nil {
		grant.approved = true
		grant.user = *server.options.Default
	}
	server.mu.Lock()
	server.pending[deviceCode] = grant
	server.byCode[userCode] = grant
	server.mu.Unlock()
	writeJSON(writer, map[string]any{
		"device_code":               deviceCode,
		"user_code":                 userCode,
		"verification_uri":          server.Issuer + "/device",
		"verification_uri_complete": server.Issuer + "/device?user_code=" + userCode,
		"expires_in":                600,
		"interval":                  1,
	})
}

// handleAuthorize implements the authorization code flow without any consent
// UI: it immediately redirects back with a code, which is what makes the
// manager's PKCE proxy testable end to end.
func (server *Server) handleAuthorize(writer http.ResponseWriter, request *http.Request) {
	query := request.URL.Query()
	redirectURI := query.Get("redirect_uri")
	if redirectURI == "" {
		http.Error(writer, "redirect_uri is required", http.StatusBadRequest)
		return
	}
	user := User{Subject: "unknown"}
	switch {
	case server.options.WebUser != nil:
		user = *server.options.WebUser
	case server.options.Default != nil:
		user = *server.options.Default
	}
	code := randomToken()
	server.mu.Lock()
	server.authCodes[code] = authGrant{clientID: query.Get("client_id"), user: user}
	server.mu.Unlock()
	target, err := url.Parse(redirectURI)
	if err != nil {
		http.Error(writer, "invalid redirect_uri", http.StatusBadRequest)
		return
	}
	params := target.Query()
	params.Set("code", code)
	params.Set("state", query.Get("state"))
	target.RawQuery = params.Encode()
	http.Redirect(writer, request, target.String(), http.StatusFound)
}

func (server *Server) handleToken(writer http.ResponseWriter, request *http.Request) {
	if err := request.ParseForm(); err != nil {
		http.Error(writer, "invalid form", http.StatusBadRequest)
		return
	}
	if request.Form.Get("grant_type") == "authorization_code" {
		server.handleAuthorizationCode(writer, request.Form.Get("code"), request.Form.Get("client_id"))
		return
	}
	deviceCode := request.Form.Get("device_code")
	server.mu.Lock()
	grant := server.pending[deviceCode]
	server.mu.Unlock()
	if grant == nil {
		writeJSONStatus(writer, http.StatusBadRequest, map[string]string{"error": "invalid_grant"})
		return
	}
	if !grant.approved {
		writeJSONStatus(writer, http.StatusBadRequest, map[string]string{"error": "authorization_pending"})
		return
	}
	token, err := server.mintIDToken(grant)
	if err != nil {
		writeJSONStatus(writer, http.StatusInternalServerError, map[string]string{"error": "server_error"})
		return
	}
	writeJSON(writer, map[string]any{
		"access_token": token,
		"token_type":   "Bearer",
		"id_token":     token,
		"expires_in":   3600,
	})
}

func (server *Server) handleAuthorizationCode(writer http.ResponseWriter, code, clientID string) {
	server.mu.Lock()
	grant, ok := server.authCodes[code]
	delete(server.authCodes, code)
	server.mu.Unlock()
	if !ok {
		writeJSONStatus(writer, http.StatusBadRequest, map[string]string{"error": "invalid_grant"})
		return
	}
	if grant.clientID != "" && clientID != "" && grant.clientID != clientID {
		writeJSONStatus(writer, http.StatusBadRequest, map[string]string{"error": "invalid_client"})
		return
	}
	token, err := server.mintIDToken(&deviceGrant{clientID: grant.clientID, user: grant.user})
	if err != nil {
		writeJSONStatus(writer, http.StatusInternalServerError, map[string]string{"error": "server_error"})
		return
	}
	writeJSON(writer, map[string]any{
		"access_token": token, "token_type": "Bearer", "id_token": token, "expires_in": 3600,
	})
}

func (server *Server) mintIDToken(grant *deviceGrant) (string, error) {
	audience := grant.clientID
	if audience == "" {
		audience = "netp2p"
	}
	now := time.Now()
	claims := map[string]any{
		"iss": server.Issuer,
		"sub": grant.user.Subject,
		"aud": audience,
		"iat": now.Unix(),
		"exp": now.Add(time.Hour).Unix(),
	}
	if grant.user.Email != "" {
		claims["email"] = grant.user.Email
	}
	if grant.user.Name != "" {
		claims["name"] = grant.user.Name
	}
	claimName := server.options.GroupsClaim
	if claimName == "" {
		claimName = "groups"
	}
	if len(grant.user.Groups) > 0 {
		claims[claimName] = grant.user.Groups
	}
	for key, value := range grant.user.ExtraClaims {
		claims[key] = value
	}
	return signRS256(server.key, server.keyID, claims)
}

func signRS256(key *rsa.PrivateKey, keyID string, claims map[string]any) (string, error) {
	header, err := json.Marshal(map[string]string{"alg": "RS256", "typ": "JWT", "kid": keyID})
	if err != nil {
		return "", err
	}
	payload, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}
	signingInput := base64.RawURLEncoding.EncodeToString(header) + "." + base64.RawURLEncoding.EncodeToString(payload)
	digest := sha256.Sum256([]byte(signingInput))
	signature, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, digest[:])
	if err != nil {
		return "", err
	}
	return signingInput + "." + base64.RawURLEncoding.EncodeToString(signature), nil
}

func keyID(key *rsa.PrivateKey) string {
	der, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		return "mock-key"
	}
	digest := sha256.Sum256(der)
	return base64.RawURLEncoding.EncodeToString(digest[:8])
}

func randomToken() string {
	buffer := make([]byte, 16)
	_, _ = rand.Read(buffer)
	return base64.RawURLEncoding.EncodeToString(buffer)
}

func randomUserCode() string {
	const alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ"
	buffer := make([]byte, 8)
	_, _ = rand.Read(buffer)
	var builder strings.Builder
	for index, value := range buffer {
		if index == 4 {
			builder.WriteByte('-')
		}
		builder.WriteByte(alphabet[int(value)%len(alphabet)])
	}
	return builder.String()
}

func writeJSON(writer http.ResponseWriter, value any) {
	writeJSONStatus(writer, http.StatusOK, value)
}

func writeJSONStatus(writer http.ResponseWriter, status int, value any) {
	writer.Header().Set("Content-Type", "application/json")
	writer.WriteHeader(status)
	_ = json.NewEncoder(writer).Encode(value)
}
