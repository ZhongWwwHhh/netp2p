package web

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/netp2p/netp2p/internal/auth"
	"github.com/netp2p/netp2p/internal/model"
	"github.com/netp2p/netp2p/internal/store"
)

func newTestServer() *Server {
	sessions, err := auth.NewSessionManager("0123456789abcdef0123456789abcdef", time.Hour)
	if err != nil {
		panic(err)
	}
	return &Server{
		bootstrap:             []byte(`{"networkId":"net-test","version":"0.1.0","protocolVersion":"3.0.0"}`),
		config:                Config{AdminToken: "secret"},
		sessions:              sessions,
		dummyPasswordVerifier: model.HashPassword("dummy-verifier"),
	}
}

type fakeAccountDirectory struct {
	users     []model.User
	groups    []model.Group
	setupKeys []model.SetupKey
}

func (fake *fakeAccountDirectory) Users() []model.User { return fake.users }

func (fake *fakeAccountDirectory) Snapshot() model.SignedSnapshot {
	return model.SignedSnapshot{State: model.NetworkState{
		Users: fake.users, Groups: fake.groups, SetupKeys: fake.setupKeys,
	}}
}

func (fake *fakeAccountDirectory) SubmitAs(
	transition model.StateTransition, _ model.Actor,
) (model.SignedSnapshot, error) {
	if transition.Group != nil {
		fake.groups = append(fake.groups, *transition.Group)
	}
	if transition.User != nil {
		fake.users = append(fake.users, *transition.User)
	}
	if transition.Type == "update_user_credentials" {
		targetID := transition.TargetID
		if targetID == "" && transition.User != nil {
			targetID = transition.User.ID
		}
		for index := range fake.users {
			if fake.users[index].ID != targetID {
				continue
			}
			if transition.User.Email != "" {
				fake.users[index].Email = transition.User.Email
			}
			if transition.User.PasswordVerifier != nil {
				fake.users[index].PasswordVerifier = transition.User.PasswordVerifier
			}
			if transition.User.Email != "" || transition.User.PasswordVerifier != nil {
				fake.users[index].CredentialsChangedAt = time.Now().UTC().Format(time.RFC3339Nano)
			}
		}
	}
	if transition.Record != nil {
		record := *transition.Record
		record.Token = ""
		fake.setupKeys = append(fake.setupKeys, record)
	}
	return fake.Snapshot(), nil
}

func newLocalAuthTestServer(t *testing.T) (*Server, *fakeAccountDirectory, *store.Store) {
	t.Helper()
	authStore, err := store.Open(filepath.Join(t.TempDir(), "auth.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = authStore.Close() })
	sessions, err := auth.NewSessionManager("0123456789abcdef0123456789abcdef", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	accounts := &fakeAccountDirectory{}
	return &Server{
		bootstrap: []byte(`{"networkId":"net-test","version":"0.1.0","protocolVersion":"3.0.0"}`),
		config:    Config{AdminToken: "secret"},
		accounts:  accounts, authStore: authStore, sessions: sessions,
		dummyPasswordVerifier: model.HashPassword("dummy-verifier"),
	}, accounts, authStore
}

func TestBootstrapHandlerServesBootstrapJSON(t *testing.T) {
	server := newTestServer()
	recorder := httptest.NewRecorder()
	server.BootstrapHandler().ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/api/bootstrap", nil))
	if recorder.Code != http.StatusOK {
		t.Fatalf("status %d, want 200", recorder.Code)
	}
	if !strings.Contains(recorder.Body.String(), `"networkId":"net-test"`) {
		t.Fatalf("body %q missing network id", recorder.Body.String())
	}
	if !strings.Contains(recorder.Body.String(), `"protocolVersion":"`) {
		t.Fatalf("body %q missing protocol version", recorder.Body.String())
	}
}

func TestBootstrapHandlerDeepLinkReturnsSPA(t *testing.T) {
	server := newTestServer()
	for _, path := range []string{"/peers", "/policies", "/dns/nameservers"} {
		recorder := httptest.NewRecorder()
		server.BootstrapHandler().ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, path, nil))
		if recorder.Code != http.StatusOK {
			t.Fatalf("GET %s status %d, want 200", path, recorder.Code)
		}
		if !strings.Contains(recorder.Body.String(), "<div id=\"app\"") && !strings.Contains(recorder.Body.String(), "<script") {
			t.Fatalf("GET %s did not return the SPA shell: %q", path, recorder.Body.String())
		}
	}
}

func TestBootstrapHandlerRejectsUnknownAPI(t *testing.T) {
	server := newTestServer()
	for _, request := range []struct {
		method string
		path   string
	}{
		{http.MethodGet, "/api/v1/snapshot"},
		{http.MethodPost, "/api/v1/transitions"},
		{http.MethodGet, "/api/unknown"},
	} {
		recorder := httptest.NewRecorder()
		server.BootstrapHandler().ServeHTTP(recorder, httptest.NewRequest(request.method, request.path, nil))
		if recorder.Code != http.StatusNotFound {
			t.Fatalf("%s %s status %d, want 404", request.method, request.path, recorder.Code)
		}
	}
}

func TestBootstrapHandlerHealthz(t *testing.T) {
	server := newTestServer()
	recorder := httptest.NewRecorder()
	server.BootstrapHandler().ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/healthz", nil))
	if recorder.Code != http.StatusOK || !strings.Contains(recorder.Body.String(), "ok") {
		t.Fatalf("healthz status %d body %q", recorder.Code, recorder.Body.String())
	}
}

func TestBootstrapHandlerReadyzWithoutManager(t *testing.T) {
	server := newTestServer()
	recorder := httptest.NewRecorder()
	server.BootstrapHandler().ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/readyz", nil))
	if recorder.Code != http.StatusServiceUnavailable {
		t.Fatalf("readyz status = %d body %q, want 503", recorder.Code, recorder.Body.String())
	}
	if !strings.Contains(recorder.Body.String(), "manager is unavailable") {
		t.Fatalf("readyz body %q missing reason", recorder.Body.String())
	}
}

func TestBootstrapHandlerReadyzReady(t *testing.T) {
	server := newTestServer()
	server.readinessFunc = func() ReadinessStatus {
		return ReadinessStatus{
			Status:          "ready",
			Height:          14,
			CommitteeOnline: 3,
			CommitteeSize:   3,
			QuorumSize:      3,
			LedgerReady:     true,
		}
	}
	recorder := httptest.NewRecorder()
	server.BootstrapHandler().ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/readyz", nil))
	if recorder.Code != http.StatusOK {
		t.Fatalf("readyz status %d body %q", recorder.Code, recorder.Body.String())
	}
	var status ReadinessStatus
	if err := json.Unmarshal(recorder.Body.Bytes(), &status); err != nil {
		t.Fatal(err)
	}
	if status.Height != 14 || status.CommitteeOnline != 3 ||
		!status.LedgerReady || status.Degraded || status.Status != "ready" {
		t.Fatalf("readiness = %+v", status)
	}
	if status.Reasons == nil {
		t.Fatal("readiness reasons must serialize as an empty JSON array")
	}
	if cache := recorder.Header().Get("Cache-Control"); cache != "no-store" {
		t.Fatalf("Cache-Control = %q, want no-store", cache)
	}
}

func TestBootstrapHandlerReadyzDegraded(t *testing.T) {
	server := newTestServer()
	server.readinessFunc = func() ReadinessStatus {
		return ReadinessStatus{
			Status:          "degraded",
			Height:          14,
			CommitteeOnline: 2,
			CommitteeSize:   3,
			QuorumSize:      3,
			LedgerReady:     true,
			Degraded:        true,
			Reasons:         []string{"committee quorum is unavailable"},
		}
	}
	recorder := httptest.NewRecorder()
	server.BootstrapHandler().ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/readyz", nil))
	if recorder.Code != http.StatusServiceUnavailable {
		t.Fatalf("readyz status %d body %q", recorder.Code, recorder.Body.String())
	}
	var status ReadinessStatus
	if err := json.Unmarshal(recorder.Body.Bytes(), &status); err != nil {
		t.Fatal(err)
	}
	if status.CommitteeOnline != 2 || !status.Degraded || len(status.Reasons) != 1 {
		t.Fatalf("readiness = %+v", status)
	}

	healthRecorder := httptest.NewRecorder()
	server.BootstrapHandler().ServeHTTP(healthRecorder, httptest.NewRequest(http.MethodGet, "/healthz", nil))
	if healthRecorder.Code != http.StatusOK {
		t.Fatalf("healthz followed readiness state: status %d body %q",
			healthRecorder.Code, healthRecorder.Body.String())
	}
}

func TestBootstrapHandlerReadyzRequiresGET(t *testing.T) {
	server := newTestServer()
	recorder := httptest.NewRecorder()
	server.BootstrapHandler().ServeHTTP(recorder, httptest.NewRequest(http.MethodPost, "/readyz", nil))
	if recorder.Code != http.StatusMethodNotAllowed {
		t.Fatalf("readyz status %d body %q", recorder.Code, recorder.Body.String())
	}
}

func TestSetupKeyCreationReturnsTokenOnce(t *testing.T) {
	server, accounts, _ := newLocalAuthTestServer(t)
	accounts.groups = append(accounts.groups, model.Group{ID: "clients"})
	request := httptest.NewRequest(http.MethodPost, "/api/v1/setup-keys", strings.NewReader(`{
		"name":"workstations","type":"one-off","groups":["clients"],"expiresAt":"7d"
	}`))
	request.Header.Set("Authorization", "Bearer secret")
	recorder := httptest.NewRecorder()
	server.handleAPI(recorder, request)

	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d body %q, want 200", recorder.Code, recorder.Body.String())
	}
	var response struct {
		Token    string               `json:"token"`
		Snapshot model.SignedSnapshot `json:"snapshot"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(response.Token, "netp2p-sk-") || len(response.Token) < 40 {
		t.Fatalf("token = %q, want a long netp2p-sk token", response.Token)
	}
	if len(accounts.setupKeys) != 1 {
		t.Fatalf("certified setup keys = %d, want 1", len(accounts.setupKeys))
	}
	stored := accounts.setupKeys[0]
	if stored.Token != "" || len(stored.TokenHash) == 0 ||
		!bytes.Equal(stored.TokenHash, model.SetupKeyHash(response.Token)) {
		t.Fatalf("stored key = %+v, want verifier only", stored)
	}
	expiresAt, err := time.Parse(time.RFC3339, stored.ExpiresAt)
	if err != nil {
		t.Fatalf("parse setup key expiry: %v", err)
	}
	untilExpiry := expiresAt.Sub(time.Now())
	if stored.UsageLimit != 1 || untilExpiry < 6*24*time.Hour || untilExpiry > 8*24*time.Hour {
		t.Fatalf("stored key limits/expiry = %d/%q", stored.UsageLimit, stored.ExpiresAt)
	}
	if len(response.Snapshot.State.SetupKeys) != 1 || response.Snapshot.State.SetupKeys[0].TokenHash != nil {
		t.Fatalf("client snapshot setup keys = %+v, want redacted key", response.Snapshot.State.SetupKeys)
	}
}

func TestAuthenticate(t *testing.T) {
	server := newTestServer()
	request := httptest.NewRequest(http.MethodGet, "/api/v1/snapshot", nil)
	if _, ok := server.authenticate(request); ok {
		t.Fatal("request without header should not authorize")
	}
	request.Header.Set("Authorization", "Bearer wrong")
	if _, ok := server.authenticate(request); ok {
		t.Fatal("wrong token should not authorize")
	}
	request.Header.Set("Authorization", "Bearer secret")
	identity, ok := server.authenticate(request)
	if !ok {
		t.Fatal("correct token should authorize")
	}
	if identity.Role != "owner" || !identity.Static {
		t.Fatalf("static token should map to the owner break-glass identity, got %+v", identity)
	}
}

func TestAuthenticateAcceptsSessionCookie(t *testing.T) {
	server := newTestServer()
	request := httptest.NewRequest(http.MethodGet, "/api/v1/session", nil)
	request.AddCookie(&http.Cookie{Name: "netp2p_session", Value: "secret"})
	identity, ok := server.authenticate(request)
	if !ok {
		t.Fatal("session cookie should authorize")
	}
	if identity.Role != "owner" || !identity.Static {
		t.Fatalf("session cookie identity = %+v", identity)
	}
}

func TestSessionReportsIdentityAndPermissions(t *testing.T) {
	server := newTestServer()
	request := httptest.NewRequest(http.MethodGet, "/api/v1/session", nil)
	request.Header.Set("Authorization", "Bearer secret")
	recorder := httptest.NewRecorder()
	server.handleAPI(recorder, request)
	if recorder.Code != http.StatusOK {
		t.Fatalf("status %d, want 200", recorder.Code)
	}
	body := recorder.Body.String()
	if !strings.Contains(body, `"role":"owner"`) {
		t.Fatalf("session body %q missing role", body)
	}
	if !strings.Contains(body, `"permissions"`) {
		t.Fatalf("session body %q missing permissions", body)
	}
}

func TestHandleAPIRejectsMissingToken(t *testing.T) {
	server := newTestServer()
	recorder := httptest.NewRecorder()
	server.handleAPI(recorder, httptest.NewRequest(http.MethodGet, "/api/v1/session", nil))
	if recorder.Code != http.StatusUnauthorized {
		t.Fatalf("status %d, want 401", recorder.Code)
	}
}

func TestOwnerBootstrapCreatesLocalOwnerSession(t *testing.T) {
	server, accounts, _ := newLocalAuthTestServer(t)
	status := httptest.NewRecorder()
	server.handleAPI(status, httptest.NewRequest(http.MethodGet, "/api/v1/auth/status", nil))
	if status.Code != http.StatusOK || !strings.Contains(status.Body.String(), `"needsOwner":true`) {
		t.Fatalf("status = %d body %q", status.Code, status.Body.String())
	}

	body := bytes.NewBufferString(`{"email":"owner@example.com","name":"Owner","password":"correct horse battery"}`)
	recorder := httptest.NewRecorder()
	server.handleAPI(recorder, httptest.NewRequest(http.MethodPost, "/api/v1/bootstrap/owner", body))
	if recorder.Code != http.StatusOK {
		t.Fatalf("bootstrap status = %d body %q", recorder.Code, recorder.Body.String())
	}
	responseBody := recorder.Body.String()
	for _, forbidden := range []string{"correct horse battery", "passwordVerifier", "argon2id"} {
		if strings.Contains(responseBody, forbidden) {
			t.Fatalf("bootstrap response leaked %q: %s", forbidden, responseBody)
		}
	}
	var response struct {
		SessionToken string `json:"sessionToken"`
		Identity     auth.Identity
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(response.SessionToken, auth.LocalSessionPrefix) || response.Identity.Role != model.RoleOwner {
		t.Fatalf("response = %+v", response)
	}
	if len(accounts.users) != 1 || !model.VerifyPassword("correct horse battery", accounts.users[0].PasswordVerifier) {
		t.Fatalf("owner verifier missing or invalid: %+v", accounts.users)
	}

	var sessionCookie *http.Cookie
	for _, cookie := range recorder.Result().Cookies() {
		if cookie.Name == "netp2p_session" {
			sessionCookie = cookie
		}
	}
	if sessionCookie == nil || !sessionCookie.HttpOnly || !sessionCookie.Secure || sessionCookie.SameSite != http.SameSiteLaxMode {
		t.Fatalf("session cookie = %+v", sessionCookie)
	}
	request := httptest.NewRequest(http.MethodGet, "/api/v1/session", nil)
	request.Header.Set("Authorization", "Bearer "+response.SessionToken)
	identity, ok := server.authenticate(request)
	if !ok || identity.Role != model.RoleOwner || identity.UserID != accounts.users[0].ID {
		t.Fatalf("local identity = %+v ok=%v", identity, ok)
	}

	cookieRequest := httptest.NewRequest(http.MethodGet, "/api/v1/auth/session", nil)
	cookieRequest.AddCookie(sessionCookie)
	cookieRecorder := httptest.NewRecorder()
	server.handleAPI(cookieRecorder, cookieRequest)
	if cookieRecorder.Code != http.StatusOK || !strings.Contains(cookieRecorder.Body.String(), `"role":"owner"`) {
		t.Fatalf("cookie session status = %d body %q", cookieRecorder.Code, cookieRecorder.Body.String())
	}
}

func TestLocalLoginLocksAfterFiveFailures(t *testing.T) {
	server, accounts, authStore := newLocalAuthTestServer(t)
	accounts.users = []model.User{{
		ID: "user-1", Email: "user@example.com", Role: model.RoleUser,
		PasswordVerifier: model.HashPassword("correct horse battery"),
	}}
	for attempt := 0; attempt < 5; attempt++ {
		body := bytes.NewBufferString(`{"email":"user@example.com","password":"wrong password"}`)
		recorder := httptest.NewRecorder()
		server.handleAPI(recorder, httptest.NewRequest(http.MethodPost, "/api/v1/auth/login", body))
		if recorder.Code != http.StatusUnauthorized {
			t.Fatalf("attempt %d status = %d body %q", attempt, recorder.Code, recorder.Body.String())
		}
	}
	body := bytes.NewBufferString(`{"email":"user@example.com","password":"wrong password"}`)
	recorder := httptest.NewRecorder()
	server.handleAPI(recorder, httptest.NewRequest(http.MethodPost, "/api/v1/auth/login", body))
	if recorder.Code != http.StatusTooManyRequests {
		t.Fatalf("locked status = %d body %q", recorder.Code, recorder.Body.String())
	}
	events, err := authStore.AuthEvents(20)
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 6 {
		t.Fatalf("auth events = %+v", events)
	}
	if err := authStore.ClearAuthFailures("user-1"); err != nil {
		t.Fatal(err)
	}
	body = bytes.NewBufferString(`{"email":"USER@example.com","password":"correct horse battery"}`)
	recorder = httptest.NewRecorder()
	server.handleAPI(recorder, httptest.NewRequest(http.MethodPost, "/api/v1/auth/login", body))
	if recorder.Code != http.StatusOK || !strings.Contains(recorder.Body.String(), `"role":"user"`) {
		t.Fatalf("login status = %d body %q", recorder.Code, recorder.Body.String())
	}
	if strings.Contains(recorder.Body.String(), "correct horse battery") || strings.Contains(recorder.Body.String(), "argon2id") {
		t.Fatalf("login response leaked credentials: %s", recorder.Body.String())
	}
}

func TestUsersEndpointDoesNotReturnPasswordVerifier(t *testing.T) {
	server, accounts, _ := newLocalAuthTestServer(t)
	accounts.users = []model.User{{
		ID: "user-1", Email: "user@example.com", Role: model.RoleUser,
		PasswordVerifier: model.HashPassword("correct horse battery"),
	}}
	request := httptest.NewRequest(http.MethodGet, "/api/v1/users", nil)
	request.Header.Set("Authorization", "Bearer secret")
	recorder := httptest.NewRecorder()
	server.handleAPI(recorder, request)
	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d body %q", recorder.Code, recorder.Body.String())
	}
	for _, forbidden := range []string{"passwordVerifier", "argon2id", "correct horse battery"} {
		if strings.Contains(recorder.Body.String(), forbidden) {
			t.Fatalf("users response leaked %q: %s", forbidden, recorder.Body.String())
		}
	}
}

func TestUserCredentialsLifecycle(t *testing.T) {
	server, accounts, _ := newLocalAuthTestServer(t)
	accounts.users = []model.User{{
		ID: "owner-1", Email: "owner@example.com", Role: model.RoleOwner,
		PasswordVerifier: model.HashPassword("original password"),
	}}
	loginBody := bytes.NewBufferString(`{"email":"owner@example.com","password":"original password"}`)
	loginRecorder := httptest.NewRecorder()
	server.handleAPI(loginRecorder, httptest.NewRequest(http.MethodPost, "/api/v1/auth/login", loginBody))
	if loginRecorder.Code != http.StatusOK {
		t.Fatalf("login status = %d body %q", loginRecorder.Code, loginRecorder.Body.String())
	}
	var login struct {
		SessionToken string `json:"sessionToken"`
	}
	if err := json.Unmarshal(loginRecorder.Body.Bytes(), &login); err != nil {
		t.Fatal(err)
	}

	request := httptest.NewRequest(http.MethodPost, "/api/v1/users/owner-1/credentials",
		bytes.NewBufferString(`{"password":"correct horse battery"}`))
	request.Header.Set("Authorization", "Bearer "+login.SessionToken)
	recorder := httptest.NewRecorder()
	server.handleAPI(recorder, request)
	if recorder.Code != http.StatusOK {
		t.Fatalf("credential status = %d body %q", recorder.Code, recorder.Body.String())
	}
	body := recorder.Body.String()
	if strings.Contains(body, "correct horse battery") || strings.Contains(body, "passwordVerifier") || strings.Contains(body, "argon2id") {
		t.Fatalf("credential response leaked secrets: %s", body)
	}
	if !model.VerifyPassword("correct horse battery", accounts.users[0].PasswordVerifier) {
		t.Fatal("certified verifier was not updated")
	}

	oldRequest := httptest.NewRequest(http.MethodGet, "/api/v1/session", nil)
	oldRequest.Header.Set("Authorization", "Bearer "+login.SessionToken)
	if _, ok := server.authenticate(oldRequest); ok {
		t.Fatal("session issued before credential change remained valid")
	}

	oldLogin := bytes.NewBufferString(`{"email":"owner@example.com","password":"original password"}`)
	oldRecorder := httptest.NewRecorder()
	server.handleAPI(oldRecorder, httptest.NewRequest(http.MethodPost, "/api/v1/auth/login", oldLogin))
	if oldRecorder.Code != http.StatusUnauthorized {
		t.Fatalf("old password status = %d", oldRecorder.Code)
	}
	newLogin := bytes.NewBufferString(`{"email":"owner@example.com","password":"correct horse battery"}`)
	newRecorder := httptest.NewRecorder()
	server.handleAPI(newRecorder, httptest.NewRequest(http.MethodPost, "/api/v1/auth/login", newLogin))
	if newRecorder.Code != http.StatusOK {
		t.Fatalf("new password status = %d body %q", newRecorder.Code, newRecorder.Body.String())
	}
}

func TestUserCredentialsAuthorization(t *testing.T) {
	server, accounts, _ := newLocalAuthTestServer(t)
	accounts.users = []model.User{
		{ID: "owner-1", Email: "owner@example.com", Role: model.RoleOwner, PasswordVerifier: model.HashPassword("owner password 1")},
		{ID: "admin-1", Email: "admin@example.com", Role: model.RoleAdmin, PasswordVerifier: model.HashPassword("admin password")},
		{ID: "user-1", Email: "user@example.com", Role: model.RoleUser, PasswordVerifier: model.HashPassword("user password 1")},
	}
	adminToken, _, err := server.sessions.Issue(auth.Identity{UserID: "admin-1", Role: model.RoleAdmin}, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodPost, "/api/v1/users/owner-1/credentials",
		bytes.NewBufferString(`{"password":"correct horse battery"}`))
	request.Header.Set("Authorization", "Bearer "+adminToken)
	recorder := httptest.NewRecorder()
	server.handleAPI(recorder, request)
	if recorder.Code != http.StatusForbidden {
		t.Fatalf("admin changing owner status = %d body %q", recorder.Code, recorder.Body.String())
	}

	userToken, _, err := server.sessions.Issue(auth.Identity{UserID: "user-1", Role: model.RoleUser}, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	request = httptest.NewRequest(http.MethodPost, "/api/v1/users/admin-1/credentials",
		bytes.NewBufferString(`{"password":"correct horse battery"}`))
	request.Header.Set("Authorization", "Bearer "+userToken)
	recorder = httptest.NewRecorder()
	server.handleAPI(recorder, request)
	if recorder.Code != http.StatusForbidden {
		t.Fatalf("user changing admin status = %d body %q", recorder.Code, recorder.Body.String())
	}
}
