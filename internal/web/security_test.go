package web

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/netp2p/netp2p/internal/auth"
	"github.com/netp2p/netp2p/internal/bft"
	"github.com/netp2p/netp2p/internal/model"
	"github.com/netp2p/netp2p/internal/store"
)

func TestSnapshotRBACReturnsScopedProjectionForRoleUser(t *testing.T) {
	server, accounts, _ := newLocalAuthTestServer(t)
	accounts.users = []model.User{
		{ID: "user-1", Email: "user@example.com", Role: model.RoleUser, AutoGroups: []string{"clients"}},
		{ID: "other-user", Email: "other@example.com", Role: model.RoleUser, AutoGroups: []string{"isolated"}},
		{ID: "viewer-1", Email: "viewer@example.com", Role: model.RoleUsageViewer},
	}
	accounts.peers = []model.PeerRecord{
		{PeerID: "own-peer", OverlayIP: "10.70.0.11", UserID: "user-1", Groups: []string{"clients"}},
		{PeerID: "other-peer", OverlayIP: "10.70.0.12", UserID: "other-user", Groups: []string{"isolated"}},
	}
	accounts.groups = []model.Group{
		{ID: "clients", Name: "Clients", UserIDs: []string{"user-1"}},
		{ID: "isolated", Name: "Isolated", UserIDs: []string{"other-user"}},
	}
	accounts.policies = []model.Policy{
		{ID: "client-policy", SourceGroups: []string{"clients"}, DestinationGroups: []string{"servers"}, Effect: model.EffectAllow},
		{ID: "isolated-policy", SourceGroups: []string{"isolated"}, DestinationGroups: []string{"isolated"}, Effect: model.EffectAllow},
	}
	accounts.routes = []model.Route{
		{ID: "client-route", RoutingGroup: "gateways", DistributionGroup: []string{"clients"}},
		{ID: "isolated-route", RoutingGroup: "gateways", DistributionGroup: []string{"isolated"}},
	}

	token, _, err := server.issueLocalSession(auth.Identity{UserID: "user-1", Role: model.RoleUser}, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodGet, "/api/v1/snapshot", nil)
	request.Header.Set("Authorization", "Bearer "+token)
	recorder := httptest.NewRecorder()
	server.handleAPI(recorder, request)
	if recorder.Code != http.StatusOK {
		t.Fatalf("snapshot status = %d body %q", recorder.Code, recorder.Body.String())
	}

	var snapshot ScopedSnapshot
	if err := json.Unmarshal(recorder.Body.Bytes(), &snapshot); err != nil {
		t.Fatal(err)
	}
	if snapshot.User.ID != "user-1" || len(snapshot.Peers) != 1 || snapshot.Peers[0].PeerID != "own-peer" {
		t.Fatalf("scoped user/peers = %+v", snapshot)
	}
	if len(snapshot.Groups) != 1 || snapshot.Groups[0].ID != "clients" {
		t.Fatalf("scoped groups = %+v", snapshot.Groups)
	}
	if len(snapshot.Policies) != 1 || snapshot.Policies[0].ID != "client-policy" {
		t.Fatalf("scoped policies = %+v", snapshot.Policies)
	}
	if len(snapshot.Routes) != 1 || snapshot.Routes[0].ID != "client-route" {
		t.Fatalf("scoped routes = %+v", snapshot.Routes)
	}
	for _, forbidden := range []string{"other-peer", "other-user", "isolated-policy", "isolated-route", "stateHash", "setupKeys"} {
		if strings.Contains(recorder.Body.String(), forbidden) {
			t.Fatalf("scoped snapshot leaked %q: %s", forbidden, recorder.Body.String())
		}
	}

	activity := httptest.NewRequest(http.MethodGet, "/api/v1/activity", nil)
	activity.Header.Set("Authorization", "Bearer "+token)
	activityRecorder := httptest.NewRecorder()
	server.handleAPI(activityRecorder, activity)
	if activityRecorder.Code != http.StatusForbidden {
		t.Fatalf("activity status = %d, want 403", activityRecorder.Code)
	}

	usageToken, _, err := server.issueLocalSession(auth.Identity{UserID: "viewer-1", Role: model.RoleUsageViewer}, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	usageRequest := httptest.NewRequest(http.MethodGet, "/api/v1/snapshot", nil)
	usageRequest.Header.Set("Authorization", "Bearer "+usageToken)
	usageRecorder := httptest.NewRecorder()
	server.handleAPI(usageRecorder, usageRequest)
	if usageRecorder.Code != http.StatusForbidden {
		t.Fatalf("usage viewer snapshot status = %d, want 403", usageRecorder.Code)
	}
}

func TestPresenceRequiresPresenceModulePermission(t *testing.T) {
	server, accounts, _ := newLocalAuthTestServer(t)
	accounts.users = []model.User{{ID: "user-1", Email: "user@example.com", Role: model.RoleUser}}
	token, _, err := server.issueLocalSession(auth.Identity{UserID: "user-1", Role: model.RoleUser}, time.Now())
	if err != nil {
		t.Fatal(err)
	}

	request := httptest.NewRequest(http.MethodGet, "/api/v1/presence", nil)
	request.Header.Set("Authorization", "Bearer "+token)
	recorder := httptest.NewRecorder()
	server.handleAPI(recorder, request)
	if recorder.Code != http.StatusForbidden {
		t.Fatalf("presence status = %d, want 403 for role without presence permission", recorder.Code)
	}
}

func TestAssignmentTransitionTimestampIsFixedAtAPIBoundary(t *testing.T) {
	now := time.Date(2026, 10, 14, 14, 20, 0, 0, time.UTC)
	assignment := model.RouteAssignment{
		ID: "assignment-1", SourcePeerID: "peer-a", DestinationPeerID: "peer-b",
		Primary: model.PathSpec{ID: "path-1", Kind: model.PathKindViaManager},
	}
	transition := model.StateTransition{
		Type: bft.TransitionUpdateAssignment, Assignment: &assignment,
	}

	normalized := normalizeTransitionForSubmit(transition, now)
	if !normalized.Assignment.UpdatedAt.Equal(now) {
		t.Fatalf("assignment timestamp = %v, want %v", normalized.Assignment.UpdatedAt, now)
	}
	if !transition.Assignment.UpdatedAt.IsZero() {
		t.Fatal("normalization mutated the caller's transition value")
	}
}

func TestLogoutRevokesCookieAndBearerSessions(t *testing.T) {
	server, accounts, _ := newLocalAuthTestServer(t)
	accounts.users = []model.User{{ID: "user-1", Email: "user@example.com", Role: model.RoleUser}}
	cookieToken, _, err := server.issueLocalSession(auth.Identity{UserID: "user-1", Role: model.RoleUser}, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	bearerToken, _, err := server.issueLocalSession(auth.Identity{UserID: "user-1", Role: model.RoleUser}, time.Now())
	if err != nil {
		t.Fatal(err)
	}

	logout := httptest.NewRequest(http.MethodPost, "/api/v1/auth/logout", nil)
	logout.Host = "console.test"
	logout.Header.Set("Origin", "https://console.test")
	logout.AddCookie(&http.Cookie{Name: "netp2p_session", Value: cookieToken})
	recorder := httptest.NewRecorder()
	server.handleAPI(recorder, logout)
	if recorder.Code != http.StatusOK {
		t.Fatalf("cookie logout status = %d body %q", recorder.Code, recorder.Body.String())
	}
	cookieRequest := httptest.NewRequest(http.MethodGet, "/api/v1/session", nil)
	cookieRequest.AddCookie(&http.Cookie{Name: "netp2p_session", Value: cookieToken})
	if _, ok := server.authenticate(cookieRequest); ok {
		t.Fatal("cookie session remained valid after logout")
	}

	bearerLogout := httptest.NewRequest(http.MethodPost, "/api/v1/auth/logout", nil)
	bearerLogout.Header.Set("Authorization", "Bearer "+bearerToken)
	bearerRecorder := httptest.NewRecorder()
	server.handleAPI(bearerRecorder, bearerLogout)
	if bearerRecorder.Code != http.StatusOK {
		t.Fatalf("bearer logout status = %d body %q", bearerRecorder.Code, bearerRecorder.Body.String())
	}
	bearerRequest := httptest.NewRequest(http.MethodGet, "/api/v1/session", nil)
	bearerRequest.Header.Set("Authorization", "Bearer "+bearerToken)
	if _, ok := server.authenticate(bearerRequest); ok {
		t.Fatal("bearer session remained valid after logout")
	}
}

func TestValidSessionSyncsAcrossManagersBeforeAuthentication(t *testing.T) {
	first, accounts, firstStore := newLocalAuthTestServer(t)
	second, secondAccounts, secondStore := newLocalAuthTestServer(t)
	accounts.users = []model.User{{ID: "user-1", Email: "user@example.com", Role: model.RoleUser}}
	secondAccounts.users = []model.User{{ID: "user-1", Email: "user@example.com", Role: model.RoleUser}}

	token, _, err := first.issueLocalSession(auth.Identity{UserID: "user-1", Role: model.RoleUser}, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	sessionSyncer := &copySessionSyncer{from: firstStore, to: secondStore}
	first.sessionSyncer = sessionSyncer
	second.sessionSyncer = sessionSyncer

	request := httptest.NewRequest(http.MethodGet, "/api/v1/session", nil)
	request.Header.Set("Authorization", "Bearer "+token)
	if _, ok := second.authenticate(request); !ok {
		t.Fatal("valid session was not pulled from the issuing manager")
	}

	logout := httptest.NewRequest(http.MethodPost, "/api/v1/auth/logout", nil)
	logout.Header.Set("Authorization", "Bearer "+token)
	recorder := httptest.NewRecorder()
	first.handleAPI(recorder, logout)
	if recorder.Code != http.StatusOK {
		t.Fatalf("logout status = %d body %q", recorder.Code, recorder.Body.String())
	}
	if _, ok := second.authenticate(request); ok {
		t.Fatal("revoked session remained valid on another manager")
	}
}

type copySessionSyncer struct {
	from *store.Store
	to   *store.Store
}

func (syncer *copySessionSyncer) Sync(context.Context) error {
	sessions, err := syncer.from.WebSessions()
	if err != nil {
		return err
	}
	return syncer.to.MergeWebSessions(sessions, time.Now())
}

func TestCookieMutationsRequireSameOrigin(t *testing.T) {
	server, accounts, _ := newLocalAuthTestServer(t)
	accounts.users = []model.User{{ID: "user-1", Email: "user@example.com", Role: model.RoleUser}}
	token, _, err := server.issueLocalSession(auth.Identity{UserID: "user-1", Role: model.RoleUser}, time.Now())
	if err != nil {
		t.Fatal(err)
	}

	newRequest := func(origin string) *http.Request {
		request := httptest.NewRequest(http.MethodPost, "/api/v1/unknown", nil)
		request.Host = "console.test"
		if origin != "" {
			request.Header.Set("Origin", origin)
		}
		request.AddCookie(&http.Cookie{Name: "netp2p_session", Value: token})
		return request
	}
	for _, origin := range []string{"", "https://evil.test", "null"} {
		recorder := httptest.NewRecorder()
		server.handleAPI(recorder, newRequest(origin))
		if recorder.Code != http.StatusForbidden {
			t.Fatalf("Origin %q status = %d, want 403", origin, recorder.Code)
		}
	}
	recorder := httptest.NewRecorder()
	server.handleAPI(recorder, newRequest("https://console.test"))
	if recorder.Code != http.StatusNotFound {
		t.Fatalf("same-origin status = %d, want 404 after CSRF check", recorder.Code)
	}
}

func TestLoginRateLimiterCombinesIPAndIdentity(t *testing.T) {
	limiter := newLoginRateLimiter()
	for attempt := 1; attempt <= loginIdentityAttempts; attempt++ {
		if !limiter.Allow("198.51.100.10", "user@example.com") {
			t.Fatalf("attempt %d was rejected before the identity limit", attempt)
		}
	}
	if limiter.Allow("198.51.100.10", "user@example.com") {
		t.Fatal("identity attempt beyond the configured limit was allowed")
	}
	if !limiter.Allow("198.51.100.10", "other@example.com") {
		t.Fatal("a different identity from the same IP was incorrectly rate limited")
	}
	if limiter.Allow("", "user@example.com") {
		t.Fatal("login without a source IP was allowed")
	}
}

func TestUserRoleTransitionRevokesPersistedSessions(t *testing.T) {
	server, accounts, _ := newLocalAuthTestServer(t)
	accounts.users = []model.User{{ID: "user-1", Email: "user@example.com", Role: model.RoleAdmin}}
	token, _, err := server.issueLocalSession(auth.Identity{UserID: "user-1", Role: model.RoleAdmin}, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	transition := model.StateTransition{
		Type: bft.TransitionUpdateUserRole, TargetID: "user-1",
		User: &model.User{ID: "user-1", Role: model.RoleUser},
	}
	if err := server.revokeSessionsForTransition(transition); err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodGet, "/api/v1/session", nil)
	request.Header.Set("Authorization", "Bearer "+token)
	if _, ok := server.authenticate(request); ok {
		t.Fatal("role change did not revoke the user's persisted session")
	}
}
