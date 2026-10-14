package web

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"log"
	"net/http"
	"net/mail"
	"strings"
	"time"

	"github.com/netp2p/netp2p/internal/auth"
	"github.com/netp2p/netp2p/internal/bft"
	"github.com/netp2p/netp2p/internal/model"
	"github.com/netp2p/netp2p/internal/store"
)

const (
	loginMaxAttempts           = 5
	loginLockDuration          = 15 * time.Minute
	sessionReplicationAttempts = 4
)

var sessionReplicationRetryDelay = 100 * time.Millisecond

type accountDirectory interface {
	Users() []model.User
	Snapshot() model.SignedSnapshot
	SubmitAs(model.StateTransition, model.Actor) (model.SignedSnapshot, error)
}

type loginRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

type ownerBootstrapRequest struct {
	Email    string `json:"email"`
	Name     string `json:"name"`
	Password string `json:"password"`
}

type credentialsRequest struct {
	Email    *string `json:"email,omitempty"`
	Password *string `json:"password,omitempty"`
}

func (server *Server) handlePublicAuth(writer http.ResponseWriter, request *http.Request) bool {
	path := strings.TrimSuffix(request.URL.Path, "/")
	switch {
	case request.Method == http.MethodGet && path == "/api/v1/auth/status":
		server.handleAuthStatus(writer)
	case request.Method == http.MethodGet && path == "/api/v1/auth/session":
		server.handleAuthSession(writer, request)
	case request.Method == http.MethodPost && path == "/api/v1/auth/login":
		server.handleLogin(writer, request)
	case request.Method == http.MethodPost && path == "/api/v1/auth/logout":
		server.handleLogout(writer, request)
	case request.Method == http.MethodGet && path == "/api/v1/bootstrap/status":
		server.handleAuthStatus(writer)
	case request.Method == http.MethodPost && path == "/api/v1/bootstrap/owner":
		server.handleOwnerBootstrap(writer, request)
	default:
		return false
	}
	return true
}

func (server *Server) handleAuthSession(writer http.ResponseWriter, request *http.Request) {
	identity, ok := server.authenticate(request)
	if !ok {
		writeError(writer, http.StatusUnauthorized, "unauthorized")
		return
	}
	writeJSON(writer, http.StatusOK, map[string]any{
		"identity": identity, "permissions": auth.Permissions(identity.Role),
		"sessionReplicationDegraded": server.sessionReplicationDegraded.Load(),
	})
}

func (server *Server) handleAuthStatus(writer http.ResponseWriter) {
	writeJSON(writer, http.StatusOK, map[string]any{
		"needsOwner":                 server.needsOwner(),
		"localLogin":                 server.sessions != nil && server.authStore != nil,
		"sessionReplicationDegraded": server.sessionReplicationDegraded.Load(),
	})
}

func (server *Server) handleLogin(writer http.ResponseWriter, request *http.Request) {
	var body loginRequest
	if !server.decodeAuthBody(writer, request, &body) {
		return
	}
	email := normalizeEmail(body.Email)
	if email == "" || body.Password == "" {
		writeError(writer, http.StatusBadRequest, "email and password are required")
		return
	}
	now := time.Now()
	user, found := server.findUserByEmail(email)
	userID := user.ID
	if !found {
		userID = "unknown:" + hashIdentity(email)
	}
	lock, err := server.authStore.AuthLock(userID)
	if err != nil {
		writeError(writer, http.StatusInternalServerError, "cannot read login state")
		return
	}
	if lockedUntil, parseErr := time.Parse(time.RFC3339Nano, lock.LockedUntil); parseErr == nil && now.Before(lockedUntil) {
		if !server.recordAuthEvent(writer, userID, email, "login", "locked_out", request) {
			return
		}
		writeError(writer, http.StatusTooManyRequests, "too many failed attempts; try again later")
		return
	}
	if !server.allowLogin(writer, userID, email, request) {
		return
	}
	verifier := user.PasswordVerifier
	if len(verifier) == 0 {
		verifier = server.dummyPasswordVerifier
	}
	if !model.VerifyPassword(body.Password, verifier) || !found {
		state, failureErr := server.authStore.RecordAuthFailure(userID, now, loginMaxAttempts, loginLockDuration)
		if failureErr != nil {
			writeError(writer, http.StatusInternalServerError, "cannot record login failure")
			return
		}
		result := "invalid_credentials"
		if state.LockedUntil != "" {
			result = "locked_out"
		}
		if !server.recordAuthEvent(writer, userID, email, "login", result, request) {
			return
		}
		writeError(writer, http.StatusUnauthorized, "invalid email or password")
		return
	}
	if user.Blocked {
		if !server.recordAuthEvent(writer, userID, email, "login", "user_blocked", request) {
			return
		}
		writeError(writer, http.StatusForbidden, "user is blocked")
		return
	}
	if err := server.authStore.ClearAuthFailures(userID); err != nil {
		writeError(writer, http.StatusInternalServerError, "cannot clear login state")
		return
	}
	identity := identityForUser(user)
	token, expires, err := server.issueLocalSession(identity, now)
	if err != nil {
		writeError(writer, http.StatusInternalServerError, "cannot create or persist session")
		return
	}
	if !server.recordAuthEvent(writer, userID, email, "login", "success", request) {
		return
	}
	server.setSessionCookie(writer, token, expires)
	writeJSON(writer, http.StatusOK, map[string]any{
		"identity": identity, "permissions": auth.Permissions(identity.Role),
		"expiresAt":                  expires.Format(time.RFC3339),
		"sessionReplicationDegraded": server.sessionReplicationDegraded.Load(),
	})
}

func (server *Server) allowLogin(writer http.ResponseWriter, userID, email string, request *http.Request) bool {
	server.loginLimiterOnce.Do(func() {
		if server.loginLimiter == nil {
			server.loginLimiter = newLoginRateLimiter()
		}
	})
	if !server.loginLimiter.Allow(loginClientIP(request), hashIdentity(email)) {
		if !server.recordAuthEvent(writer, userID, email, "login", "rate_limited", request) {
			return false
		}
		writeError(writer, http.StatusTooManyRequests, "too many login attempts; try again later")
		return false
	}
	return true
}

func (server *Server) handleLogout(writer http.ResponseWriter, request *http.Request) {
	server.clearSessionCookie(writer)
	if token, ok := requestSessionToken(request); ok {
		if identity, valid := server.validPersistedSession(token, time.Now()); valid {
			if !server.recordAuthEvent(writer, identity.UserID, identity.Email, "logout", "success", request) {
				return
			}
			if err := server.revokeSessionToken(token, time.Now()); err != nil {
				writeError(writer, http.StatusInternalServerError, "cannot revoke session")
				return
			}
		}
	}
	writeJSON(writer, http.StatusOK, map[string]string{"status": "signed out"})
}

func (server *Server) handleUserCredentials(writer http.ResponseWriter, request *http.Request, targetID string, identity auth.Identity) {
	if targetID == "" {
		writeError(writer, http.StatusNotFound, "not found")
		return
	}
	target, found := server.findUserByID(targetID)
	if !found {
		writeError(writer, http.StatusNotFound, "user not found")
		return
	}
	if identity.UserID != target.ID && !identity.Allows(auth.ModuleUsers, auth.OpUpdate) {
		writeError(writer, http.StatusForbidden, "forbidden")
		return
	}
	if target.Role == model.RoleOwner && identity.Role != model.RoleOwner {
		writeError(writer, http.StatusForbidden, "only an owner may modify owner credentials")
		return
	}
	var body credentialsRequest
	if !server.decodeAuthBody(writer, request, &body) {
		return
	}
	if body.Email == nil && body.Password == nil {
		writeError(writer, http.StatusBadRequest, "email or password is required")
		return
	}
	update := model.User{ID: target.ID}
	if body.Email != nil {
		email := normalizeEmail(*body.Email)
		if email == "" {
			writeError(writer, http.StatusBadRequest, "email must not be empty")
			return
		}
		parsed, err := mail.ParseAddress(email)
		if err != nil || strings.ToLower(parsed.Address) != email {
			writeError(writer, http.StatusBadRequest, "invalid email")
			return
		}
		if existing, exists := server.findUserByEmail(email); exists && existing.ID != target.ID {
			writeError(writer, http.StatusConflict, "email already registered")
			return
		}
		update.Email = email
	}
	if body.Password != nil && len(*body.Password) < 12 {
		writeError(writer, http.StatusBadRequest, "a password of at least 12 characters is required")
		return
	}
	if body.Password != nil {
		update.PasswordVerifier = model.HashPassword(*body.Password)
	} else {
		// Email-only changes keep the existing password and its verifier
		// intact, as required by the certified transition.
		update.PasswordVerifier = target.PasswordVerifier
	}
	update.CredentialsChangedAt = time.Now().UTC().Format(time.RFC3339Nano)
	transition := model.StateTransition{
		Type: bft.TransitionUpdateUserCredentials, TargetID: target.ID, User: &update,
	}
	_, err := server.accounts.SubmitAs(transition, auth.ActorOf(identity))
	if err != nil {
		if !server.recordAuthEvent(writer, target.ID, target.Email, "update_credentials", "failed", request) {
			return
		}
		writeError(writer, http.StatusConflict, err.Error())
		return
	}
	if !server.recordAuthEvent(writer, target.ID, update.Email, "update_credentials", "success", request) {
		return
	}
	if err := server.authStore.RevokeUserWebSessions(target.ID, time.Now()); err != nil {
		writeError(writer, http.StatusInternalServerError, "cannot revoke user sessions")
		return
	}
	server.clearSessionCookie(writer)
	updated, _ := server.findUserByID(target.ID)
	writeJSON(writer, http.StatusOK, publicUsers([]model.User{updated})[0])
}

func (server *Server) handleOwnerBootstrap(writer http.ResponseWriter, request *http.Request) {
	if !server.needsOwner() {
		writeError(writer, http.StatusConflict, "owner already exists")
		return
	}
	var body ownerBootstrapRequest
	if !server.decodeAuthBody(writer, request, &body) {
		return
	}
	email := normalizeEmail(body.Email)
	if email == "" || len(body.Password) < 12 {
		writeError(writer, http.StatusBadRequest, "valid email and a password of at least 12 characters are required")
		return
	}
	parsed, err := mail.ParseAddress(email)
	if err != nil || strings.ToLower(parsed.Address) != email {
		writeError(writer, http.StatusBadRequest, "invalid email")
		return
	}
	if _, exists := server.findUserByEmail(email); exists {
		writeError(writer, http.StatusConflict, "email already registered")
		return
	}
	name := strings.TrimSpace(body.Name)
	if name == "" {
		name = email
	}
	user := model.User{
		ID: "local-" + hashIdentity(email), Email: email, Name: name, Role: model.RoleOwner,
		AutoGroups: []string{"owners"}, Issued: model.GroupIssuedAPI,
		PasswordVerifier: model.HashPassword(body.Password),
	}
	if !server.hasGroup("owners") {
		group := model.Group{ID: "owners", Name: "Owners", Issued: model.GroupIssuedAPI}
		if _, err := server.accounts.SubmitAs(
			model.StateTransition{Type: bft.TransitionUpsertGroup, Group: &group},
			model.Actor{ID: "bootstrap", Name: "first owner bootstrap", Role: model.RoleOwner},
		); err != nil {
			writeError(writer, http.StatusConflict, err.Error())
			return
		}
	}
	snapshot, err := server.accounts.SubmitAs(
		model.StateTransition{Type: bft.TransitionRegisterUser, User: &user},
		model.Actor{ID: "bootstrap", Name: "first owner bootstrap", Role: model.RoleOwner},
	)
	if err != nil {
		if !server.recordAuthEvent(writer, user.ID, email, "bootstrap_owner", "failed", request) {
			return
		}
		writeError(writer, http.StatusConflict, err.Error())
		return
	}
	_ = snapshot
	identity := identityForUser(user)
	token, expires, issueErr := server.issueLocalSession(identity, time.Now())
	if issueErr != nil {
		writeError(writer, http.StatusInternalServerError, "cannot create or persist session")
		return
	}
	if !server.recordAuthEvent(writer, user.ID, email, "bootstrap_owner", "success", request) {
		return
	}
	server.setSessionCookie(writer, token, expires)
	writeJSON(writer, http.StatusOK, map[string]any{
		"identity": identity, "permissions": auth.Permissions(identity.Role),
		"expiresAt":                  expires.Format(time.RFC3339),
		"sessionReplicationDegraded": server.sessionReplicationDegraded.Load(),
	})
}

func (server *Server) issueLocalSession(identity auth.Identity, now time.Time) (string, time.Time, error) {
	token, expires, err := server.sessions.Issue(identity, now)
	if err != nil {
		return "", time.Time{}, err
	}
	sessionID, err := server.sessions.SessionID(token)
	if err != nil {
		return "", time.Time{}, err
	}
	if err := server.authStore.RecordWebSession(store.WebSession{
		ID: sessionID, UserID: identity.UserID,
		IssuedAt:  now.UTC().Format(time.RFC3339Nano),
		ExpiresAt: expires.UTC().Format(time.RFC3339Nano),
	}); err != nil {
		return "", time.Time{}, err
	}
	server.syncWebSessionsWithRetry()
	return token, expires, nil
}

func (server *Server) syncWebSessionsWithRetry() bool {
	if server.sessionSyncer == nil {
		server.sessionReplicationDegraded.Store(false)
		return true
	}
	var syncErr error
	for attempt := 1; attempt <= sessionReplicationAttempts; attempt++ {
		ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
		syncErr = server.sessionSyncer.Sync(ctx)
		cancel()
		if syncErr == nil {
			server.sessionReplicationDegraded.Store(false)
			return true
		}
		if attempt < sessionReplicationAttempts {
			time.Sleep(sessionReplicationRetryDelay)
		}
	}
	server.sessionReplicationDegraded.Store(true)
	log.Printf("web session replication degraded=true attempts=%d error=%v",
		sessionReplicationAttempts, syncErr)
	return false
}

func (server *Server) syncWebSessions() error {
	if server.sessionSyncer == nil {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	return server.sessionSyncer.Sync(ctx)
}

func (server *Server) decodeAuthBody(writer http.ResponseWriter, request *http.Request, target any) bool {
	if err := decodeJSONBody(writer, request, 16<<10, target); err != nil {
		writeError(writer, http.StatusBadRequest, "invalid request")
		return false
	}
	return true
}

func (server *Server) recordAuthEvent(
	writer http.ResponseWriter, userID, email, eventType, result string, request *http.Request,
) bool {
	event := store.AuthEvent{
		UserID: userID, Email: email, Type: eventType, Result: result,
		RemoteAddress: request.RemoteAddr, UserAgent: truncate(request.UserAgent(), 256),
	}
	if err := server.authStore.RecordAuthEvent(event); err != nil {
		writeError(writer, http.StatusInternalServerError, "cannot record auth event")
		return false
	}
	return true
}

func (server *Server) setSessionCookie(writer http.ResponseWriter, token string, expires time.Time) {
	http.SetCookie(writer, &http.Cookie{
		Name: "netp2p_session", Value: token, Path: "/",
		MaxAge: int(time.Until(expires).Seconds()), HttpOnly: true, Secure: true,
		SameSite: http.SameSiteLaxMode,
	})
}

func (server *Server) clearSessionCookie(writer http.ResponseWriter) {
	http.SetCookie(writer, &http.Cookie{
		Name: "netp2p_session", Value: "", Path: "/", MaxAge: -1,
		HttpOnly: true, Secure: true, SameSite: http.SameSiteLaxMode,
	})
}

func (server *Server) needsOwner() bool {
	for _, user := range server.accounts.Users() {
		if user.Role == model.RoleOwner {
			return false
		}
	}
	return true
}

func (server *Server) hasGroup(id string) bool {
	for _, group := range server.accounts.Snapshot().State.Groups {
		if group.ID == id {
			return true
		}
	}
	return false
}

func (server *Server) findUserByEmail(email string) (model.User, bool) {
	for _, user := range server.accounts.Users() {
		if normalizeEmail(user.Email) == email {
			return user, true
		}
	}
	return model.User{}, false
}

func (server *Server) findUserByID(id string) (model.User, bool) {
	for _, user := range server.accounts.Users() {
		if user.ID == id {
			return user, true
		}
	}
	return model.User{}, false
}

func identityForUser(user model.User) auth.Identity {
	return auth.Identity{
		Subject: user.ID, UserID: user.ID, Email: user.Email, Name: user.Name, Role: user.Role,
	}
}

func publicUsers(users []model.User) []model.User {
	result := make([]model.User, len(users))
	for index, user := range users {
		result[index] = user
		result[index].PasswordVerifier = nil
	}
	return result
}

func normalizeEmail(value string) string {
	return strings.ToLower(strings.TrimSpace(value))
}

func hashIdentity(value string) string {
	digest := sha256.Sum256([]byte(value))
	return hex.EncodeToString(digest[:8])
}

func truncate(value string, limit int) string {
	if len(value) <= limit {
		return value
	}
	return value[:limit]
}
