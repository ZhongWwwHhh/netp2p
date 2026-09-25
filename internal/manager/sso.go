package manager

import (
	"context"
	"fmt"
	"log"
	"sort"
	"strings"
	"time"

	"github.com/netp2p/netp2p/internal/auth"
	"github.com/netp2p/netp2p/internal/bft"
	"github.com/netp2p/netp2p/internal/model"
	"github.com/netp2p/netp2p/internal/oidc"
	"github.com/netp2p/netp2p/internal/protocol"
)

// loginRefreshWindow bounds how often a routine login rewrites peer.LastLogin.
// Rewriting it on every reconnect would grow the decision log for no benefit,
// while a stale timestamp would expire an otherwise healthy session.
const loginRefreshWindow = 12 * time.Hour

// authenticate resolves a login request to a registration. When a JWT is
// presented the manager verifies it, synchronizes the user's groups and returns
// the user-bound registration. A non-empty code/message signals failure.
func (manager *Manager) authenticate(request protocol.LoginRequest) (Registration, string, string) {
	registration := toRegistration(request)
	if strings.TrimSpace(request.JWTToken) == "" {
		return registration, "", ""
	}
	if manager.sso == nil {
		return registration, protocol.CodeInvalidJWT, "sso is not configured"
	}
	claims, err := manager.sso.Verify(context.Background(), request.JWTToken)
	if err != nil {
		return registration, protocol.CodeInvalidJWT, fmt.Sprintf("invalid jwt: %v", err)
	}
	if !manager.sso.Config().Allowed(claims) {
		return registration, protocol.CodeInvalidJWT, "user is not in an allowed group"
	}
	user, err := manager.ensureUser(claims)
	if err != nil {
		return registration, protocol.CodeInvalidJWT, err.Error()
	}
	if user.Blocked {
		return registration, protocol.CodeInvalidJWT, "user is blocked"
	}
	now := time.Now().UTC()
	if code, message := manager.checkLoginExpiration(request.PeerID, claims, now); message != "" {
		return registration, code, message
	}
	registration.UserID = user.ID
	registration.LastLogin = now.Format(time.RFC3339)
	return registration, "", ""
}

// Authenticate is the console-facing entry point: it turns an ID token into an
// identity with a role the permission matrix understands.
func (manager *Manager) Authenticate(ctx context.Context, token string) (auth.Identity, error) {
	if manager.sso == nil {
		return auth.Identity{}, fmt.Errorf("sso is not configured")
	}
	claims, err := manager.sso.Verify(ctx, token)
	if err != nil {
		return auth.Identity{}, err
	}
	if !manager.sso.Config().Allowed(claims) {
		return auth.Identity{}, fmt.Errorf("user is not in an allowed group")
	}
	user, err := manager.ensureUser(claims)
	if err != nil {
		return auth.Identity{}, err
	}
	if user.Blocked {
		return auth.Identity{}, fmt.Errorf("user is blocked")
	}
	return auth.Identity{
		Subject: claims.Subject, UserID: user.ID,
		Email: user.Email, Name: user.Name, Role: user.Role,
	}, nil
}

// ensureUser creates or updates the certified user record for the claims.
func (manager *Manager) ensureUser(claims oidc.Claims) (model.User, error) {
	state := manager.engine.CurrentState()
	autoGroups, err := manager.ensureClaimGroups(state, claims.Groups, claimsActor(claims, ""))
	if err != nil {
		return model.User{}, err
	}
	if existing := findUserRecord(state, claims.Subject); existing != nil {
		return manager.reconcileUser(*existing, claims, autoGroups)
	}
	user := model.User{
		ID: claims.Subject, Email: claims.Email, Name: claims.Name,
		Role: manager.initialRole(claims, state), AutoGroups: autoGroups,
		Issued: model.GroupIssuedJWT, LastLogin: time.Now().UTC().Format(time.RFC3339),
	}
	snapshot, err := manager.SubmitAs(
		model.StateTransition{Type: bft.TransitionRegisterUser, User: &user},
		claimsActor(claims, user.Role),
	)
	if err != nil {
		return model.User{}, err
	}
	if record := findUserRecord(snapshot.State, user.ID); record != nil {
		return *record, nil
	}
	return model.User{}, fmt.Errorf("user %s missing from certified state", user.ID)
}

// reconcileUser re-submits only what actually changed: group membership and,
// when the IdP's role claim says otherwise, the role.
func (manager *Manager) reconcileUser(user model.User, claims oidc.Claims, autoGroups []string) (model.User, error) {
	current := user
	if !sameStrings(current.AutoGroups, autoGroups) {
		snapshot, err := manager.SubmitAs(
			model.StateTransition{
				Type: bft.TransitionUpdateUserGroups,
				User: &model.User{ID: current.ID, AutoGroups: autoGroups, LastLogin: time.Now().UTC().Format(time.RFC3339)},
			},
			claimsActor(claims, current.Role),
		)
		if err != nil {
			return model.User{}, err
		}
		if record := findUserRecord(snapshot.State, current.ID); record != nil {
			current = *record
		}
	}
	if role, ok := manager.sso.Config().ConfigRole(claims); ok && role != current.Role {
		snapshot, err := manager.SubmitAs(
			model.StateTransition{
				Type: bft.TransitionUpdateUserRole,
				User: &model.User{ID: current.ID, Role: role},
			},
			claimsActor(claims, role),
		)
		if err != nil {
			// The IdP role is advisory. A rejected change (for example, the
			// certified state refuses to demote the last owner) must not lock
			// the user out of the network.
			log.Printf("sso: keeping role %q for %s: %v", current.Role, current.ID, err)
		} else if record := findUserRecord(snapshot.State, current.ID); record != nil {
			current = *record
		}
	}
	return current, nil
}

// ensureClaimGroups maps IdP group names onto managed groups, creating a
// JWT-issued group the first time a name appears.
func (manager *Manager) ensureClaimGroups(state model.NetworkState, claimGroups []string, actor model.Actor) ([]string, error) {
	if !state.Settings.JWTGroupsEnabled {
		return []string{}, nil
	}
	names := dedupeStrings(claimGroups)
	ids := make([]string, 0, len(names))
	for _, name := range names {
		current := manager.engine.CurrentState()
		if group := groupByClaim(current, name); group != nil {
			ids = append(ids, group.ID)
			continue
		}
		group := model.Group{
			ID: uniqueGroupID(current, name), Name: name,
			Issued: model.GroupIssuedJWT, SSOClaim: name,
		}
		snapshot, err := manager.SubmitAs(
			model.StateTransition{Type: bft.TransitionUpsertGroup, Group: &group},
			actor,
		)
		if err != nil {
			return nil, err
		}
		if created := groupByClaim(snapshot.State, name); created != nil {
			ids = append(ids, created.ID)
		}
	}
	sort.Strings(ids)
	return ids, nil
}

// initialRole picks the role for a brand new user: an explicit IdP role wins,
// the very first user bootstraps as owner, everyone else is a plain user.
func (manager *Manager) initialRole(claims oidc.Claims, state model.NetworkState) string {
	// The first account to ever log in owns the network, so there is always an
	// owner capable of administering it.
	if len(state.Users) == 0 {
		return model.RoleOwner
	}
	if role, ok := manager.sso.Config().ConfigRole(claims); ok {
		return role
	}
	return model.RoleUser
}

// claimsActor renders IdP claims as the audit actor for user and group
// transitions. The role is the effective role where it is known; group
// synchronization happens before the user record exists, so it falls back to a
// descriptive label.
func claimsActor(claims oidc.Claims, role string) model.Actor {
	id := claims.Subject
	if id == "" {
		id = claims.Email
	}
	name := claims.Name
	if name == "" {
		name = claims.Email
	}
	if role == "" {
		role = "sso"
	}
	return model.Actor{ID: id, Name: name, Role: role}
}

// checkLoginExpiration enforces the certified login lifetime for SSO peers.
// A token issued after the recorded login means the client re-authenticated,
// which refreshes the window instead of expiring it.
func (manager *Manager) checkLoginExpiration(peerID string, claims oidc.Claims, now time.Time) (string, string) {
	state := manager.engine.CurrentState()
	days := state.Settings.LoginExpirationDays
	if days <= 0 {
		return "", ""
	}
	var peer *model.PeerRecord
	for index := range state.Peers {
		if state.Peers[index].PeerID == peerID {
			peer = &state.Peers[index]
			break
		}
	}
	// Setup-key peers and first-time SSO registrations never expire.
	if peer == nil || peer.UserID == "" || peer.LastLogin == "" {
		return "", ""
	}
	last, err := time.Parse(time.RFC3339, peer.LastLogin)
	if err != nil {
		return "", ""
	}
	if loginExpired(days, last, claims.IssuedAt, now) {
		return protocol.CodeLoginExpired, "login expired; re-authenticate"
	}
	return "", ""
}

// loginExpired decides whether a cached session has outlived the certified
// window. A token issued after the last recorded login means the client
// re-authenticated, which restarts the window.
func loginExpired(days int, lastLogin, issuedAt, now time.Time) bool {
	if days <= 0 {
		return false
	}
	if !issuedAt.IsZero() && issuedAt.After(lastLogin) {
		return false
	}
	return now.Sub(lastLogin) > time.Duration(days)*24*time.Hour
}

// shouldRefreshLogin reports whether a routine login should rewrite LastLogin.
func shouldRefreshLogin(lastLogin string) bool {
	if lastLogin == "" {
		return true
	}
	parsed, err := time.Parse(time.RFC3339, lastLogin)
	if err != nil {
		return true
	}
	return time.Since(parsed) > loginRefreshWindow
}

func findUserRecord(state model.NetworkState, id string) *model.User {
	for index := range state.Users {
		if state.Users[index].ID == id {
			return &state.Users[index]
		}
	}
	return nil
}

func groupByClaim(state model.NetworkState, claim string) *model.Group {
	for index := range state.Groups {
		if state.Groups[index].SSOClaim == claim {
			return &state.Groups[index]
		}
	}
	return nil
}

// uniqueGroupID derives a stable, collision-free ID from an IdP group name.
func uniqueGroupID(state model.NetworkState, claim string) string {
	base := "jwt-" + sanitizeGroupID(claim)
	if base == "jwt-" {
		base = "jwt-group"
	}
	candidate := base
	for suffix := 2; ; suffix++ {
		if !groupIDTaken(state, candidate) {
			return candidate
		}
		candidate = fmt.Sprintf("%s-%d", base, suffix)
	}
}

func groupIDTaken(state model.NetworkState, id string) bool {
	for index := range state.Groups {
		if state.Groups[index].ID == id {
			return true
		}
	}
	return false
}

func sanitizeGroupID(name string) string {
	var builder strings.Builder
	for _, char := range strings.ToLower(strings.TrimSpace(name)) {
		switch {
		case char >= 'a' && char <= 'z', char >= '0' && char <= '9', char == '-':
			builder.WriteRune(char)
		case char == '_' || char == ' ' || char == '.' || char == '/':
			builder.WriteRune('-')
		}
	}
	return strings.Trim(builder.String(), "-")
}

func dedupeStrings(values []string) []string {
	seen := make(map[string]struct{}, len(values))
	result := make([]string, 0, len(values))
	for _, value := range values {
		if value == "" {
			continue
		}
		if _, exists := seen[value]; exists {
			continue
		}
		seen[value] = struct{}{}
		result = append(result, value)
	}
	sort.Strings(result)
	return result
}

func sameStrings(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}
