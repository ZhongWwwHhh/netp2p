// Package oidc verifies IdP-issued ID tokens and maps their claims onto the
// overlay's user, group and role model.
package oidc

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/netp2p/netp2p/internal/model"
)

// Config is the seed-provided OIDC configuration.
type Config struct {
	Issuer      string `json:"issuer"`
	ClientID    string `json:"clientId"`
	WebClientID string `json:"webClientId,omitempty"`
	// WebRedirectURI is the externally reachable console callback. It is
	// deliberately explicit so a reverse proxy cannot influence it with a
	// forged Host header.
	WebRedirectURI string `json:"webRedirectUri,omitempty"`
	// Audience overrides the token audience that must be present. It defaults
	// to ClientID.
	Audience string `json:"audience,omitempty"`
	// GroupsClaim names the claim holding IdP group names. Defaults to
	// "groups".
	GroupsClaim string `json:"groupsClaim,omitempty"`
	// RoleClaim names a claim that directly carries a NetP2P role.
	RoleClaim   string   `json:"roleClaim,omitempty"`
	AdminGroups []string `json:"adminGroups,omitempty"`
	AllowGroups []string `json:"allowGroups,omitempty"`
	Scopes      []string `json:"scopes,omitempty"`
}

// Enabled reports whether SSO is configured.
func (config Config) Enabled() bool {
	return strings.TrimSpace(config.Issuer) != "" && strings.TrimSpace(config.ClientID) != ""
}

func (config Config) groupsClaim() string {
	if strings.TrimSpace(config.GroupsClaim) != "" {
		return config.GroupsClaim
	}
	return "groups"
}

func (config Config) audience() string {
	if strings.TrimSpace(config.Audience) != "" {
		return config.Audience
	}
	return config.ClientID
}

// ScopesOrDefault returns the configured scopes, defaulting to openid profile
// email.
func (config Config) ScopesOrDefault() []string {
	if len(config.Scopes) > 0 {
		return append([]string(nil), config.Scopes...)
	}
	return []string{oidc.ScopeOpenID, "profile", "email"}
}

// Claims is the subset of an ID token the overlay cares about.
type Claims struct {
	Subject string   `json:"subject"`
	Email   string   `json:"email,omitempty"`
	Name    string   `json:"name,omitempty"`
	Groups  []string `json:"groups,omitempty"`
	Role    string   `json:"role,omitempty"`
	// IssuedAt is the token's iat. It lets the manager tell a fresh
	// re-authentication from a cached token without refresh-token plumbing.
	IssuedAt time.Time      `json:"issuedAt,omitempty"`
	Raw      map[string]any `json:"-"`
}

// Verifier validates ID tokens against an issuer's JWKS.
type Verifier struct {
	config      Config
	provider    *oidc.Provider
	verifier    *oidc.IDTokenVerifier
	webVerifier *oidc.IDTokenVerifier
}

// NewVerifier performs OIDC discovery and prepares token verification.
func NewVerifier(ctx context.Context, config Config) (*Verifier, error) {
	if !config.Enabled() {
		return nil, fmt.Errorf("oidc issuer and clientId are required")
	}
	provider, err := oidc.NewProvider(ctx, config.Issuer)
	if err != nil {
		return nil, fmt.Errorf("oidc discovery: %w", err)
	}
	verifier := &Verifier{
		config:   config,
		provider: provider,
		verifier: provider.Verifier(&oidc.Config{ClientID: config.audience()}),
	}
	// The console uses a separate public client, so its tokens carry a different
	// audience and need their own verifier.
	if web := strings.TrimSpace(config.WebClientID); web != "" && web != config.audience() {
		verifier.webVerifier = provider.Verifier(&oidc.Config{ClientID: web})
	}
	return verifier, nil
}

// NewVerifierWithRetry tolerates transient startup races, such as a container
// DNS record or IdP listener becoming available shortly after the manager.
func NewVerifierWithRetry(ctx context.Context, config Config, attempts int, interval time.Duration) (*Verifier, error) {
	if attempts < 1 {
		attempts = 1
	}
	if interval <= 0 {
		interval = time.Millisecond
	}
	var lastErr error
	for attempt := 1; attempt <= attempts; attempt++ {
		verifier, err := NewVerifier(ctx, config)
		if err == nil {
			return verifier, nil
		}
		lastErr = err
		if attempt == attempts {
			break
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(interval):
		}
	}
	return nil, fmt.Errorf("oidc discovery failed after %d attempts: %w", attempts, lastErr)
}

// Verify checks the token signature, issuer, audience and expiry, then extracts
// the claims the overlay uses.
func (verifier *Verifier) Verify(ctx context.Context, rawToken string) (Claims, error) {
	token, err := verifier.verifier.Verify(ctx, rawToken)
	if err != nil && verifier.webVerifier != nil {
		token, err = verifier.webVerifier.Verify(ctx, rawToken)
	}
	if err != nil {
		return Claims{}, err
	}
	raw := map[string]any{}
	if err := token.Claims(&raw); err != nil {
		return Claims{}, fmt.Errorf("decode claims: %w", err)
	}
	return claimsFromMap(token.Subject, raw, verifier.config), nil
}

// Endpoint exposes the provider's OAuth endpoints for the device flow and the
// browser PKCE flow.
func (verifier *Verifier) Endpoint() (authURL, tokenURL, deviceAuthURL string) {
	endpoint := verifier.provider.Endpoint()
	return endpoint.AuthURL, endpoint.TokenURL, endpoint.DeviceAuthURL
}

// Config returns the configuration the verifier was built with.
func (verifier *Verifier) Config() Config { return verifier.config }

func claimsFromMap(subject string, raw map[string]any, config Config) Claims {
	claims := Claims{
		Subject: subject,
		Groups:  ToGroups(raw[config.groupsClaim()]),
		Raw:     raw,
	}
	claims.Email, _ = raw["email"].(string)
	claims.Name, _ = raw["name"].(string)
	if claims.Name == "" {
		claims.Name, _ = raw["preferred_username"].(string)
	}
	if config.RoleClaim != "" {
		claims.Role, _ = raw[config.RoleClaim].(string)
	}
	if seconds, ok := raw["iat"].(float64); ok {
		claims.IssuedAt = time.Unix(int64(seconds), 0)
	}
	return claims
}

// ToGroups extracts a group list from a claim value. IdPs emit either a single
// string or an array of strings.
func ToGroups(value any) []string {
	switch typed := value.(type) {
	case string:
		if typed == "" {
			return nil
		}
		return []string{typed}
	case []string:
		return append([]string(nil), typed...)
	case []any:
		result := make([]string, 0, len(typed))
		for _, item := range typed {
			if text, ok := item.(string); ok && text != "" {
				result = append(result, text)
			}
		}
		return result
	}
	return nil
}

// ConfigRole is the role implied by the claims alone: an explicit role claim
// wins, then membership in an admin group.
func (config Config) ConfigRole(claims Claims) (string, bool) {
	if claims.Role != "" && modelRole(claims.Role) {
		return claims.Role, true
	}
	if containsAny(claims.Groups, config.AdminGroups) {
		return model.RoleAdmin, true
	}
	return "", false
}

// Allowed reports whether the claims satisfy the allow-list. An empty allow
// list admits everyone.
func (config Config) Allowed(claims Claims) bool {
	if len(config.AllowGroups) == 0 {
		return true
	}
	return containsAny(claims.Groups, config.AllowGroups)
}

func modelRole(role string) bool {
	switch role {
	case model.RoleOwner, model.RoleAdmin, model.RoleNetworkAdmin,
		model.RoleAuditor, model.RoleUsageViewer, model.RoleUser:
		return true
	}
	return false
}

func containsAny(values, wanted []string) bool {
	for _, candidate := range values {
		for _, target := range wanted {
			if candidate == target {
				return true
			}
		}
	}
	return false
}
