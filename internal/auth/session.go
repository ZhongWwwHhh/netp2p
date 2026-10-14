package auth

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

const LocalSessionPrefix = "netp2p_local."

type SessionManager struct {
	key []byte
	ttl time.Duration
}

type localSession struct {
	SessionID string    `json:"sid"`
	Identity  Identity  `json:"identity"`
	IssuedAt  time.Time `json:"issuedAt"`
	ExpiresAt time.Time `json:"expiresAt"`
}

func NewSessionManager(secret string, ttl time.Duration) (*SessionManager, error) {
	if len(secret) < 32 {
		return nil, fmt.Errorf("session secret must be at least 32 bytes")
	}
	if ttl <= 0 {
		return nil, fmt.Errorf("session ttl must be positive")
	}
	return &SessionManager{key: []byte(secret), ttl: ttl}, nil
}

func (manager *SessionManager) TTL() time.Duration { return manager.ttl }

func (manager *SessionManager) Issue(identity Identity, now time.Time) (string, time.Time, error) {
	if manager == nil {
		return "", time.Time{}, fmt.Errorf("session manager is not configured")
	}
	buffer := make([]byte, 16)
	if _, err := rand.Read(buffer); err != nil {
		return "", time.Time{}, fmt.Errorf("read session id: %w", err)
	}
	expires := now.Add(manager.ttl).UTC()
	payload, err := json.Marshal(localSession{
		SessionID: base64.RawURLEncoding.EncodeToString(buffer),
		Identity:  identity, IssuedAt: now.UTC(), ExpiresAt: expires,
	})
	if err != nil {
		return "", time.Time{}, fmt.Errorf("encode session: %w", err)
	}
	encoded := base64.RawURLEncoding.EncodeToString(payload)
	return LocalSessionPrefix + encoded + "." + manager.sign(encoded), expires, nil
}

func (manager *SessionManager) Verify(token string, now time.Time) (Identity, error) {
	if manager == nil {
		return Identity{}, fmt.Errorf("session manager is not configured")
	}
	if !strings.HasPrefix(token, LocalSessionPrefix) {
		return Identity{}, fmt.Errorf("invalid session token")
	}
	encoded, signature, ok := strings.Cut(strings.TrimPrefix(token, LocalSessionPrefix), ".")
	if !ok || encoded == "" || signature == "" {
		return Identity{}, fmt.Errorf("malformed session token")
	}
	if !hmac.Equal([]byte(signature), []byte(manager.sign(encoded))) {
		return Identity{}, fmt.Errorf("invalid session signature")
	}
	payload, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil {
		return Identity{}, fmt.Errorf("decode session: %w", err)
	}
	var session localSession
	if err := json.Unmarshal(payload, &session); err != nil {
		return Identity{}, fmt.Errorf("decode session: %w", err)
	}
	if session.SessionID == "" || session.Identity.UserID == "" {
		return Identity{}, fmt.Errorf("invalid session subject")
	}
	if now.UTC().After(session.ExpiresAt) {
		return Identity{}, fmt.Errorf("session expired")
	}
	return session.Identity, nil
}

// SessionID returns the server-side identifier embedded in a valid signed
// local session. Web handlers persist this identifier and use it for logout and
// user-wide revocation.
func (manager *SessionManager) SessionID(token string) (string, error) {
	if manager == nil {
		return "", fmt.Errorf("session manager is not configured")
	}
	if !strings.HasPrefix(token, LocalSessionPrefix) {
		return "", fmt.Errorf("invalid session token")
	}
	encoded, signature, ok := strings.Cut(strings.TrimPrefix(token, LocalSessionPrefix), ".")
	if !ok || encoded == "" || signature == "" ||
		!hmac.Equal([]byte(signature), []byte(manager.sign(encoded))) {
		return "", fmt.Errorf("invalid session signature")
	}
	payload, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil {
		return "", fmt.Errorf("decode session token: %w", err)
	}
	var session localSession
	if err := json.Unmarshal(payload, &session); err != nil {
		return "", fmt.Errorf("decode session token: %w", err)
	}
	if session.SessionID == "" {
		return "", fmt.Errorf("session token has no session id")
	}
	return session.SessionID, nil
}

// ExternalSessionID derives a stable non-secret identifier for an externally
// issued bearer token. Only the hash is persisted.
func ExternalSessionID(token string) string {
	digest := sha256.Sum256([]byte(token))
	return "external-" + base64.RawURLEncoding.EncodeToString(digest[:])
}

// IssuedAt exposes the certified timestamp used by the web layer to invalidate
// sessions issued before a target user's credentials changed.
func (manager *SessionManager) IssuedAt(token string) (time.Time, error) {
	if manager == nil {
		return time.Time{}, fmt.Errorf("session manager is not configured")
	}
	if !strings.HasPrefix(token, LocalSessionPrefix) {
		return time.Time{}, fmt.Errorf("invalid session token")
	}
	encoded, signature, ok := strings.Cut(strings.TrimPrefix(token, LocalSessionPrefix), ".")
	if !ok || encoded == "" || signature == "" || !hmac.Equal([]byte(signature), []byte(manager.sign(encoded))) {
		return time.Time{}, fmt.Errorf("invalid session signature")
	}
	payload, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil {
		return time.Time{}, fmt.Errorf("decode session: %w", err)
	}
	var session localSession
	if err := json.Unmarshal(payload, &session); err != nil {
		return time.Time{}, fmt.Errorf("decode session: %w", err)
	}
	return session.IssuedAt, nil
}

func (manager *SessionManager) sign(encoded string) string {
	mac := hmac.New(sha256.New, manager.key)
	_, _ = mac.Write([]byte(encoded))
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}
