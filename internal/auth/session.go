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

func (manager *SessionManager) sign(encoded string) string {
	mac := hmac.New(sha256.New, manager.key)
	_, _ = mac.Write([]byte(encoded))
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}
