package manager

import (
	"sync"
	"time"

	"github.com/libp2p/go-libp2p/core/peer"
	ma "github.com/multiformats/go-multiaddr"
)

const (
	tokenRateWindow       = time.Minute
	setupKeyTokenAttempts = 5
	adminTokenAttempts    = 30
	managerJoinAttempts   = 30
	maxTokenRateKeys      = 4096
)

type tokenRateBucket struct {
	attempts []time.Time
	lastSeen time.Time
}

// tokenRateLimiter bounds expensive verifier attempts by the authenticated
// libp2p peer identity. Its key set is capped, so hostile peer IDs cannot grow
// manager memory without bound.
type tokenRateLimiter struct {
	mu      sync.Mutex
	buckets map[string]*tokenRateBucket
}

func newTokenRateLimiter() *tokenRateLimiter {
	return &tokenRateLimiter{buckets: make(map[string]*tokenRateBucket)}
}

// tokenRateKey combines the authenticated libp2p peer with its transport
// address. Peer identity remains authoritative, while the address component
// prevents one peer from spreading its attempt budget across advertised paths.
func tokenRateKey(remote peer.ID, address ma.Multiaddr) string {
	peerID := remote.String()
	if address == nil {
		return peerID
	}
	for _, component := range ma.Split(address) {
		code := component.Protocol().Code
		switch code {
		case ma.P_IP4, ma.P_IP6, ma.P_DNS, ma.P_DNS4, ma.P_DNS6:
			host, err := component.ValueForProtocol(code)
			if err == nil && host != "" {
				return peerID + "|" + host
			}
		}
	}
	return peerID
}

func (limiter *tokenRateLimiter) Allow(peerID string, limit int) bool {
	if peerID == "" || limit <= 0 {
		return false
	}
	now := time.Now()
	cutoff := now.Add(-tokenRateWindow)

	limiter.mu.Lock()
	defer limiter.mu.Unlock()

	bucket := limiter.buckets[peerID]
	if bucket == nil {
		if len(limiter.buckets) >= maxTokenRateKeys {
			limiter.pruneLocked(cutoff)
		}
		if len(limiter.buckets) >= maxTokenRateKeys {
			limiter.evictLeastRecentlyUsedLocked()
		}
		bucket = &tokenRateBucket{}
		limiter.buckets[peerID] = bucket
	}
	bucket.lastSeen = now

	retained := bucket.attempts[:0]
	for _, attempt := range bucket.attempts {
		if attempt.After(cutoff) {
			retained = append(retained, attempt)
		}
	}
	retained = append(retained, now)
	bucket.attempts = retained
	return len(bucket.attempts) <= limit
}

func (limiter *tokenRateLimiter) pruneLocked(cutoff time.Time) {
	for key, bucket := range limiter.buckets {
		if bucket.lastSeen.Before(cutoff) {
			delete(limiter.buckets, key)
		}
	}
}

func (limiter *tokenRateLimiter) evictLeastRecentlyUsedLocked() {
	var oldestKey string
	var oldest time.Time
	for key, bucket := range limiter.buckets {
		if oldestKey == "" || bucket.lastSeen.Before(oldest) {
			oldestKey, oldest = key, bucket.lastSeen
		}
	}
	if oldestKey != "" {
		delete(limiter.buckets, oldestKey)
	}
}
