package web

import (
	"net"
	"net/http"
	"sync"
	"time"
)

const (
	loginIPAttempts       = 30
	loginIdentityAttempts = loginMaxAttempts + 1
	loginRateWindow       = time.Minute
	maxLoginRateKeys      = 8192
)

type loginRateBucket struct {
	attempts []time.Time
	lastSeen time.Time
}

// loginRateLimiter bounds both email/password spraying from one source and
// repeated attempts against one account from that source. It does not trust
// proxy headers; the socket peer is the only network identity used.
type loginRateLimiter struct {
	mu      sync.Mutex
	buckets map[string]*loginRateBucket
}

func newLoginRateLimiter() *loginRateLimiter {
	return &loginRateLimiter{buckets: make(map[string]*loginRateBucket)}
}

func (limiter *loginRateLimiter) Allow(ip, identity string) bool {
	if ip == "" || identity == "" {
		return false
	}
	ipKey := "ip:" + ip
	identityKey := "identity:" + ip + "|" + identity
	now := time.Now()
	cutoff := now.Add(-loginRateWindow)

	limiter.mu.Lock()
	defer limiter.mu.Unlock()
	limiter.pruneLocked(cutoff)

	ipBucket := limiter.bucketLocked(ipKey, cutoff)
	identityBucket := limiter.bucketLocked(identityKey, cutoff)
	if len(ipBucket.attempts) >= loginIPAttempts || len(identityBucket.attempts) >= loginIdentityAttempts {
		ipBucket.lastSeen = now
		identityBucket.lastSeen = now
		return false
	}
	ipBucket.attempts = append(ipBucket.attempts, now)
	identityBucket.attempts = append(identityBucket.attempts, now)
	return true
}

func (limiter *loginRateLimiter) bucketLocked(key string, cutoff time.Time) *loginRateBucket {
	bucket := limiter.buckets[key]
	if bucket == nil {
		if len(limiter.buckets) >= maxLoginRateKeys {
			limiter.evictLeastRecentlyUsedLocked()
		}
		bucket = &loginRateBucket{}
		limiter.buckets[key] = bucket
	}
	bucket.lastSeen = time.Now()
	retained := bucket.attempts[:0]
	for _, attempt := range bucket.attempts {
		if attempt.After(cutoff) {
			retained = append(retained, attempt)
		}
	}
	bucket.attempts = retained
	return bucket
}

func (limiter *loginRateLimiter) pruneLocked(cutoff time.Time) {
	for key, bucket := range limiter.buckets {
		if bucket.lastSeen.Before(cutoff) {
			delete(limiter.buckets, key)
		}
	}
}

func (limiter *loginRateLimiter) evictLeastRecentlyUsedLocked() {
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

func loginClientIP(request *http.Request) string {
	if request == nil || request.RemoteAddr == "" {
		return "unknown"
	}
	if host, _, err := net.SplitHostPort(request.RemoteAddr); err == nil && host != "" {
		return host
	}
	return request.RemoteAddr
}
