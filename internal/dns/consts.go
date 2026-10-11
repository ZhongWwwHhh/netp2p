package dns

import (
	"log"
	"time"
)

const (
	// defaultTTL applies to locally answered overlay records.
	defaultTTL = 30
	// dnsTimeout bounds a single upstream exchange.
	dnsTimeout = 3 * time.Second
	// maxDNSCacheTTL bounds upstream TTLs so a hostile reply cannot pin a
	// cache entry for an unreasonable period.
	maxDNSCacheTTL = 24 * time.Hour
)

func logf(format string, args ...any) {
	log.Printf(format, args...)
}
