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
)

func logf(format string, args ...any) {
	log.Printf(format, args...)
}
