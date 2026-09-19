// Package conntrack remembers outbound overlay flows so return traffic is
// admitted without a second, mirror-image policy rule.
//
// Without this a unidirectional allow policy could carry a TCP SYN but the
// SYN-ACK would be dropped, so no connection could ever complete. Policies stay
// one-way; established flows become implicitly reversible for a bounded time.
package conntrack

import (
	"net/netip"
	"sync"
	"time"

	"github.com/netp2p/netp2p/internal/packet"
)

const (
	tcpTimeout   = 5 * time.Minute
	udpTimeout   = 60 * time.Second
	icmpTimeout  = 30 * time.Second
	otherTimeout = 60 * time.Second
	defaultMax   = 65536
)

// Key identifies one direction of a flow.
type Key struct {
	Protocol        uint8
	Source          netip.Addr
	Destination     netip.Addr
	SourcePort      uint16
	DestinationPort uint16
}

// Reverse returns the key describing the same flow in the opposite direction.
func (key Key) Reverse() Key {
	return Key{
		Protocol:        key.Protocol,
		Source:          key.Destination,
		Destination:     key.Source,
		SourcePort:      key.DestinationPort,
		DestinationPort: key.SourcePort,
	}
}

type entry struct {
	expiresAt time.Time
}

// Table is a bounded, TTL-based flow table.
type Table struct {
	mu      sync.Mutex
	entries map[Key]entry
	now     func() time.Time
	max     int
}

func NewTable() *Table {
	return &Table{
		entries: make(map[Key]entry),
		now:     time.Now,
		max:     defaultMax,
	}
}

// Observe records an allowed outbound packet so its reply is admitted later.
func (table *Table) Observe(key Key) {
	now := table.now()
	table.mu.Lock()
	defer table.mu.Unlock()
	table.prune(now)
	if len(table.entries) >= table.max {
		// Refuse new flows rather than growing without bound; existing flows
		// keep refreshing so an active connection is never evicted.
		if _, exists := table.entries[key]; !exists {
			return
		}
	}
	table.entries[key] = entry{expiresAt: now.Add(timeoutFor(key.Protocol))}
}

// ReplyAllowed reports whether packetKey is the return direction of a flow seen
// outbound, refreshing the entry when it is.
func (table *Table) ReplyAllowed(packetKey Key) bool {
	now := table.now()
	reverse := packetKey.Reverse()
	table.mu.Lock()
	defer table.mu.Unlock()
	current, ok := table.entries[reverse]
	if !ok {
		return false
	}
	if now.After(current.expiresAt) {
		delete(table.entries, reverse)
		return false
	}
	table.entries[reverse] = entry{expiresAt: now.Add(timeoutFor(reverse.Protocol))}
	return true
}

// Len reports the number of live entries, pruning expired ones first.
func (table *Table) Len() int {
	now := table.now()
	table.mu.Lock()
	defer table.mu.Unlock()
	table.prune(now)
	return len(table.entries)
}

func (table *Table) prune(now time.Time) {
	for key, current := range table.entries {
		if now.After(current.expiresAt) {
			delete(table.entries, key)
		}
	}
}

func timeoutFor(protocol uint8) time.Duration {
	switch protocol {
	case packet.ProtocolTCP:
		return tcpTimeout
	case packet.ProtocolUDP:
		return udpTimeout
	case packet.ProtocolICMP:
		return icmpTimeout
	default:
		return otherTimeout
	}
}
