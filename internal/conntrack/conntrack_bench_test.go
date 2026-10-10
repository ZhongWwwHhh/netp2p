package conntrack

import (
	"net/netip"
	"testing"

	"github.com/netp2p/netp2p/internal/packet"
)

func benchmarkKeys(count int) []Key {
	keys := make([]Key, count)
	for index := range keys {
		keys[index] = Key{
			Protocol:        packet.ProtocolTCP,
			Source:          netip.AddrFrom4([4]byte{100, 64, byte(index >> 8), byte(index)}),
			Destination:     netip.AddrFrom4([4]byte{100, 64, 0, 250}),
			SourcePort:      uint16(30000 + index%20000),
			DestinationPort: 443,
		}
	}
	return keys
}

func BenchmarkConntrackObserve(b *testing.B) {
	table := NewTable()
	keys := benchmarkKeys(1024)
	b.ReportAllocs()
	b.ResetTimer()
	for index := 0; index < b.N; index++ {
		table.Observe(keys[index%len(keys)])
	}
}

func BenchmarkConntrackReplyAllowed(b *testing.B) {
	table := NewTable()
	keys := benchmarkKeys(1024)
	for _, key := range keys {
		table.Observe(key)
	}
	b.ReportAllocs()
	b.ResetTimer()
	for index := 0; index < b.N; index++ {
		if !table.ReplyAllowed(keys[index%len(keys)].Reverse()) {
			b.Fatal("expected established benchmark flow to be reversible")
		}
	}
}
