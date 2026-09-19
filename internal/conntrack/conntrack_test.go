package conntrack

import (
	"net/netip"
	"testing"
	"time"

	"github.com/netp2p/netp2p/internal/packet"
)

func addr(value string) netip.Addr {
	return netip.MustParseAddr(value)
}

func TestReplyAllowedMatchesReverseFlow(t *testing.T) {
	table := NewTable()
	request := Key{
		Protocol: packet.ProtocolTCP,
		Source:   addr("100.64.0.1"), Destination: addr("100.64.0.2"),
		SourcePort: 51000, DestinationPort: 443,
	}
	table.Observe(request)

	reply := Key{
		Protocol: packet.ProtocolTCP,
		Source:   addr("100.64.0.2"), Destination: addr("100.64.0.1"),
		SourcePort: 443, DestinationPort: 51000,
	}
	if !table.ReplyAllowed(reply) {
		t.Fatal("reply of an observed flow must be allowed")
	}
	// The reverse direction of an unobserved flow stays blocked.
	other := Key{
		Protocol: packet.ProtocolTCP,
		Source:   addr("100.64.0.3"), Destination: addr("100.64.0.1"),
		SourcePort: 443, DestinationPort: 51000,
	}
	if table.ReplyAllowed(other) {
		t.Fatal("unrelated flow must not be admitted")
	}
	// The forward direction never matches its own reverse lookup.
	if table.ReplyAllowed(request) {
		t.Fatal("outbound key must not satisfy a reply check")
	}
}

func TestICMPIdentifierMatchesBothDirections(t *testing.T) {
	table := NewTable()
	// Both directions carry the echo identifier on both sides, so the reply
	// maps onto the request without a port swap.
	table.Observe(Key{
		Protocol: packet.ProtocolICMP,
		Source:   addr("100.64.0.1"), Destination: addr("100.64.0.2"),
		SourcePort: 0x1234, DestinationPort: 0x1234,
	})
	reply := Key{
		Protocol: packet.ProtocolICMP,
		Source:   addr("100.64.0.2"), Destination: addr("100.64.0.1"),
		SourcePort: 0x1234, DestinationPort: 0x1234,
	}
	if !table.ReplyAllowed(reply) {
		t.Fatal("echo reply must map onto the request")
	}
}

func TestEntryExpires(t *testing.T) {
	table := NewTable()
	now := time.Now()
	table.now = func() time.Time { return now }

	table.Observe(Key{Protocol: packet.ProtocolUDP, Source: addr("100.64.0.1"), Destination: addr("100.64.0.2")})
	if table.Len() != 1 {
		t.Fatalf("entries = %d, want 1", table.Len())
	}

	now = now.Add(udpTimeout + time.Second)
	if table.Len() != 0 {
		t.Fatalf("expired entry still present: %d", table.Len())
	}
	reply := Key{Protocol: packet.ProtocolUDP, Source: addr("100.64.0.2"), Destination: addr("100.64.0.1")}
	if table.ReplyAllowed(reply) {
		t.Fatal("expired flow must not admit a reply")
	}
}

func TestReplyRefreshesDeadline(t *testing.T) {
	table := NewTable()
	now := time.Now()
	table.now = func() time.Time { return now }

	request := Key{Protocol: packet.ProtocolUDP, Source: addr("100.64.0.1"), Destination: addr("100.64.0.2")}
	reply := request.Reverse()
	table.Observe(request)

	now = now.Add(udpTimeout - time.Second)
	if !table.ReplyAllowed(reply) {
		t.Fatal("flow should still be live")
	}
	// Refreshed by the reply, so it survives past the original deadline.
	now = now.Add(2 * time.Second)
	if table.Len() != 1 {
		t.Fatal("reply did not refresh the flow")
	}
}

func TestObserveIsBounded(t *testing.T) {
	table := NewTable()
	table.max = 4
	for index := 0; index < 64; index++ {
		table.Observe(Key{
			Protocol: packet.ProtocolTCP,
			Source:   addr("100.64.0.1"), Destination: addr("100.64.0.2"),
			SourcePort: uint16(1000 + index),
		})
	}
	if table.Len() > 4 {
		t.Fatalf("table grew past its bound: %d", table.Len())
	}
}

func TestActiveFlowSurvivesAtCapacity(t *testing.T) {
	table := NewTable()
	table.max = 1
	request := Key{Protocol: packet.ProtocolTCP, Source: addr("100.64.0.1"), Destination: addr("100.64.0.2"), SourcePort: 1234}
	table.Observe(request)
	table.Observe(request)
	if !table.ReplyAllowed(request.Reverse()) {
		t.Fatal("existing flow was evicted by the capacity guard")
	}
}
