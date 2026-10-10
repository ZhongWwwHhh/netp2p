package dns

import (
	"testing"
	"time"

	"github.com/miekg/dns"
)

func BenchmarkDNSOverlayQuery(b *testing.B) {
	resolver := NewResolver("127.0.0.1:0")
	if err := resolver.ListenAndServe(); err != nil {
		b.Fatal(err)
	}
	b.Cleanup(func() { _ = resolver.Shutdown() })
	resolver.Update(Config{
		Domain: "netp2p.test",
		Peers:  map[string]string{"peer": "100.64.0.10"},
	})
	client := &dns.Client{Net: "udp", Timeout: time.Second}
	message := new(dns.Msg)
	message.SetQuestion("peer.netp2p.test.", dns.TypeA)
	b.ReportAllocs()
	b.ResetTimer()
	for index := 0; index < b.N; index++ {
		reply, _, err := client.Exchange(message, resolver.ListenAddr())
		if err != nil {
			b.Fatal(err)
		}
		if reply.Rcode != dns.RcodeSuccess || len(reply.Answer) != 1 {
			b.Fatalf("unexpected DNS reply: code=%d answers=%d", reply.Rcode, len(reply.Answer))
		}
	}
}
