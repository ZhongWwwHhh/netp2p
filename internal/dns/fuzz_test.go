package dns

import (
	"math"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/netp2p/netp2p/internal/model"
)

type fuzzDNSWriter struct{}

func (writer *fuzzDNSWriter) LocalAddr() net.Addr         { return &net.UDPAddr{} }
func (writer *fuzzDNSWriter) RemoteAddr() net.Addr        { return &net.UDPAddr{} }
func (writer *fuzzDNSWriter) WriteMsg(_ *dns.Msg) error   { return nil }
func (writer *fuzzDNSWriter) Write(_ []byte) (int, error) { return 0, nil }
func (writer *fuzzDNSWriter) Close() error                { return nil }
func (writer *fuzzDNSWriter) TsigStatus() error           { return nil }
func (writer *fuzzDNSWriter) TsigTimersOnly(bool)         {}
func (writer *fuzzDNSWriter) Hijack()                     {}

func FuzzResolverHandle(f *testing.F) {
	valid := new(dns.Msg)
	valid.SetQuestion("peer.fuzz.invalid.", dns.TypeA)
	encoded, err := valid.Pack()
	if err != nil {
		f.Fatal(err)
	}
	f.Add(encoded)
	f.Add([]byte{0xff, 0xff, 0x01, 0x00, 0x00})
	f.Add([]byte{0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00})
	f.Add([]byte("\xff.example.\x00"))

	f.Fuzz(func(t *testing.T, data []byte) {
		request := new(dns.Msg)
		if err := request.Unpack(data); err != nil {
			return
		}
		resolver := NewResolver("127.0.0.1:0")
		resolver.Update(Config{
			Domain: "fuzz.invalid",
			Peers:  map[string]string{"peer": "100.64.0.1"},
			Zones: []model.DNSZone{{
				ID: "zone", Domain: "zone.fuzz.invalid", Enabled: true,
				Records: []model.DNSRecord{{Name: "host", Type: "A", Value: "not-an-ip", TTL: -1}},
			}},
		})
		resolver.handle(&fuzzDNSWriter{}, request)
	})
}

func TestResolverMalformedUDPStress(t *testing.T) {
	if testing.Short() {
		t.Skip("short mode skips the local UDP stress run")
	}
	resolver := NewResolver("127.0.0.1:0")
	resolver.Update(Config{Domain: "fuzz.invalid", Peers: map[string]string{"peer": "100.64.0.1"}})
	if err := resolver.ListenAndServe(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = resolver.Shutdown() })

	connection, err := net.DialTimeout("udp", resolver.ListenAddr(), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	if err := connection.SetDeadline(time.Now().Add(3 * time.Second)); err != nil {
		t.Fatal(err)
	}

	patterns := [][]byte{
		{0xff, 0xff, 0xff, 0xff},
		{0x00, 0x00, 0x01, 0x00, 0x00, 0xff, 0xff},
		[]byte("\x12\x34\x01\x00\x00\x01\x00\x00"),
		make([]byte, 512),
	}
	var writeErrors sync.Mutex
	var failures int
	var workers sync.WaitGroup
	for worker := 0; worker < 4; worker++ {
		workers.Add(1)
		go func(worker int) {
			defer workers.Done()
			for iteration := 0; iteration < 128; iteration++ {
				pattern := patterns[(worker+iteration)%len(patterns)]
				if _, err := connection.Write(pattern); err != nil {
					writeErrors.Lock()
					failures++
					writeErrors.Unlock()
					return
				}
			}
		}(worker)
	}
	workers.Wait()
	if failures != 0 {
		t.Fatalf("%d local UDP writes failed", failures)
	}

	query := new(dns.Msg)
	query.SetQuestion("peer.fuzz.invalid.", dns.TypeA)
	client := &dns.Client{Net: "udp", Timeout: 2 * time.Second}
	reply, _, err := client.Exchange(query, resolver.ListenAddr())
	if err != nil {
		t.Fatalf("resolver did not recover after malformed traffic: %v", err)
	}
	if reply.Rcode != dns.RcodeSuccess || len(reply.Answer) != 1 {
		t.Fatalf("post-stress reply = %+v", reply)
	}
}

func TestMaximumReplyTTLDoesNotOverflowCacheExpiry(t *testing.T) {
	resolver := NewResolver("127.0.0.1:0")
	request := new(dns.Msg)
	request.SetQuestion("overflow.fuzz.invalid.", dns.TypeA)
	reply := new(dns.Msg)
	reply.SetReply(request)
	reply.Answer = append(reply.Answer, &dns.A{
		Hdr: dns.RR_Header{Name: "overflow.fuzz.invalid.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: math.MaxUint32},
		A:   net.ParseIP("100.64.0.1").To4(),
	})
	resolver.storeCached(request, reply)
	if len(resolver.cache) != 1 {
		t.Fatalf("cache entries = %d, want one bounded entry", len(resolver.cache))
	}
	for _, entry := range resolver.cache {
		if maxExpiry := resolver.now().Add(maxDNSCacheTTL); entry.expiresAt.After(maxExpiry) {
			t.Fatalf("expiry %s is after bounded maximum %s", entry.expiresAt, maxExpiry)
		}
	}
}
