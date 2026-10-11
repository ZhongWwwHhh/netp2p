package dns

import (
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/miekg/dns"
	"github.com/netp2p/netp2p/internal/metrics"
	"github.com/netp2p/netp2p/internal/model"
	"github.com/prometheus/client_golang/prometheus"
)

func counterValue(t *testing.T, collector prometheus.Collector) float64 {
	t.Helper()
	registry := prometheus.NewRegistry()
	registry.MustRegister(collector)
	families, err := registry.Gather()
	if err != nil {
		t.Fatalf("gather metric: %v", err)
	}
	if len(families) == 0 || len(families[0].Metric) == 0 {
		t.Fatal("metric produced no samples")
	}
	if counter := families[0].Metric[0].GetCounter(); counter != nil {
		return counter.GetValue()
	}
	t.Fatalf("metric is not a counter: %v", families[0].GetType())
	return 0
}

func testConfig() Config {
	return Config{
		Domain: "netp2p.internal",
		Peers:  map[string]string{"alpha": "100.64.0.1", "beta": "100.64.0.2"},
		Zones: []model.DNSZone{{
			ID: "zone-1", Domain: "internal.example", Enabled: true,
			Records: []model.DNSRecord{{Name: "db", Type: "A", Value: "100.64.0.9"}},
		}},
	}
}

// startResolver runs a resolver on an ephemeral port and returns its address.
func startResolver(t *testing.T, config Config) (*Resolver, string) {
	t.Helper()
	resolver := NewResolver("127.0.0.1:0")
	resolver.Update(config)
	if err := resolver.ListenAndServe(); err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = resolver.Shutdown() })
	return resolver, resolver.ListenAddr()
}

func query(t *testing.T, address, name string, qtype uint16) *dns.Msg {
	t.Helper()
	message := new(dns.Msg)
	message.SetQuestion(dns.Fqdn(name), qtype)
	client := &dns.Client{Net: "udp"}
	reply, _, err := client.Exchange(message, address)
	if err != nil {
		t.Fatalf("query %s: %v", name, err)
	}
	return reply
}

func TestResolvesPeerNamesInOverlayDomain(t *testing.T) {
	_, address := startResolver(t, testConfig())
	reply := query(t, address, "alpha.netp2p.internal", dns.TypeA)
	if len(reply.Answer) != 1 {
		t.Fatalf("answers = %v, want one A record", reply.Answer)
	}
	record, ok := reply.Answer[0].(*dns.A)
	if !ok {
		t.Fatalf("answer type %T, want *dns.A", reply.Answer[0])
	}
	if record.A.String() != "100.64.0.1" {
		t.Fatalf("address = %s, want 100.64.0.1", record.A)
	}
	if !reply.Authoritative {
		t.Fatal("overlay answers must be authoritative")
	}
}

func TestResolvesCertifiedZoneRecords(t *testing.T) {
	_, address := startResolver(t, testConfig())
	reply := query(t, address, "db.internal.example", dns.TypeA)
	if len(reply.Answer) != 1 {
		t.Fatalf("answers = %v, want one A record", reply.Answer)
	}
	if record, ok := reply.Answer[0].(*dns.A); !ok || record.A.String() != "100.64.0.9" {
		t.Fatalf("answer = %v, want 100.64.0.9", reply.Answer[0])
	}
}

func TestUnknownOverlayNameReturnsNXDOMAIN(t *testing.T) {
	_, address := startResolver(t, testConfig())
	reply := query(t, address, "missing.netp2p.internal", dns.TypeA)
	if len(reply.Answer) != 0 {
		t.Fatalf("answers = %v, want none", reply.Answer)
	}
	if reply.Rcode != dns.RcodeNameError {
		t.Fatalf("rcode = %s, want NXDOMAIN", dns.RcodeToString[reply.Rcode])
	}
}

func TestDisabledSkipsOverlayAnswers(t *testing.T) {
	config := testConfig()
	config.Disabled = true
	_, address := startResolver(t, config)
	reply := query(t, address, "alpha.netp2p.internal", dns.TypeA)
	if len(reply.Answer) != 0 {
		t.Fatalf("answers = %v, want none when disabled", reply.Answer)
	}
}

func TestDNSFailuresAreCounted(t *testing.T) {
	collector := metrics.New()
	resolver := NewResolverWithMetrics("127.0.0.1:0", collector)
	resolver.Update(Config{})

	request := message("example.com")
	response := new(dns.Msg)
	response.SetReply(request)
	writer := &captureDNSWriter{}
	resolver.forwardOrFail(writer, request, response, resolver.snapshot())

	if writer.reply == nil {
		t.Fatal("resolver did not write a reply")
	}
	if writer.reply.Rcode != dns.RcodeServerFailure {
		t.Fatalf("rcode = %s, want SERVFAIL", dns.RcodeToString[writer.reply.Rcode])
	}
	if resolver.Failures() != 1 {
		t.Fatalf("failures = %d, want 1", resolver.Failures())
	}
	if got := counterValue(t, collector.DNSFailures); got != 1 {
		t.Fatalf("dns failure metric = %v, want 1", got)
	}
}

type captureDNSWriter struct {
	reply *dns.Msg
}

func (writer *captureDNSWriter) LocalAddr() net.Addr  { return &net.UDPAddr{} }
func (writer *captureDNSWriter) RemoteAddr() net.Addr { return &net.UDPAddr{} }
func (writer *captureDNSWriter) WriteMsg(reply *dns.Msg) error {
	writer.reply = reply
	return nil
}
func (writer *captureDNSWriter) Write([]byte) (int, error) { return 0, nil }
func (writer *captureDNSWriter) Close() error              { return nil }
func (writer *captureDNSWriter) TsigStatus() error         { return nil }
func (writer *captureDNSWriter) TsigTimersOnly(bool)       {}
func (writer *captureDNSWriter) Hijack()                   {}

func TestForwardsToCertifiedNameserver(t *testing.T) {
	upstream := startUpstream(t, "192.0.2.55")
	config := testConfig()
	config.Nameservers = []model.Nameserver{{
		ID: "ns-1", Enabled: true, MatchDomains: []string{"corp.example"},
		Servers: []string{upstream},
	}}
	_, address := startResolver(t, config)

	reply := query(t, address, "host.corp.example", dns.TypeA)
	if len(reply.Answer) != 1 {
		t.Fatalf("answers = %v, want the forwarded record", reply.Answer)
	}
	if record, ok := reply.Answer[0].(*dns.A); !ok || record.A.String() != "192.0.2.55" {
		t.Fatalf("answer = %v, want 192.0.2.55", reply.Answer[0])
	}
}

func TestResolverServesTCPClients(t *testing.T) {
	_, address := startResolver(t, testConfig())
	client := &dns.Client{Net: "tcp"}
	request := message("alpha.netp2p.internal")
	reply, _, err := client.Exchange(request, address)
	if err != nil {
		t.Fatalf("tcp query: %v", err)
	}
	if len(reply.Answer) != 1 {
		t.Fatalf("tcp answers = %v, want one A record", reply.Answer)
	}
}

func TestDNSTCPFallbackForTruncatedUpstream(t *testing.T) {
	upstream := startTruncatingUpstream(t, "192.0.2.88")
	config := testConfig()
	config.Nameservers = []model.Nameserver{{
		ID: "ns-1", Enabled: true, Servers: []string{upstream},
	}}
	_, address := startResolver(t, config)

	reply := query(t, address, "large.corp.example", dns.TypeA)
	if reply.Truncated {
		t.Fatal("resolver returned a truncated reply instead of using TCP")
	}
	if len(reply.Answer) != 1 {
		t.Fatalf("answers = %v, want the TCP upstream record", reply.Answer)
	}
	if record, ok := reply.Answer[0].(*dns.A); !ok || record.A.String() != "192.0.2.88" {
		t.Fatalf("answer = %v, want 192.0.2.88", reply.Answer[0])
	}
}

func TestDNSUsesEDNSAndCache(t *testing.T) {
	upstream := startCountingUpstream(t, "192.0.2.99")
	config := testConfig()
	config.Nameservers = []model.Nameserver{{
		ID: "ns-1", Enabled: true, Servers: []string{upstream.address},
	}}
	_, address := startResolver(t, config)

	request := message("cached.corp.example")
	request.SetEdns0(4096, false)
	client := &dns.Client{Net: "udp"}
	first, _, err := client.Exchange(request, address)
	if err != nil {
		t.Fatalf("first query: %v", err)
	}
	if opt := first.IsEdns0(); opt == nil || opt.UDPSize() != ednsUDPSize {
		t.Fatalf("first reply EDNS = %v, want UDP size %d", first.IsEdns0(), ednsUDPSize)
	}
	second, _, err := client.Exchange(request, address)
	if err != nil {
		t.Fatalf("second query: %v", err)
	}
	if len(second.Answer) != 1 {
		t.Fatalf("cached answers = %v", second.Answer)
	}
	if upstream.queries.Load() != 1 {
		t.Fatalf("upstream queries = %d, want one cache miss", upstream.queries.Load())
	}
}

func TestUpstreamsHonourMatchDomains(t *testing.T) {
	resolver := NewResolver("127.0.0.1:0")
	config := Config{
		Nameservers: []model.Nameserver{
			{ID: "scoped", Enabled: true, MatchDomains: []string{"corp.example"}, Servers: []string{"10.0.0.1"}},
			{ID: "general", Enabled: true, Servers: []string{"10.0.0.2"}},
			{ID: "disabled", Enabled: false, Servers: []string{"10.0.0.3"}},
		},
		Upstreams: []string{"10.0.0.9"},
	}

	scoped := resolver.upstreamsFor(config, message("host.corp.example"))
	if len(scoped) != 3 || scoped[0] != "10.0.0.1:53" || scoped[1] != "10.0.0.2:53" || scoped[2] != "10.0.0.9:53" {
		t.Fatalf("scoped upstreams = %v", scoped)
	}
	other := resolver.upstreamsFor(config, message("host.other.example"))
	if len(other) != 2 || other[0] != "10.0.0.2:53" {
		t.Fatalf("other upstreams = %v", other)
	}
}

func message(name string) *dns.Msg {
	request := new(dns.Msg)
	request.SetQuestion(dns.Fqdn(name), dns.TypeA)
	return request
}

func TestPeerLabelsPreferAssignedAndDeduplicate(t *testing.T) {
	state := model.NetworkState{
		Peers: []model.PeerRecord{
			{PeerID: "a", OverlayIP: "100.64.0.1", DNSLabel: "alpha"},
			{PeerID: "b", OverlayIP: "100.64.0.2", Hostname: "alpha"},
			{PeerID: "c", OverlayIP: "100.64.0.3", Hostname: "Web-01.corp.example"},
			{PeerID: "d", OverlayIP: ""},
		},
	}
	labels := PeerLabels(state)
	if labels["alpha"] != "100.64.0.1" {
		t.Fatalf("assigned label lost: %v", labels)
	}
	if labels["alpha-2"] != "100.64.0.2" {
		t.Fatalf("collision not resolved: %v", labels)
	}
	if labels["web-01"] != "100.64.0.3" {
		t.Fatalf("hostname not sanitized: %v", labels)
	}
	if len(labels) != 3 {
		t.Fatalf("labels = %v, want 3 entries", labels)
	}
}

func TestSanitizeLabel(t *testing.T) {
	cases := map[string]string{
		"web-01.corp.example":   "web-01",
		"WEB_02":                "web-02",
		"my host":               "my-host",
		"---":                   "",
		"":                      "",
		strings.Repeat("a", 80): strings.Repeat("a", 63),
	}
	for input, want := range cases {
		if got := SanitizeLabel(input); got != want {
			t.Fatalf("SanitizeLabel(%q) = %q, want %q", input, got, want)
		}
	}
}

func TestParseNameservers(t *testing.T) {
	content := "# comment\nnameserver 203.0.113.53\nsearch corp\nnameserver 198.51.100.53:5353\n; ignored\nnameserver\n"
	got := ParseNameservers(content)
	want := []string{"203.0.113.53:53", "198.51.100.53:5353"}
	if len(got) != len(want) {
		t.Fatalf("nameservers = %v, want %v", got, want)
	}
	for index := range want {
		if got[index] != want[index] {
			t.Fatalf("nameservers = %v, want %v", got, want)
		}
	}
}

func TestTakeoverAndRestore(t *testing.T) {
	path := filepath.Join(t.TempDir(), "resolv.conf")
	original := "nameserver 203.0.113.53\n"
	if err := os.WriteFile(path, []byte(original), 0o644); err != nil {
		t.Fatal(err)
	}

	resolv, err := Takeover(path, "127.0.0.1:53", []string{"203.0.113.53:53"})
	if err != nil {
		t.Fatalf("takeover: %v", err)
	}
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(content), "nameserver 127.0.0.1") {
		t.Fatalf("resolv.conf = %q, want the local resolver", content)
	}
	if backup, err := os.ReadFile(resolv.BackupPath()); err != nil || string(backup) != original {
		t.Fatalf("backup = %q err = %v", backup, err)
	}

	if err := resolv.Restore(); err != nil {
		t.Fatalf("restore: %v", err)
	}
	restored, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(restored) != original {
		t.Fatalf("restored = %q, want %q", restored, original)
	}
	// Restoring twice must not fail.
	if err := resolv.Restore(); err != nil {
		t.Fatalf("second restore: %v", err)
	}
}

func TestTakeoverRejectsNonStandardPort(t *testing.T) {
	path := filepath.Join(t.TempDir(), "resolv.conf")
	if _, err := Takeover(path, "127.0.0.1:5353", nil); err == nil {
		t.Fatal("takeover must be refused when the resolver is not on port 53")
	}
}

// A restart of a host whose resolv.conf was already taken over must recover the
// real upstreams from the backup instead of forwarding to itself.
func TestRestartAfterTakeoverKeepsRealUpstreams(t *testing.T) {
	path := filepath.Join(t.TempDir(), "resolv.conf")
	original := "nameserver 127.0.0.11\n"
	if err := os.WriteFile(path, []byte(original), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := Takeover(path, "127.0.0.1:53", []string{"127.0.0.11:53"}); err != nil {
		t.Fatalf("first takeover: %v", err)
	}
	// Simulate a restart before Restore: the live file still points to us.
	if upstreams := HostUpstreams(path); len(upstreams) != 1 || upstreams[0] != "127.0.0.11:53" {
		t.Fatalf("upstreams after restart = %v, want the original resolver", upstreams)
	}
	second, err := Takeover(path, "127.0.0.1:53", HostUpstreams(path))
	if err != nil {
		t.Fatalf("second takeover: %v", err)
	}
	if err := second.Restore(); err != nil {
		t.Fatalf("restore: %v", err)
	}
	restored, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(restored) != original {
		t.Fatalf("restored = %q, want %q", restored, original)
	}
}

// startUpstream runs a stub DNS server answering every A query with address.
func startUpstream(t *testing.T, answer string) string {
	t.Helper()
	packetConn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	mux := dns.NewServeMux()
	mux.HandleFunc(".", func(writer dns.ResponseWriter, request *dns.Msg) {
		response := new(dns.Msg)
		response.SetReply(request)
		for _, question := range request.Question {
			if question.Qtype == dns.TypeA {
				response.Answer = append(response.Answer, &dns.A{
					Hdr: dns.RR_Header{Name: question.Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 30},
					A:   net.ParseIP(answer).To4(),
				})
			}
		}
		_ = writer.WriteMsg(response)
	})
	server := &dns.Server{PacketConn: packetConn, Handler: mux}
	go func() { _ = server.ActivateAndServe() }()
	t.Cleanup(func() { _ = server.Shutdown() })
	return packetConn.LocalAddr().String()
}

type countingUpstream struct {
	address string
	queries atomic.Uint64
}

func startCountingUpstream(t *testing.T, answer string) *countingUpstream {
	t.Helper()
	upstream := &countingUpstream{}
	upstream.address = startUpstreamHandler(t, answer, func(_ *dns.Msg, viaTCP bool) {
		if viaTCP {
			upstream.queries.Add(1)
		}
	})
	return upstream
}

func startTruncatingUpstream(t *testing.T, answer string) string {
	t.Helper()
	return startUpstreamHandler(t, answer, func(request *dns.Msg, _ bool) {
		if request.IsEdns0() == nil {
			t.Error("upstream request did not use EDNS0")
		}
	})
}

func startUpstreamHandler(t *testing.T, answer string, onRequest func(*dns.Msg, bool)) string {
	t.Helper()
	tcpListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen upstream tcp: %v", err)
	}
	packetConn, err := net.ListenPacket("udp", tcpListener.Addr().String())
	if err != nil {
		_ = packetConn.Close()
		_ = tcpListener.Close()
		t.Fatalf("listen upstream udp: %v", err)
	}
	mux := dns.NewServeMux()
	mux.HandleFunc(".", func(writer dns.ResponseWriter, request *dns.Msg) {
		_, viaTCP := writer.RemoteAddr().(*net.TCPAddr)
		onRequest(request, viaTCP)
		response := new(dns.Msg)
		response.SetReply(request)
		if _, isTCP := writer.RemoteAddr().(*net.TCPAddr); !isTCP {
			response.Truncated = true
			_ = writer.WriteMsg(response)
			return
		}
		if request.IsEdns0() != nil {
			response.SetEdns0(ednsUDPSize, false)
		}
		for _, question := range request.Question {
			if question.Qtype == dns.TypeA {
				response.Answer = append(response.Answer, &dns.A{
					Hdr: dns.RR_Header{Name: question.Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 30},
					A:   net.ParseIP(answer).To4(),
				})
			}
		}
		_ = writer.WriteMsg(response)
	})
	udpServer := &dns.Server{PacketConn: packetConn, Handler: mux}
	tcpServer := &dns.Server{Listener: tcpListener, Handler: mux}
	go func() { _ = udpServer.ActivateAndServe() }()
	go func() { _ = tcpServer.ActivateAndServe() }()
	t.Cleanup(func() {
		_ = udpServer.Shutdown()
		_ = tcpServer.Shutdown()
	})
	return packetConn.LocalAddr().String()
}
