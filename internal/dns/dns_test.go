package dns

import (
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/miekg/dns"
	"github.com/netp2p/netp2p/internal/model"
)

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

func TestUnknownOverlayNameIsNotAnsweredAuthoritatively(t *testing.T) {
	_, address := startResolver(t, testConfig())
	reply := query(t, address, "missing.netp2p.internal", dns.TypeA)
	if len(reply.Answer) != 0 {
		t.Fatalf("answers = %v, want none", reply.Answer)
	}
	// With no upstream reachable the resolver must fail, not fabricate.
	if reply.Rcode != dns.RcodeServerFailure {
		t.Fatalf("rcode = %s, want SERVFAIL", dns.RcodeToString[reply.Rcode])
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
	content := "# comment\nnameserver 8.8.8.8\nsearch corp\nnameserver 1.1.1.1:5353\n; ignored\nnameserver\n"
	got := ParseNameservers(content)
	want := []string{"8.8.8.8:53", "1.1.1.1:5353"}
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
	original := "nameserver 8.8.8.8\n"
	if err := os.WriteFile(path, []byte(original), 0o644); err != nil {
		t.Fatal(err)
	}

	resolv, err := Takeover(path, "127.0.0.1:53", []string{"8.8.8.8:53"})
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
