// Package dns serves the overlay's own name space and forwards everything else
// to certified resolvers.
//
// Peer names and certified zones are authoritative and answered locally. Any
// other query is forwarded to the nameservers the certified state assigns to
// this peer, falling back to whatever resolver the host used before the overlay
// took over /etc/resolv.conf.
package dns

import (
	"context"
	"fmt"
	"net"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/miekg/dns"
	"github.com/netp2p/netp2p/internal/metrics"
	"github.com/netp2p/netp2p/internal/model"
	"github.com/netp2p/netp2p/internal/tracing"
	"go.opentelemetry.io/otel"
)

const (
	ednsUDPSize        = 1232
	maxDNSCacheEntries = 1024
)

// Config is the certified subset the resolver needs.
type Config struct {
	Domain      string
	Peers       map[string]string // dns label -> overlay IP
	Zones       []model.DNSZone
	Nameservers []model.Nameserver
	// Disabled turns off overlay handling entirely for this peer.
	Disabled bool
	// Upstreams are used when no certified nameserver matches a query.
	Upstreams []string
}

// Resolver answers DNS queries using the most recent certified configuration.
type Resolver struct {
	mu       sync.RWMutex
	config   Config
	servers  []*dns.Server
	udp      *dns.Client
	tcp      *dns.Client
	listen   string
	bound    string
	started  bool
	localIPs map[string]struct{}
	cache    map[dnsCacheKey]dnsCacheEntry
	now      func() time.Time
	metrics  *metrics.Metrics
	failures atomic.Uint64
}

type dnsCacheKey struct {
	question dns.Question
	dnssec   bool
}

type dnsCacheEntry struct {
	reply     *dns.Msg
	expiresAt time.Time
}

func NewResolver(listen string) *Resolver {
	return NewResolverWithMetrics(listen, nil)
}

func NewResolverWithMetrics(listen string, collector *metrics.Metrics) *Resolver {
	return &Resolver{
		listen:  listen,
		udp:     &dns.Client{Net: "udp", Timeout: dnsTimeout, UDPSize: ednsUDPSize},
		tcp:     &dns.Client{Net: "tcp", Timeout: dnsTimeout},
		cache:   make(map[dnsCacheKey]dnsCacheEntry),
		now:     time.Now,
		metrics: collector,
	}
}

// Update swaps in a new certified configuration.
func (resolver *Resolver) Update(config Config) {
	resolver.mu.Lock()
	resolver.config = config
	resolver.cache = make(map[dnsCacheKey]dnsCacheEntry)
	resolver.mu.Unlock()
}

// ListenAddr returns the address the resolver bound to.
func (resolver *Resolver) ListenAddr() string {
	resolver.mu.RLock()
	defer resolver.mu.RUnlock()
	if resolver.bound != "" {
		return resolver.bound
	}
	return resolver.listen
}

// ListenAndServe starts the resolver. It returns after the listener is
// established so a bind failure is reported to the caller instead of being
// buried in a goroutine.
func (resolver *Resolver) ListenAndServe() error {
	resolver.mu.Lock()
	if resolver.started {
		resolver.mu.Unlock()
		return fmt.Errorf("dns resolver already started")
	}
	resolver.started = true
	resolver.mu.Unlock()

	mux := dns.NewServeMux()
	mux.HandleFunc(".", resolver.handle)

	packetConn, err := net.ListenPacket("udp", resolver.listen)
	if err != nil {
		return fmt.Errorf("listen dns %s: %w", resolver.listen, err)
	}
	// UDP and TCP must use the same port so a truncated UDP reply can be
	// retried by the stub resolver over TCP.
	tcpListener, err := net.Listen("tcp", packetConn.LocalAddr().String())
	if err != nil {
		_ = packetConn.Close()
		return fmt.Errorf("listen dns tcp %s: %w", packetConn.LocalAddr().String(), err)
	}
	udpServer := &dns.Server{PacketConn: packetConn, Handler: mux}
	tcpServer := &dns.Server{Listener: tcpListener, Handler: mux}
	resolver.mu.Lock()
	resolver.servers = []*dns.Server{udpServer, tcpServer}
	resolver.bound = packetConn.LocalAddr().String()
	resolver.mu.Unlock()
	go func() {
		if serveErr := udpServer.ActivateAndServe(); serveErr != nil {
			// A closed listener during shutdown is not an error worth surfacing.
			if !strings.Contains(serveErr.Error(), "closed") {
				logf("dns server stopped: %v", serveErr)
			}
		}
	}()
	go func() {
		if serveErr := tcpServer.ActivateAndServe(); serveErr != nil {
			if !strings.Contains(serveErr.Error(), "closed") {
				logf("dns tcp server stopped: %v", serveErr)
			}
		}
	}()
	return nil
}

func (resolver *Resolver) Shutdown() error {
	resolver.mu.Lock()
	servers := append([]*dns.Server(nil), resolver.servers...)
	resolver.mu.Unlock()
	if len(servers) == 0 {
		return nil
	}
	var firstError error
	for _, server := range servers {
		if err := server.Shutdown(); err != nil && firstError == nil {
			firstError = err
		}
	}
	return firstError
}

func (resolver *Resolver) handle(writer dns.ResponseWriter, request *dns.Msg) {
	if tracing.Enabled() {
		_, span := otel.Tracer("netp2p").Start(context.Background(), "dns.resolve")
		defer span.End()
	}
	response := new(dns.Msg)
	response.SetReply(request)
	response.Authoritative = true
	if opt := request.IsEdns0(); opt != nil {
		response.SetEdns0(ednsUDPSize, opt.Do())
	}

	config := resolver.snapshot()
	if config.Disabled {
		resolver.forwardOrFail(writer, request, response, config)
		return
	}

	overlayQuestion := false
	handled := 0
	for _, question := range request.Question {
		if question.Qtype == dns.TypeA || question.Qtype == dns.TypeAAAA {
			if isOverlayName(config, question.Name) {
				overlayQuestion = true
			}
			if address, ok := resolver.lookupOverlay(config, question.Name); ok {
				appendAddress(response, question, address)
				handled++
			}
		}
	}
	if overlayQuestion {
		if handled != len(request.Question) {
			response.Rcode = dns.RcodeNameError
			resolver.storeCached(request, response)
		}
		_ = writer.WriteMsg(response)
		return
	}
	resolver.forwardOrFail(writer, request, response, config)
}

// lookupOverlay resolves a name inside the overlay domain: certified zone
// records first, then automatically registered peer names.
func (resolver *Resolver) lookupOverlay(config Config, name string) (string, bool) {
	trimmed := strings.TrimSuffix(strings.ToLower(name), ".")
	if trimmed == "" {
		return "", false
	}
	for _, zone := range config.Zones {
		if !zone.Enabled || zone.Domain == "" {
			continue
		}
		domain := strings.TrimSuffix(strings.ToLower(zone.Domain), ".")
		if trimmed != domain && !strings.HasSuffix(trimmed, "."+domain) {
			continue
		}
		relative := strings.TrimPrefix(strings.TrimSuffix(trimmed, domain), ".")
		relative = strings.TrimSuffix(relative, ".")
		for _, record := range zone.Records {
			if !strings.EqualFold(record.Type, "A") {
				continue
			}
			if strings.EqualFold(strings.TrimSuffix(record.Name, "."), relative) {
				if parsed := net.ParseIP(record.Value); parsed != nil {
					return parsed.String(), true
				}
			}
		}
	}
	if config.Domain == "" {
		return "", false
	}
	domain := strings.TrimSuffix(strings.ToLower(config.Domain), ".")
	if trimmed == domain {
		return "", false
	}
	if !strings.HasSuffix(trimmed, "."+domain) {
		return "", false
	}
	label := strings.TrimSuffix(trimmed, "."+domain)
	if address, ok := config.Peers[label]; ok {
		return address, true
	}
	return "", false
}

// forwardOrFail relays the query to a certified nameserver, or to the original
// upstream when none matches.
func (resolver *Resolver) forwardOrFail(writer dns.ResponseWriter, request *dns.Msg, response *dns.Msg, config Config) {
	if cached, ok := resolver.cachedReply(request); ok {
		_ = writer.WriteMsg(cached)
		return
	}
	upstreams := resolver.upstreamsFor(config, request)
	for _, upstream := range upstreams {
		reply, err := resolver.exchange(request, upstream)
		if err != nil {
			logf("dns upstream %s failed: %v", upstream, err)
			continue
		}
		reply.Id = request.Id
		resolver.storeCached(request, reply)
		_ = writer.WriteMsg(reply)
		return
	}
	logf("dns query for %s had no usable upstream (tried %v)", questionName(request), upstreams)
	resolver.recordFailure()
	// SERVFAIL is the correct answer when nothing upstream could be reached, so
	// the stub resolver retries rather than caching a negative result.
	response.Rcode = dns.RcodeServerFailure
	_ = writer.WriteMsg(response)
}

func (resolver *Resolver) recordFailure() {
	resolver.failures.Add(1)
	if resolver.metrics != nil {
		resolver.metrics.DNSFailures.Inc()
	}
}

func (resolver *Resolver) Failures() uint64 {
	return resolver.failures.Load()
}

func (resolver *Resolver) exchange(request *dns.Msg, upstream string) (*dns.Msg, error) {
	outgoing := request.Copy()
	do := false
	if opt := request.IsEdns0(); opt != nil {
		do = opt.Do()
	}
	outgoing.SetEdns0(ednsUDPSize, do)

	reply, _, udpErr := resolver.udp.Exchange(outgoing, upstream)
	if udpErr == nil && !reply.Truncated {
		return reply, nil
	}
	tcpReply, _, tcpErr := resolver.tcp.Exchange(outgoing, upstream)
	if tcpErr == nil {
		return tcpReply, nil
	}
	if udpErr == nil && reply.Truncated {
		// Returning the truncated UDP reply lets a capable stub resolver retry
		// this server over its TCP listener when the upstream TCP path also
		// failed.
		return reply, nil
	}
	return nil, tcpErr
}

func (resolver *Resolver) cachedReply(request *dns.Msg) (*dns.Msg, bool) {
	key, ok := cacheKey(request)
	if !ok {
		return nil, false
	}
	now := resolver.now()
	resolver.mu.RLock()
	entry, exists := resolver.cache[key]
	resolver.mu.RUnlock()
	if !exists || !now.Before(entry.expiresAt) {
		if exists {
			resolver.mu.Lock()
			delete(resolver.cache, key)
			resolver.mu.Unlock()
		}
		return nil, false
	}
	reply := entry.reply.Copy()
	reply.Id = request.Id
	return reply, true
}

func (resolver *Resolver) storeCached(request *dns.Msg, reply *dns.Msg) {
	key, ok := cacheKey(request)
	if !ok || len(request.Question) != 1 {
		return
	}
	if reply.Rcode != dns.RcodeSuccess && reply.Rcode != dns.RcodeNameError {
		return
	}
	ttl := replyTTL(reply)
	if ttl <= 0 {
		return
	}
	resolver.mu.Lock()
	defer resolver.mu.Unlock()
	if resolver.cache == nil {
		resolver.cache = make(map[dnsCacheKey]dnsCacheEntry)
	}
	if _, exists := resolver.cache[key]; !exists && len(resolver.cache) >= maxDNSCacheEntries {
		return
	}
	resolver.cache[key] = dnsCacheEntry{
		reply:     reply.Copy(),
		expiresAt: resolver.now().Add(ttl),
	}
}

func cacheKey(request *dns.Msg) (dnsCacheKey, bool) {
	if len(request.Question) != 1 {
		return dnsCacheKey{}, false
	}
	return dnsCacheKey{
		question: request.Question[0],
		dnssec:   func() bool { opt := request.IsEdns0(); return opt != nil && opt.Do() }(),
	}, true
}

func replyTTL(reply *dns.Msg) time.Duration {
	minimum := uint32(0)
	for _, section := range [][]dns.RR{reply.Answer, reply.Ns, reply.Extra} {
		for _, record := range section {
			if _, isOpt := record.(*dns.OPT); isOpt {
				continue
			}
			if minimum == 0 || record.Header().Ttl < minimum {
				minimum = record.Header().Ttl
			}
		}
	}
	if minimum == 0 && reply.Rcode == dns.RcodeNameError {
		// Negative answers without SOA should not be cached indefinitely.
		minimum = defaultTTL
	}
	return time.Duration(minimum) * time.Second
}

func isOverlayName(config Config, name string) bool {
	trimmed := strings.TrimSuffix(strings.ToLower(name), ".")
	if trimmed == "" {
		return false
	}
	if config.Domain != "" {
		domain := strings.TrimSuffix(strings.ToLower(config.Domain), ".")
		if trimmed == domain || strings.HasSuffix(trimmed, "."+domain) {
			return true
		}
	}
	for _, zone := range config.Zones {
		if !zone.Enabled || zone.Domain == "" {
			continue
		}
		domain := strings.TrimSuffix(strings.ToLower(zone.Domain), ".")
		if trimmed == domain || strings.HasSuffix(trimmed, "."+domain) {
			return true
		}
	}
	return false
}

func questionName(request *dns.Msg) string {
	if len(request.Question) == 0 {
		return "<empty>"
	}
	return request.Question[0].Name
}

// upstreamsFor returns the certified nameservers that apply to the query,
// followed by the original host resolvers.
func (resolver *Resolver) upstreamsFor(config Config, request *dns.Msg) []string {
	result := make([]string, 0, 4)
	seen := make(map[string]struct{})
	add := func(address string) {
		address = strings.TrimSpace(address)
		if address == "" {
			return
		}
		if _, exists := seen[address]; exists {
			return
		}
		seen[address] = struct{}{}
		result = append(result, address)
	}

	for _, nameserver := range config.Nameservers {
		if !nameserver.Enabled {
			continue
		}
		if !matchesDomains(nameserver.MatchDomains, request.Question) {
			continue
		}
		for _, server := range nameserver.Servers {
			add(addressWithPort(server))
		}
	}
	for _, upstream := range config.Upstreams {
		add(addressWithPort(upstream))
	}
	return result
}

// matchesDomains reports whether any question falls under one of the suffixes.
// An empty list matches every query.
func matchesDomains(domains []string, questions []dns.Question) bool {
	if len(domains) == 0 {
		return true
	}
	for _, domain := range domains {
		suffix := strings.TrimSuffix(strings.ToLower(domain), ".")
		if suffix == "" {
			return true
		}
		for _, question := range questions {
			name := strings.TrimSuffix(strings.ToLower(question.Name), ".")
			if name == suffix || strings.HasSuffix(name, "."+suffix) {
				return true
			}
		}
	}
	return false
}

func (resolver *Resolver) snapshot() Config {
	resolver.mu.RLock()
	defer resolver.mu.RUnlock()
	return resolver.config
}

func appendAddress(response *dns.Msg, question dns.Question, address string) {
	ip := net.ParseIP(address)
	if ip == nil {
		return
	}
	if question.Qtype == dns.TypeA {
		if v4 := ip.To4(); v4 != nil {
			response.Answer = append(response.Answer, &dns.A{
				Hdr: dns.RR_Header{Name: question.Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: defaultTTL},
				A:   v4,
			})
		}
		return
	}
	if v6 := ip.To16(); v6 != nil && ip.To4() == nil {
		response.Answer = append(response.Answer, &dns.AAAA{
			Hdr:  dns.RR_Header{Name: question.Name, Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: defaultTTL},
			AAAA: v6,
		})
	}
}

func addressWithPort(server string) string {
	if _, _, err := net.SplitHostPort(server); err == nil {
		return server
	}
	return net.JoinHostPort(server, "53")
}

// PeerLabels maps every peer to the name it answers to inside the overlay
// domain, preferring the assigned DNSLabel and falling back to a sanitized
// hostname.
func PeerLabels(state model.NetworkState) map[string]string {
	labels := make(map[string]string, len(state.Peers))
	used := make(map[string]struct{}, len(state.Peers))
	peers := append([]model.PeerRecord(nil), state.Peers...)
	sort.Slice(peers, func(i, j int) bool { return peers[i].PeerID < peers[j].PeerID })
	for _, peer := range peers {
		if peer.OverlayIP == "" {
			continue
		}
		label := peer.DNSLabel
		if label == "" {
			label = SanitizeLabel(peer.Hostname)
		}
		if label == "" {
			continue
		}
		unique := label
		for suffix := 2; ; suffix++ {
			if _, taken := used[unique]; !taken {
				break
			}
			unique = fmt.Sprintf("%s-%d", label, suffix)
		}
		used[unique] = struct{}{}
		labels[unique] = peer.OverlayIP
	}
	return labels
}

// SanitizeLabel turns a hostname into a single DNS label.
func SanitizeLabel(hostname string) string {
	trimmed := strings.ToLower(strings.TrimSpace(hostname))
	if index := strings.Index(trimmed, "."); index >= 0 {
		trimmed = trimmed[:index]
	}
	var builder strings.Builder
	for _, char := range trimmed {
		switch {
		case char >= 'a' && char <= 'z', char >= '0' && char <= '9', char == '-':
			builder.WriteRune(char)
		case char == '_' || char == ' ':
			builder.WriteRune('-')
		}
	}
	label := strings.Trim(builder.String(), "-")
	if len(label) > 63 {
		label = label[:63]
	}
	return label
}
