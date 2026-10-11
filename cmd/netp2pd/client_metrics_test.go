package main

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/netp2p/netp2p/internal/client"
	"github.com/netp2p/netp2p/internal/metrics"
)

func TestClientMetricsListenOnlyAllowsIPv4Loopback(t *testing.T) {
	if address, err := clientMetricsListen(""); err != nil || address != "127.0.0.1:9102" {
		t.Fatalf("default metrics address = %q, %v; want 127.0.0.1:9102, nil", address, err)
	}
	if address, err := clientMetricsListen("127.0.0.1:9100"); err != nil || address != "127.0.0.1:9100" {
		t.Fatalf("loopback metrics address = %q, %v; want 127.0.0.1:9100, nil", address, err)
	}
	for _, address := range []string{"0.0.0.0:9100", "192.0.2.1:9100", "[::1]:9100", "localhost:9100", "127.0.0.1"} {
		if _, err := clientMetricsListen(address); err == nil {
			t.Fatalf("metrics address %q was accepted", address)
		}
	}
}

func TestStartClientMetricsBindsLoopbackAndExposesCollectors(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	collector, address, err := startClientMetrics(ctx, clientOptions{metricsListen: "127.0.0.1:0"})
	if err != nil {
		t.Fatalf("startClientMetrics: %v", err)
	}
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		t.Fatalf("split metrics address: %v", err)
	}
	if ip := net.ParseIP(host); ip == nil || !ip.Equal(net.IPv4(127, 0, 0, 1)) {
		t.Fatalf("metrics address %q is not IPv4 loopback", address)
	}

	collector.DNSFailures.Inc()
	collector.ForwardQueueDepth.Set(3)
	response, err := http.Get(fmt.Sprintf("http://%s/metrics", address))
	if err != nil {
		t.Fatalf("get metrics: %v", err)
	}
	defer response.Body.Close()
	body, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatalf("read metrics body: %v", err)
	}
	if response.StatusCode != http.StatusOK {
		t.Fatalf("metrics status = %d, want %d", response.StatusCode, http.StatusOK)
	}
	exposition := string(body)
	for _, name := range []string{
		"netp2p_dns_failures_total",
		"netp2p_forward_queue_depth",
		"go_goroutines",
		"process_resident_memory_bytes",
	} {
		if !strings.Contains(exposition, name) {
			t.Fatalf("metrics exposition is missing %q:\n%s", name, exposition)
		}
	}
}

func TestStartDNSUsesClientMetricsCollector(t *testing.T) {
	collector := metrics.New()
	resolver, restoreDNS := startDNS(clientOptions{dnsListen: testDNSListenAddress(t)}, []string{"127.0.0.1:1"}, false, collector)
	if resolver == nil {
		t.Fatal("dns resolver was not started")
	}
	defer restoreDNS()

	query := new(dns.Msg)
	query.SetQuestion(dns.Fqdn("metrics.netp2p.invalid"), dns.TypeA)
	dnsClient := &dns.Client{Net: "udp", Timeout: 5 * time.Second}
	reply, _, err := dnsClient.Exchange(query, resolver.ListenAddr())
	if err != nil {
		t.Fatalf("exchange with local resolver: %v", err)
	}
	if reply.Rcode != dns.RcodeServerFailure {
		t.Fatalf("resolver rcode = %d, want %d", reply.Rcode, dns.RcodeServerFailure)
	}
	if resolver.Failures() != 1 {
		t.Fatalf("resolver failures = %d, want 1", resolver.Failures())
	}
	if exposition := metricsExposition(t, collector); !strings.Contains(exposition, "netp2p_dns_failures_total 1") {
		t.Fatalf("dns failures metric missing from exposition:\n%s", exposition)
	}
}

func testDNSListenAddress(t *testing.T) string {
	t.Helper()
	for port := 20000; port < 25000; port++ {
		address := fmt.Sprintf("127.0.0.1:%d", port)
		listener, err := net.ListenPacket("udp", address)
		if err == nil {
			_ = listener.Close()
			return address
		}
	}
	t.Fatal("no UDP test port is available")
	return ""
}

func TestUpdateClientMetricsPublishesQueueDepth(t *testing.T) {
	collector := metrics.New()
	updateClientMetrics(client.DataPlaneStats{OutboundQueueDepth: 7}, collector)
	if exposition := metricsExposition(t, collector); !strings.Contains(exposition, "netp2p_forward_queue_depth 7") {
		t.Fatalf("forward queue depth metric missing from exposition:\n%s", exposition)
	}
}

func TestPublishClientMetricsAddsOutboundDropDelta(t *testing.T) {
	collector := metrics.New()
	publishClientMetrics(
		client.DataPlaneStats{OutboundQueueDepth: 1, OutboundDrops: 4},
		client.DataPlaneStats{OutboundQueueDepth: 2, OutboundDrops: 7},
		collector,
	)
	exposition := metricsExposition(t, collector)
	if !strings.Contains(exposition, "netp2p_forward_queue_depth 2") {
		t.Fatalf("queue depth missing from metrics:\n%s", exposition)
	}
	if !strings.Contains(exposition, "netp2p_forward_dropped_total 3") {
		t.Fatalf("outbound drop delta missing from metrics:\n%s", exposition)
	}
}

func metricsExposition(t *testing.T, collector *metrics.Metrics) string {
	t.Helper()
	server := httptest.NewServer(collector.Handler())
	defer server.Close()
	response, err := http.Get(server.URL + "/metrics")
	if err != nil {
		t.Fatalf("get metrics: %v", err)
	}
	defer response.Body.Close()
	body, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatalf("read metrics body: %v", err)
	}
	if response.StatusCode != http.StatusOK {
		t.Fatalf("metrics status = %d, want %d", response.StatusCode, http.StatusOK)
	}
	return string(body)
}
