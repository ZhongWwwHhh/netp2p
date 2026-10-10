package metrics

import (
	"net/http/httptest"
	"strings"
	"testing"
)

func TestHandlerExposesRegisteredMetrics(t *testing.T) {
	collector := New()
	collector.BFTHeight.Set(7)
	collector.Forwarded.Add(3)
	collector.ForwardQueueDepth.Set(2)
	collector.DNSFailures.Add(1)

	recorder := httptest.NewRecorder()
	collector.Handler().ServeHTTP(recorder, httptest.NewRequest("GET", "/metrics", nil))
	body := recorder.Body.String()
	if !strings.Contains(body, "netp2p_bft_height 7") {
		t.Fatalf("height gauge missing from exposition:\n%s", body)
	}
	if !strings.Contains(body, "netp2p_forward_forwarded_total 3") {
		t.Fatalf("forward counter missing from exposition:\n%s", body)
	}
	if !strings.Contains(body, "netp2p_forward_queue_depth 2") {
		t.Fatalf("forward queue depth missing from exposition:\n%s", body)
	}
	if !strings.Contains(body, "netp2p_dns_failures_total 1") {
		t.Fatalf("dns failure counter missing from exposition:\n%s", body)
	}
	if !strings.Contains(body, "go_goroutines") {
		t.Fatalf("go goroutine metric missing from exposition:\n%s", body)
	}
	if !strings.Contains(body, "process_resident_memory_bytes") {
		t.Fatalf("process resident memory metric missing from exposition:\n%s", body)
	}
}

func TestRegistriesAreIsolated(t *testing.T) {
	first := New()
	second := New()
	first.BFTHeight.Set(1)
	second.BFTHeight.Set(2)
	// Both registries must be usable independently; New must not panic on a
	// duplicate registration.
	_ = first.Handler()
	_ = second.Handler()
}
