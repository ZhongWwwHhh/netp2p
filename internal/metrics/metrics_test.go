package metrics

import (
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
)

func TestHandlerExposesRegisteredMetrics(t *testing.T) {
	collector := New()
	collector.BFTHeight.Set(7)
	collector.BFTLastCommitTime.Set(1770791724.25)
	collector.Forwarded.Add(3)
	collector.ForwardQueueDepth.Set(2)
	collector.DNSFailures.Add(1)
	collector.RecordSyncRequest()
	collector.RecordSyncError()
	collector.RecordSyncTimeout()
	collector.RecordStoreWriteFailure()
	collector.RecordScalePathSelection("family-multi", "multi_hop", 2)
	collector.SetBFTView(3, 1)
	collector.SetBFTHeightLag(4, 6)
	collector.RecordBFTRoundTimeout()
	collector.RecordBFTSubmit("accepted", 4, false)
	collector.RecordBFTSubmit("round_timeout", 5, true)
	collector.BFTCatchUps.Add(1)
	collector.BFTCatchupFailures.Add(2)

	recorder := httptest.NewRecorder()
	collector.Handler().ServeHTTP(recorder, httptest.NewRequest("GET", "/metrics", nil))
	body := recorder.Body.String()
	if !strings.Contains(body, "netp2p_bft_height 7") {
		t.Fatalf("height gauge missing from exposition:\n%s", body)
	}
	if !strings.Contains(body, "netp2p_bft_last_commit_timestamp_seconds") {
		t.Fatalf("last commit timestamp missing from exposition:\n%s", body)
	}
	if !strings.Contains(body, "netp2p_forward_forwarded_total 3") {
		t.Fatalf("forward counter missing from exposition:\n%s", body)
	}
	if !strings.Contains(body, "netp2p_forward_queue_depth 2") {
		t.Fatalf("forward queue depth missing from exposition:\n%s", body)
	}
	if !strings.Contains(body, `netp2p_forward_scale_path_selections_total{kind="multi_hop",manager_hops="2",path_family="family-multi"} 1`) {
		t.Fatalf("scale path selection metric missing from exposition:\n%s", body)
	}
	if !strings.Contains(body, "netp2p_dns_failures_total 1") {
		t.Fatalf("dns failure counter missing from exposition:\n%s", body)
	}
	if !strings.Contains(body, "netp2p_sync_requests_total 1") ||
		!strings.Contains(body, "netp2p_sync_errors_total 1") ||
		!strings.Contains(body, "netp2p_sync_timeouts_total 1") {
		t.Fatalf("sync counters missing from exposition:\n%s", body)
	}
	if !strings.Contains(body, "netp2p_bft_submit_attempts_total 2") ||
		!strings.Contains(body, "netp2p_bft_submit_failures_total 1") ||
		!strings.Contains(body, `netp2p_bft_submit_attempts_by_result_total{result="accepted",round="4"} 1`) ||
		!strings.Contains(body, `netp2p_bft_submit_attempts_by_result_total{result="round_timeout",round="5"} 1`) ||
		!strings.Contains(body, `netp2p_bft_submit_failures_by_result_total{result="round_timeout",round="5"} 1`) {
		t.Fatalf("BFT submit counters missing from exposition:\n%s", body)
	}
	if !strings.Contains(body, `result="accepted"`) ||
		!strings.Contains(body, `result="round_timeout"`) ||
		!strings.Contains(body, `round="4"`) ||
		!strings.Contains(body, `round="5"`) {
		t.Fatalf("BFT submit labels missing from exposition:\n%s", body)
	}
	if !strings.Contains(body, "netp2p_bft_round 3") ||
		!strings.Contains(body, "netp2p_bft_uncommitted_proposals 1") ||
		!strings.Contains(body, "netp2p_bft_round_timeouts_total 1") ||
		!strings.Contains(body, "netp2p_bft_height_lag 2") {
		t.Fatalf("BFT view metrics missing from exposition:\n%s", body)
	}
	if !strings.Contains(body, "netp2p_bft_catchup_success_total 1") ||
		!strings.Contains(body, "netp2p_bft_catchup_failures_total 2") {
		t.Fatalf("BFT catch-up metrics missing from exposition:\n%s", body)
	}
	if !strings.Contains(body, "netp2p_store_write_failures_total 1") {
		t.Fatalf("store write failure counter missing from exposition:\n%s", body)
	}
	if !strings.Contains(body, "go_goroutines") {
		t.Fatalf("go goroutine metric missing from exposition:\n%s", body)
	}
	if !strings.Contains(body, "process_resident_memory_bytes") {
		t.Fatalf("process resident memory metric missing from exposition:\n%s", body)
	}
}

func TestBFTCommitHelpers(t *testing.T) {
	collector := New()
	certifiedAt := time.Unix(1770791724, 500000000).UTC()

	collector.RestoreBFTSnapshot(12, certifiedAt)
	if got := gaugeValue(t, collector.BFTHeight); got != 12 {
		t.Fatalf("restored height = %v, want 12", got)
	}
	if got := gaugeValue(t, collector.BFTLastCommitTime); got != 1770791724.5 {
		t.Fatalf("restored timestamp = %v, want 1770791724.5", got)
	}
	if got := counterValue(t, collector.BFTCommits); got != 0 {
		t.Fatalf("restore incremented commits to %v, want 0", got)
	}

	collector.PublishBFTCommit(13, certifiedAt.Add(time.Second))
	if got := gaugeValue(t, collector.BFTHeight); got != 13 {
		t.Fatalf("published height = %v, want 13", got)
	}
	if got := gaugeValue(t, collector.BFTLastCommitTime); got != 1770791725.5 {
		t.Fatalf("published timestamp = %v, want 1770791725.5", got)
	}
	if got := counterValue(t, collector.BFTCommits); got != 1 {
		t.Fatalf("published commits = %v, want 1", got)
	}

	var nilCollector *Metrics
	nilCollector.RestoreBFTSnapshot(1, time.Now())
	nilCollector.PublishBFTCommit(2, time.Now())
	nilCollector.RecordSyncRequest()
	nilCollector.RecordSyncError()
	nilCollector.RecordSyncTimeout()
	nilCollector.RecordStoreWriteFailure()
	nilCollector.SetBFTView(1, 1)
	nilCollector.SetBFTHeightLag(1, 2)
	nilCollector.RecordBFTRoundTimeout()
	nilCollector.RecordBFTSubmit("accepted", 1, false)
}

func TestRoutingEpochHelpers(t *testing.T) {
	collector := New()

	collector.SetRoutingEpoch(42, 90*time.Second, 2048)
	if got := gaugeValue(t, collector.RoutingEpochPresent); got != 1 {
		t.Fatalf("routing epoch present = %v, want 1", got)
	}
	if got := gaugeValue(t, collector.RoutingEpochSequence); got != 42 {
		t.Fatalf("routing epoch sequence = %v, want 42", got)
	}
	if got := gaugeValue(t, collector.RoutingEpochAge); got != 90 {
		t.Fatalf("routing epoch age = %v, want 90", got)
	}
	if got := gaugeValue(t, collector.RoutingEpochSize); got != 2048 {
		t.Fatalf("routing epoch size = %v, want 2048", got)
	}

	collector.ClearRoutingEpoch()
	if got := gaugeValue(t, collector.RoutingEpochPresent); got != 0 {
		t.Fatalf("cleared routing epoch present = %v, want 0", got)
	}
	if got := gaugeValue(t, collector.RoutingEpochAge); got != 0 {
		t.Fatalf("cleared routing epoch age = %v, want 0", got)
	}

	collector.RecordRoutingEpochInvalid()
	if got := counterValue(t, collector.RoutingEpochInvalid); got != 1 {
		t.Fatalf("routing epoch invalid counter = %v, want 1", got)
	}

	var nilCollector *Metrics
	nilCollector.SetRoutingEpoch(1, time.Second, 1)
	nilCollector.ClearRoutingEpoch()
	nilCollector.RecordRoutingEpochInvalid()
}

func gaugeValue(t *testing.T, gauge prometheus.Gauge) float64 {
	t.Helper()
	var metric dto.Metric
	if err := gauge.Write(&metric); err != nil {
		t.Fatal(err)
	}
	return metric.GetGauge().GetValue()
}

func counterValue(t *testing.T, counter prometheus.Counter) float64 {
	t.Helper()
	var metric dto.Metric
	if err := counter.Write(&metric); err != nil {
		t.Fatal(err)
	}
	return metric.GetCounter().GetValue()
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
