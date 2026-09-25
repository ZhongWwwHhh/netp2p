package alerts

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/netp2p/netp2p/internal/model"
)

// recordingSink captures delivered events for assertions.
type recordingSink struct {
	mu     sync.Mutex
	events []Event
}

func (sink *recordingSink) Send(_ context.Context, event Event) error {
	sink.mu.Lock()
	defer sink.mu.Unlock()
	sink.events = append(sink.events, event)
	return nil
}

func (sink *recordingSink) snapshot() []Event {
	sink.mu.Lock()
	defer sink.mu.Unlock()
	return append([]Event(nil), sink.events...)
}

func TestRulesFireAndResolveOnTransitions(t *testing.T) {
	sink := &recordingSink{}
	alerter := New(Config{}, sink)
	ctx := context.Background()
	base := time.Now()

	degraded := Input{
		Manager: "manager-1", Height: 4,
		DisconnectedPeers: []string{"manager-4"},
		PeerCount:         2, LinkSegments: 3, MinLinkConfidence: 0.7,
		Now: base,
	}
	events := alerter.Evaluate(ctx, degraded)
	if len(events) != 1 || events[0].Status != "firing" || events[0].Alert.Rule != RuleQuorumDegraded {
		t.Fatalf("expected one quorum_degraded firing event, got %+v", events)
	}
	if events[0].Alert.Severity != SeverityWarning {
		t.Fatalf("quorum_degraded severity = %q", events[0].Alert.Severity)
	}

	// Re-evaluating the same condition must not re-fire.
	if again := alerter.Evaluate(ctx, degraded); len(again) != 0 {
		t.Fatalf("a steady alert re-fired: %+v", again)
	}
	if len(alerter.Active()) != 1 {
		t.Fatalf("active set = %+v", alerter.Active())
	}

	// Once the member reconnects, the alert resolves exactly once.
	healthy := degraded
	healthy.DisconnectedPeers = nil
	healthy.Now = base.Add(time.Second)
	events = alerter.Evaluate(ctx, healthy)
	if len(events) != 1 || events[0].Status != "resolved" || events[0].Alert.ID != RuleQuorumDegraded {
		t.Fatalf("expected one resolved event, got %+v", events)
	}
	if len(alerter.Active()) != 0 {
		t.Fatalf("active set should be empty, got %+v", alerter.Active())
	}
	if len(sink.snapshot()) != 2 {
		t.Fatalf("sink saw %d events, want firing+resolved", len(sink.snapshot()))
	}
}

func TestProbeFailedRequiresPeers(t *testing.T) {
	alerter := New(Config{})
	ctx := context.Background()
	// No peers: no alert, even with no measurements.
	if events := alerter.Evaluate(ctx, Input{Now: time.Now()}); len(events) != 0 {
		t.Fatalf("empty network fired %+v", events)
	}
	// Peers but no confident measurement: alert.
	events := alerter.Evaluate(ctx, Input{PeerCount: 2, LinkSegments: 0, Now: time.Now()})
	if len(events) != 1 || events[0].Alert.Rule != RuleProbeFailed {
		t.Fatalf("expected probe_failed, got %+v", events)
	}
}

func TestQuotaExceededIsPerBudget(t *testing.T) {
	alerter := New(Config{})
	events := alerter.Evaluate(context.Background(), Input{
		Now: time.Now(),
		Budgets: []model.TrafficBudget{
			{ID: "spent", DailyBytes: 100, UsedDailyBytes: 100, OnExhausted: "block"},
			{ID: "fine", DailyBytes: 100, UsedDailyBytes: 10},
			{ID: "unlimited", DailyBytes: 0, UsedDailyBytes: 1 << 40},
		},
	})
	if len(events) != 1 {
		t.Fatalf("expected exactly one quota alert, got %+v", events)
	}
	if events[0].Alert.ID != RuleQuotaExceeded+":spent" {
		t.Fatalf("quota alert id = %q", events[0].Alert.ID)
	}
}

func TestForwardDropsUsesBaselineAndThreshold(t *testing.T) {
	alerter := New(Config{Thresholds: Thresholds{DropCount: 10, DropRatePercent: 5}})
	ctx := context.Background()
	now := time.Now()
	// First pass only establishes a baseline.
	if events := alerter.Evaluate(ctx, Input{Forwarded: 0, Dropped: 0, Now: now}); len(events) != 0 {
		t.Fatalf("baseline pass fired %+v", events)
	}
	// A small delta under the threshold must stay quiet.
	if events := alerter.Evaluate(ctx, Input{Forwarded: 100, Dropped: 2, Now: now.Add(time.Second)}); len(events) != 0 {
		t.Fatalf("below-threshold delta fired %+v", events)
	}
	// Crossing the absolute threshold fires.
	events := alerter.Evaluate(ctx, Input{Forwarded: 200, Dropped: 20, Now: now.Add(2 * time.Second)})
	if len(events) != 1 || events[0].Alert.Rule != RuleForwardDrops {
		t.Fatalf("expected forward_drops, got %+v", events)
	}
}

func TestForwardDropsFiresOnRate(t *testing.T) {
	// A high drop *rate* fires even below the absolute count.
	alerter := New(Config{Thresholds: Thresholds{DropCount: 1000, DropRatePercent: 5}})
	ctx := context.Background()
	now := time.Now()
	alerter.Evaluate(ctx, Input{Forwarded: 0, Dropped: 0, Now: now})
	events := alerter.Evaluate(ctx, Input{Forwarded: 50, Dropped: 10, Now: now.Add(time.Second)})
	if len(events) != 1 || events[0].Alert.Rule != RuleForwardDrops {
		t.Fatalf("expected forward_drops via rate, got %+v", events)
	}
}

func TestWebhookDeliversJSONAndRetriesOn5xx(t *testing.T) {
	var mu sync.Mutex
	attempts := 0
	var received Event
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		mu.Lock()
		attempts++
		attempt := attempts
		mu.Unlock()
		if attempt < 3 {
			writer.WriteHeader(http.StatusInternalServerError)
			return
		}
		if request.Header.Get("Authorization") != "Bearer sekret" {
			writer.WriteHeader(http.StatusUnauthorized)
			return
		}
		if err := json.NewDecoder(request.Body).Decode(&received); err != nil {
			writer.WriteHeader(http.StatusBadRequest)
			return
		}
		writer.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	sink := NewWebhookSink(server.URL, "sekret")
	sink.Backoff = time.Millisecond
	err := sink.Send(context.Background(), Event{
		Status: "firing", Manager: "manager-1", Height: 7,
		Alert: Alert{ID: "x", Rule: RuleQuorumDegraded, Severity: SeverityWarning, Summary: "down"},
		Time:  time.Now(),
	})
	if err != nil {
		t.Fatalf("webhook send failed after retries: %v", err)
	}
	mu.Lock()
	total := attempts
	mu.Unlock()
	if total != 3 {
		t.Fatalf("attempts = %d, want 3 (two 5xx then success)", total)
	}
	if received.Status != "firing" || received.Manager != "manager-1" || received.Height != 7 || received.Alert.Rule != RuleQuorumDegraded {
		t.Fatalf("webhook payload mismatch: %+v", received)
	}
}

func TestWebhookDoesNotRetry4xx(t *testing.T) {
	var mu sync.Mutex
	attempts := 0
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		mu.Lock()
		attempts++
		mu.Unlock()
		writer.WriteHeader(http.StatusBadRequest)
	}))
	defer server.Close()

	sink := NewWebhookSink(server.URL, "")
	sink.Backoff = time.Millisecond
	if err := sink.Send(context.Background(), Event{Alert: Alert{ID: "x"}}); err == nil {
		t.Fatal("expected an error for a 4xx response")
	}
	mu.Lock()
	total := attempts
	mu.Unlock()
	if total != 1 {
		t.Fatalf("attempts = %d, want 1 (4xx is permanent)", total)
	}
}

func TestNoWebhookConfiguredIsNoOp(t *testing.T) {
	if err := NewWebhookSink("", "").Send(context.Background(), Event{Alert: Alert{ID: "x"}}); err != nil {
		t.Fatalf("empty webhook should be a no-op, got %v", err)
	}
}

func TestDefaultThresholdsApplied(t *testing.T) {
	config := Config{}.withDefaults()
	if config.Interval != 15*time.Second || config.Thresholds.DropCount != 100 || config.Thresholds.DropRatePercent != 5 {
		t.Fatalf("unexpected defaults: %+v", config)
	}
}
