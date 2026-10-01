package alerts

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"time"
)

// WebhookSink POSTs alert events as JSON. Delivery retries are bounded so a
// misbehaving endpoint can never stall evaluation.
type WebhookSink struct {
	URL         string
	Secret      string
	Client      *http.Client
	MaxAttempts int
	Backoff     time.Duration
}

// NewWebhookSink builds a webhook sink with sane defaults. An empty URL yields
// a disabled sink. The URL must use https unless allowInsecure is set: alert
// payloads carry operational detail that should not travel in the clear.
func NewWebhookSink(rawURL, secret string, allowInsecure bool) (*WebhookSink, error) {
	if rawURL != "" {
		parsed, err := url.Parse(rawURL)
		if err != nil {
			return nil, fmt.Errorf("alert webhook url %q is invalid: %w", rawURL, err)
		}
		switch parsed.Scheme {
		case "https":
		case "http":
			if !allowInsecure {
				return nil, fmt.Errorf("alert webhook url %q must use https (pass --allow-insecure-webhook to permit http)", rawURL)
			}
		default:
			return nil, fmt.Errorf("alert webhook url %q must use https", rawURL)
		}
	}
	return &WebhookSink{
		URL: rawURL, Secret: secret,
		Client:      &http.Client{Timeout: 5 * time.Second},
		MaxAttempts: 3,
		Backoff:     500 * time.Millisecond,
	}, nil
}

// Send delivers one event, retrying transient failures. A permanent client
// error (4xx) is not retried: repeating it would not change the outcome.
func (sink *WebhookSink) Send(ctx context.Context, event Event) error {
	if sink == nil || sink.URL == "" {
		return nil
	}
	body, err := json.Marshal(event)
	if err != nil {
		return err
	}
	client := sink.Client
	if client == nil {
		client = &http.Client{Timeout: 5 * time.Second}
	}
	attempts := sink.MaxAttempts
	if attempts <= 0 {
		attempts = 1
	}
	var lastErr error
	for attempt := 0; attempt < attempts; attempt++ {
		if attempt > 0 && sink.Backoff > 0 {
			timer := time.NewTimer(sink.Backoff * time.Duration(attempt))
			select {
			case <-ctx.Done():
				timer.Stop()
				return ctx.Err()
			case <-timer.C:
			}
		}
		lastErr = sink.attempt(ctx, client, body)
		if lastErr == nil {
			return nil
		}
		if isPermanent(lastErr) {
			break
		}
	}
	slog.Warn("alert webhook delivery failed", "url", sink.URL, "rule", event.Alert.Rule, "error", lastErr)
	return lastErr
}

// permanentError marks a 4xx response, which retrying cannot fix.
type permanentError struct {
	status int
	body   string
}

func (err *permanentError) Error() string {
	return fmt.Sprintf("webhook rejected with status %d: %s", err.status, err.body)
}

func isPermanent(err error) bool {
	_, ok := err.(*permanentError)
	return ok
}

func (sink *WebhookSink) attempt(ctx context.Context, client *http.Client, body []byte) error {
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, sink.URL, bytes.NewReader(body))
	if err != nil {
		return err
	}
	request.Header.Set("Content-Type", "application/json")
	if sink.Secret != "" {
		request.Header.Set("Authorization", "Bearer "+sink.Secret)
	}
	response, err := client.Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if response.StatusCode >= 200 && response.StatusCode < 300 {
		return nil
	}
	if response.StatusCode >= 400 && response.StatusCode < 500 {
		return &permanentError{status: response.StatusCode}
	}
	return fmt.Errorf("webhook returned status %d", response.StatusCode)
}

// LogSink writes alerts to the structured logger. It is always available, so an
// operator with no webhook configured still gets a record of every transition.
type LogSink struct {
	Logger *slog.Logger
}

// Send emits one structured line per alert transition.
func (sink LogSink) Send(_ context.Context, event Event) error {
	logger := sink.Logger
	if logger == nil {
		logger = slog.Default()
	}
	level := slog.LevelWarn
	if event.Status == "resolved" {
		level = slog.LevelInfo
	}
	logger.LogAttrs(context.Background(), level, "alert",
		slog.String("status", event.Status),
		slog.String("rule", event.Alert.Rule),
		slog.String("severity", string(event.Alert.Severity)),
		slog.String("summary", event.Alert.Summary),
		slog.String("manager", event.Manager),
		slog.Uint64("height", event.Height),
	)
	return nil
}
