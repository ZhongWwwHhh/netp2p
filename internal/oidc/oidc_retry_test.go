package oidc

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestNewVerifierWithRetryRecoversTransientDiscoveryFailure(t *testing.T) {
	var attempts atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.URL.Path != "/.well-known/openid-configuration" {
			http.NotFound(writer, request)
			return
		}
		if attempts.Add(1) == 1 {
			http.Error(writer, "temporarily unavailable", http.StatusServiceUnavailable)
			return
		}
		writer.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(writer).Encode(map[string]string{
			"issuer":                 "http://" + request.Host,
			"authorization_endpoint": "http://" + request.Host + "/authorize",
			"token_endpoint":         "http://" + request.Host + "/token",
			"jwks_uri":               "http://" + request.Host + "/jwks",
		})
	}))
	defer server.Close()

	verifier, err := NewVerifierWithRetry(
		context.Background(), Config{Issuer: server.URL, ClientID: "netp2p"}, 3, time.Millisecond,
	)
	if err != nil {
		t.Fatalf("retry did not recover transient discovery failure: %v", err)
	}
	authURL, _, _ := verifier.Endpoint()
	if authURL != server.URL+"/authorize" {
		t.Fatalf("authorization endpoint = %q", authURL)
	}
}

func TestNewVerifierWithRetryReportsBoundedFailure(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		http.Error(writer, "unavailable", http.StatusServiceUnavailable)
	}))
	defer server.Close()

	_, err := NewVerifierWithRetry(
		context.Background(), Config{Issuer: server.URL, ClientID: "netp2p"}, 2, time.Millisecond,
	)
	if err == nil || !strings.Contains(err.Error(), "after 2 attempts") {
		t.Fatalf("error = %v, want bounded retry failure", err)
	}
}
