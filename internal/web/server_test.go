package web

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func newTestServer() *Server {
	return &Server{
		bootstrap: []byte(`{"networkId":"net-test","version":"0.1.0"}`),
		config:    Config{AdminToken: "secret"},
	}
}

func TestBootstrapHandlerServesBootstrapJSON(t *testing.T) {
	server := newTestServer()
	recorder := httptest.NewRecorder()
	server.BootstrapHandler().ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/api/bootstrap", nil))
	if recorder.Code != http.StatusOK {
		t.Fatalf("status %d, want 200", recorder.Code)
	}
	if !strings.Contains(recorder.Body.String(), `"networkId":"net-test"`) {
		t.Fatalf("body %q missing network id", recorder.Body.String())
	}
}

func TestBootstrapHandlerDeepLinkReturnsSPA(t *testing.T) {
	server := newTestServer()
	for _, path := range []string{"/peers", "/policies", "/dns/nameservers"} {
		recorder := httptest.NewRecorder()
		server.BootstrapHandler().ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, path, nil))
		if recorder.Code != http.StatusOK {
			t.Fatalf("GET %s status %d, want 200", path, recorder.Code)
		}
		if !strings.Contains(recorder.Body.String(), "<div id=\"app\"") && !strings.Contains(recorder.Body.String(), "<script") {
			t.Fatalf("GET %s did not return the SPA shell: %q", path, recorder.Body.String())
		}
	}
}

func TestBootstrapHandlerRejectsUnknownAPI(t *testing.T) {
	server := newTestServer()
	for _, request := range []struct {
		method string
		path   string
	}{
		{http.MethodGet, "/api/v1/snapshot"},
		{http.MethodPost, "/api/v1/transitions"},
		{http.MethodGet, "/api/unknown"},
	} {
		recorder := httptest.NewRecorder()
		server.BootstrapHandler().ServeHTTP(recorder, httptest.NewRequest(request.method, request.path, nil))
		if recorder.Code != http.StatusNotFound {
			t.Fatalf("%s %s status %d, want 404", request.method, request.path, recorder.Code)
		}
	}
}

func TestBootstrapHandlerHealthz(t *testing.T) {
	server := newTestServer()
	recorder := httptest.NewRecorder()
	server.BootstrapHandler().ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/healthz", nil))
	if recorder.Code != http.StatusOK || !strings.Contains(recorder.Body.String(), "ok") {
		t.Fatalf("healthz status %d body %q", recorder.Code, recorder.Body.String())
	}
}

func TestAuthorize(t *testing.T) {
	request := httptest.NewRequest(http.MethodGet, "/api/v1/snapshot", nil)
	if authorize(request, "secret") {
		t.Fatal("request without header should not authorize")
	}
	request.Header.Set("Authorization", "Bearer wrong")
	if authorize(request, "secret") {
		t.Fatal("wrong token should not authorize")
	}
	request.Header.Set("Authorization", "Bearer secret")
	if !authorize(request, "secret") {
		t.Fatal("correct token should authorize")
	}
}
