package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/netp2p/netp2p/internal/client"
)

func TestPingEndpointPreservesHealthProbe(t *testing.T) {
	state := &ipcState{}
	recorder := httptest.NewRecorder()
	state.handlePing(recorder, httptest.NewRequest(http.MethodGet, "/v1/ping", nil))
	if recorder.Code != http.StatusOK {
		t.Fatalf("health probe status = %d, want %d", recorder.Code, http.StatusOK)
	}
	var payload struct {
		OK      bool   `json:"ok"`
		Version string `json:"version"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &payload); err != nil {
		t.Fatal(err)
	}
	if !payload.OK || payload.Version == "" {
		t.Fatalf("health probe payload = %+v", payload)
	}
}

func TestPingEndpointRequiresActiveDataPlane(t *testing.T) {
	activeClient.Store(nil)
	defer activeClient.Store(nil)
	state := &ipcState{}
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/v1/ping?target=100.64.0.1&timeout_ms=100", nil)
	state.handlePing(recorder, request)
	if recorder.Code != http.StatusServiceUnavailable {
		t.Fatalf("inactive ping status = %d, want %d", recorder.Code, http.StatusServiceUnavailable)
	}
	var payload struct {
		Error string `json:"error"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &payload); err != nil {
		t.Fatal(err)
	}
	if payload.Error == "" {
		t.Fatal("inactive ping payload has no error")
	}
}

func TestActiveClientRegistrationStoresAndClears(t *testing.T) {
	current := &client.Client{}
	activeClient.Store(current)
	if activeClient.Load() != current {
		t.Fatal("active client was not stored")
	}
	activeClient.Store(nil)
	if activeClient.Load() != nil {
		t.Fatal("active client was not cleared")
	}
}
