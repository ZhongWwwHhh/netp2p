package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"gopkg.in/yaml.v3"
)

func TestDoctorIncludesNextAction(t *testing.T) {
	state := &ipcState{cfg: runtimeConfig{IPC: ipcConfig{Path: "/tmp/netp2p.sock"}}, state: "idle"}
	recorder := httptest.NewRecorder()
	state.handleDoctor(recorder, httptest.NewRequest(http.MethodGet, "/v1/doctor", nil))

	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", recorder.Code, http.StatusOK)
	}
	var payload struct {
		State      string `json:"state"`
		NextAction string `json:"nextAction"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &payload); err != nil {
		t.Fatal(err)
	}
	if payload.State != "idle" || payload.NextAction == "" {
		t.Fatalf("doctor state/action = %q/%q, want idle and a concrete action", payload.State, payload.NextAction)
	}
}

func TestUnprovisionedClientReportsNeedsLoginAndRefusesUp(t *testing.T) {
	cfg := defaultRuntimeConfig()
	cfg.Role = "client"
	cfg.DataDir = t.TempDir()
	state := newIPCState(context.Background(), cfg, filepath.Join(t.TempDir(), "runtime.yaml"), func(context.Context, runtimeConfig) error {
		return nil
	})
	recorder := httptest.NewRecorder()
	state.handleUp(recorder, httptest.NewRequest(http.MethodPost, "/v1/up", nil))
	if recorder.Code != http.StatusConflict {
		t.Fatalf("up status = %d, want %d", recorder.Code, http.StatusConflict)
	}
	recorder = httptest.NewRecorder()
	state.handleDoctor(recorder, httptest.NewRequest(http.MethodGet, "/v1/doctor", nil))
	var payload struct {
		State      string `json:"state"`
		NextAction string `json:"nextAction"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &payload); err != nil {
		t.Fatal(err)
	}
	if payload.State != "needs-login" || payload.NextAction != "Run netp2p login with the network manager and setup key, then run netp2p up." {
		t.Fatalf("unprovisioned doctor view = %+v", payload)
	}
}

func TestReloadSupervisorUsesUpdatedClientConfig(t *testing.T) {
	configPath := filepath.Join(t.TempDir(), "runtime.yaml")
	idle := defaultRuntimeConfig()
	idle.Role = "client"
	idle.DataDir = t.TempDir()
	idleRaw, err := yaml.Marshal(idle)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(configPath, idleRaw, 0o600); err != nil {
		t.Fatal(err)
	}

	started := make(chan runtimeConfig, 1)
	state := newIPCState(context.Background(), idle, configPath, func(_ context.Context, cfg runtimeConfig) error {
		started <- cfg
		return nil
	})
	if !state.unprovisioned() {
		t.Fatal("initial daemon state should recognize an unprovisioned profile")
	}

	provisioned := defaultRuntimeConfig()
	provisioned.Role = "client"
	provisioned.DataDir = idle.DataDir
	provisioned.Manager = "/ip4/127.0.0.1/udp/4001/quic-v1"
	provisioned.SetupKey = "test-setup-key"
	provisionedRaw, err := yaml.Marshal(provisioned)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(configPath, provisionedRaw, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := state.reloadConfig(); err != nil {
		t.Fatalf("reloadConfig: %v", err)
	}
	if !state.startClient() {
		t.Fatal("reloaded supervisor did not start")
	}
	select {
	case got := <-started:
		if got.Manager != provisioned.Manager {
			t.Fatalf("supervisor used stale config: %+v", got)
		}
	case <-time.After(time.Second):
		t.Fatal("reloaded supervisor did not invoke its start callback")
	}
}

func TestClientReadyMapsStartingProcessStateToRunning(t *testing.T) {
	dir := t.TempDir()
	statusPath := filepath.Join(dir, "status.json")
	if err := os.WriteFile(statusPath, []byte(`{"state":"ready","nextAction":"No action required."}`), 0o600); err != nil {
		t.Fatal(err)
	}
	state := &ipcState{
		cfg:     runtimeConfig{Role: "client", IPC: ipcConfig{Path: filepath.Join(dir, "netp2pd.sock")}, StatusFile: statusPath},
		state:   "starting",
		lastErr: "stale startup warning",
	}

	recorder := httptest.NewRecorder()
	state.handleStatus(recorder, httptest.NewRequest(http.MethodGet, "/v1/status", nil))
	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", recorder.Code, http.StatusOK)
	}
	var payload struct {
		State  string         `json:"state"`
		Client map[string]any `json:"client"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &payload); err != nil {
		t.Fatal(err)
	}
	if payload.State != "running" {
		t.Fatalf("outer state = %q, client = %+v, want running when client is ready", payload.State, payload.Client)
	}
}

func TestDoctorUsesLiveReadyClientForNextAction(t *testing.T) {
	dir := t.TempDir()
	statusPath := filepath.Join(dir, "status.json")
	if err := os.WriteFile(statusPath, []byte(`{"state":"ready","nextAction":"No action required."}`), 0o600); err != nil {
		t.Fatal(err)
	}
	state := &ipcState{
		cfg:     runtimeConfig{Role: "client", IPC: ipcConfig{Path: filepath.Join(dir, "netp2pd.sock")}, StatusFile: statusPath},
		state:   "starting",
		lastErr: "stale startup warning",
	}

	recorder := httptest.NewRecorder()
	state.handleDoctor(recorder, httptest.NewRequest(http.MethodGet, "/v1/doctor", nil))
	var payload struct {
		State      string `json:"state"`
		NextAction string `json:"nextAction"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &payload); err != nil {
		t.Fatal(err)
	}
	if payload.State != "running" {
		t.Fatalf("doctor state = %q, want running", payload.State)
	}
	if payload.NextAction != "No action required; use netp2p status --json for live manager state." {
		t.Fatalf("doctor action = %q, want explicit healthy state", payload.NextAction)
	}
}
