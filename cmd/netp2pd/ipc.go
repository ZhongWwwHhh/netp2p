package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"time"

	"github.com/netp2p/netp2p/internal/version"
)

type ipcState struct {
	mu         sync.RWMutex
	cfg        runtimeConfig
	started    time.Time
	state      string
	lastErr    string
	supervisor *clientSupervisor
}

func newIPCState(ctx context.Context, cfg runtimeConfig, startClient func(context.Context) error) *ipcState {
	state := "running"
	if cfg.Role == "daemon" {
		state = "idle"
	}
	result := &ipcState{cfg: cfg, started: time.Now(), state: state}
	if cfg.Role == "client" || cfg.Role == "daemon" {
		result.supervisor = newClientSupervisor(ctx, startClient, result.clientStopped)
	}
	return result
}

func startIPC(ctx context.Context, state *ipcState) (net.Listener, *http.Server, error) {
	listener, err := listenIPC(state.cfg.IPC.Path)
	if err != nil {
		return nil, nil, fmt.Errorf("listen IPC: %w", err)
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/status", state.handleStatus)
	mux.HandleFunc("/v1/up", state.handleUp)
	mux.HandleFunc("/v1/down", state.handleDown)
	mux.HandleFunc("/v1/doctor", state.handleDoctor)
	mux.HandleFunc("/v1/netcheck", state.handleDoctor)
	mux.HandleFunc("/v1/ping", state.handlePing)
	server := &http.Server{
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
	}
	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = server.Shutdown(shutdownCtx)
	}()
	go func() {
		if err := server.Serve(listener); err != nil && !errors.Is(err, http.ErrServerClosed) {
			state.mu.Lock()
			state.state = "error"
			state.lastErr = err.Error()
			state.mu.Unlock()
		}
	}()
	return listener, server, nil
}

func (state *ipcState) handleStatus(writer http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodGet {
		http.Error(writer, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	state.mu.RLock()
	cfg := state.cfg
	started := state.started
	currentState := state.state
	lastErr := state.lastErr
	state.mu.RUnlock()

	payload := map[string]any{
		"version":       version.Version,
		"protocol":      version.ProtocolVersion,
		"role":          cfg.Role,
		"state":         currentState,
		"pid":           os.Getpid(),
		"startedAt":     started.UTC().Format(time.RFC3339Nano),
		"uptimeSeconds": int(time.Since(started).Seconds()),
		"goos":          runtime.GOOS,
		"goarch":        runtime.GOARCH,
	}
	if lastErr != "" {
		payload["lastError"] = lastErr
	}
	if cfg.Role == "client" {
		statusPath := cfg.StatusFile
		if statusPath == "" {
			statusPath = filepath.Join(cfg.DataDir, "status.json")
		}
		if raw, err := os.ReadFile(statusPath); err == nil {
			var clientStatus map[string]any
			if json.Unmarshal(raw, &clientStatus) == nil {
				payload["client"] = clientStatus
			}
		}
	}
	writeJSON(writer, http.StatusOK, payload)
}

func (state *ipcState) handleUp(writer http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodPost {
		http.Error(writer, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if state.supervisor == nil {
		writeJSON(writer, http.StatusConflict, map[string]any{"error": "up is only supported by client and daemon roles"})
		return
	}
	state.mu.Lock()
	state.state = "starting"
	state.lastErr = ""
	state.mu.Unlock()
	state.supervisor.Start()
	writeJSON(writer, http.StatusOK, map[string]any{"running": true, "state": "starting"})
}

func (state *ipcState) handleDown(writer http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodPost {
		http.Error(writer, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if state.supervisor == nil {
		writeJSON(writer, http.StatusConflict, map[string]any{"error": "down is only supported by client and daemon roles"})
		return
	}
	state.mu.Lock()
	state.state = "stopping"
	state.mu.Unlock()
	state.supervisor.Stop()
	state.mu.Lock()
	if state.state != "error" {
		state.state = "stopped"
	}
	state.mu.Unlock()
	writeJSON(writer, http.StatusOK, map[string]any{"running": false, "state": "stopped"})
}

func (state *ipcState) clientStopped(err error) {
	state.mu.Lock()
	if err != nil && !errors.Is(err, context.Canceled) {
		state.state = "error"
		state.lastErr = err.Error()
	} else if state.state != "error" {
		state.state = "stopped"
	}
	state.mu.Unlock()
}

func (state *ipcState) startClient() bool {
	return state.supervisor != nil && state.supervisor.Start()
}

func (state *ipcState) stopClient() bool {
	return state.supervisor != nil && state.supervisor.Stop()
}

func (state *ipcState) handleDoctor(writer http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodGet {
		http.Error(writer, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	state.mu.RLock()
	cfg := state.cfg
	state.mu.RUnlock()
	checks := []map[string]any{
		{"name": "version", "ok": true, "detail": version.Version},
		{"name": "protocol", "ok": true, "detail": version.ProtocolVersion},
		{"name": "ipc", "ok": true, "detail": cfg.IPC.Path},
		{"name": "dataDir", "ok": true, "detail": cfg.DataDir},
	}
	if cfg.Manager != "" {
		checks = append(checks, map[string]any{"name": "manager", "ok": true, "detail": cfg.Manager})
	}
	writeJSON(writer, http.StatusOK, map[string]any{"version": version.Version, "checks": checks})
}

func (state *ipcState) handlePing(writer http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodGet {
		http.Error(writer, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	writeJSON(writer, http.StatusOK, map[string]any{"ok": true, "version": version.Version})
}

func writeJSON(writer http.ResponseWriter, status int, payload any) {
	writer.Header().Set("Content-Type", "application/json")
	writer.WriteHeader(status)
	_ = json.NewEncoder(writer).Encode(payload)
}
