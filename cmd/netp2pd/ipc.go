package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/netp2p/netp2p/internal/client"
	"github.com/netp2p/netp2p/internal/runtimeconfig"
	"github.com/netp2p/netp2p/internal/version"
	"gopkg.in/yaml.v3"
)

var activeClient atomic.Pointer[client.Client]

// maxIPCJSONBody bounds the locally submitted client profile. It is larger
// than any generated runtime profile but small enough to contain a hostile
// local request before it can exhaust daemon memory.
const maxIPCJSONBody = 1 << 20

type ipcState struct {
	mu         sync.RWMutex
	cfg        runtimeConfig
	configPath string
	started    time.Time
	state      string
	lastErr    string
	supervisor *clientSupervisor
}

func newIPCState(ctx context.Context, cfg runtimeConfig, configPath string, startClient func(context.Context, runtimeConfig) error) *ipcState {
	state := "running"
	if cfg.Role == "daemon" {
		state = "idle"
	}
	if (cfg.Role == "client" || cfg.Role == "daemon") && isUnprovisionedClientConfig(cfg) {
		state = "needs-login"
	}
	result := &ipcState{cfg: cfg, configPath: configPath, started: time.Now(), state: state}
	if cfg.Role == "client" || cfg.Role == "daemon" {
		result.supervisor = newClientSupervisor(ctx, func(clientContext context.Context) error {
			return startClient(clientContext, result.currentConfig())
		}, result.clientStopped)
		_ = os.Remove(result.statusPath())
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
	mux.HandleFunc("/v1/reload", state.handleReload)
	mux.HandleFunc("/v1/provision", state.handleProvision)
	mux.HandleFunc("/v1/doctor", state.handleDoctor)
	mux.HandleFunc("/v1/netcheck", state.handleDoctor)
	mux.HandleFunc("/v1/ping", state.handlePing)
	server := &http.Server{
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
	}
	server.SetKeepAlivesEnabled(false)
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
		statusPath := state.statusPath()
		if raw, err := os.ReadFile(statusPath); err == nil {
			var clientStatus map[string]any
			if json.Unmarshal(raw, &clientStatus) == nil {
				payload["client"] = clientStatus
				if ready := processStateForClient(currentState, clientStatus); ready != currentState {
					state.mu.Lock()
					state.state = ready
					state.mu.Unlock()
					currentState = ready
					payload["state"] = currentState
				}
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
	if state.unprovisioned() {
		writeJSON(writer, http.StatusConflict, map[string]any{
			"error": "client is not provisioned; run netp2p login first",
			"state": "needs-login",
		})
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
	_ = os.Remove(state.statusPath())
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

func (state *ipcState) currentConfig() runtimeConfig {
	state.mu.RLock()
	defer state.mu.RUnlock()
	return state.cfg
}

func (state *ipcState) statusPath() string {
	cfg := state.currentConfig()
	if cfg.StatusFile != "" {
		return cfg.StatusFile
	}
	return filepath.Join(cfg.DataDir, "status.json")
}

func (state *ipcState) reloadConfig() error {
	if state.configPath == "" {
		return fmt.Errorf("daemon config path is unknown")
	}
	cfg, err := parseRuntimeConfig(state.configPath)
	if err != nil {
		return fmt.Errorf("reload runtime config: %w", err)
	}
	if err := hydrateClientRecovery(&cfg); err != nil {
		return fmt.Errorf("reload runtime config: %w", err)
	}
	if cfg.Role == "client" && cfg.StatusFile == "" {
		cfg.StatusFile = filepath.Join(cfg.DataDir, "status.json")
	}
	_ = os.Remove(state.statusPath())
	_ = state.stopClient()
	state.mu.Lock()
	state.cfg = cfg
	state.state = "stopped"
	if isUnprovisionedClientConfig(cfg) {
		state.state = "needs-login"
	}
	state.lastErr = ""
	state.mu.Unlock()
	return nil
}

func (state *ipcState) handleReload(writer http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodPost {
		http.Error(writer, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if state.supervisor == nil {
		writeJSON(writer, http.StatusConflict, map[string]any{"error": "reload is only supported by client and daemon roles"})
		return
	}
	if err := state.reloadConfig(); err != nil {
		writeJSON(writer, http.StatusBadRequest, map[string]any{"error": err.Error()})
		return
	}
	state.mu.RLock()
	current := state.state
	state.mu.RUnlock()
	writeJSON(writer, http.StatusOK, map[string]any{"state": current})
}

func (state *ipcState) handleProvision(writer http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodPost {
		http.Error(writer, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if state.supervisor == nil || state.configPath == "" {
		writeJSON(writer, http.StatusConflict, map[string]any{"error": "provisioning is not supported by this daemon"})
		return
	}
	var cfg runtimeConfig
	decoder := json.NewDecoder(http.MaxBytesReader(writer, request.Body, maxIPCJSONBody))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&cfg); err != nil {
		writeJSON(writer, http.StatusBadRequest, map[string]any{"error": fmt.Sprintf("decode runtime config: %v", err)})
		return
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		writeJSON(writer, http.StatusBadRequest, map[string]any{"error": "runtime config must contain exactly one JSON object"})
		return
	}
	if cfg.Role != "client" {
		writeJSON(writer, http.StatusBadRequest, map[string]any{"error": "provisioning supports only client profiles"})
		return
	}
	if err := validateRuntimeConfig(cfg); err != nil {
		writeJSON(writer, http.StatusBadRequest, map[string]any{"error": err.Error()})
		return
	}
	if cfg.StatusFile == "" {
		cfg.StatusFile = filepath.Join(cfg.DataDir, "status.json")
	}
	encoded, err := yaml.Marshal(cfg)
	if err != nil {
		writeJSON(writer, http.StatusInternalServerError, map[string]any{"error": fmt.Sprintf("encode runtime config: %v", err)})
		return
	}
	if err := writeDaemonRuntimeConfig(state.configPath, encoded); err != nil {
		writeJSON(writer, http.StatusInternalServerError, map[string]any{"error": fmt.Sprintf("write runtime config: %v", err)})
		return
	}
	if err := state.reloadConfig(); err != nil {
		writeJSON(writer, http.StatusInternalServerError, map[string]any{"error": err.Error()})
		return
	}
	writeJSON(writer, http.StatusOK, map[string]any{"state": "provisioned"})
}

func (state *ipcState) unprovisioned() bool {
	state.mu.RLock()
	defer state.mu.RUnlock()
	return isUnprovisionedClientConfig(state.cfg)
}

func isUnprovisionedClientConfig(cfg runtimeConfig) bool {
	err := validateRuntimeConfig(cfg)
	return err != nil && runtimeconfig.IsUnprovisionedClientError(err)
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
	processState := state.state
	lastErr := state.lastErr
	state.mu.RUnlock()
	var clientStatus map[string]any
	statusPath := cfg.StatusFile
	if statusPath == "" {
		statusPath = filepath.Join(cfg.DataDir, "status.json")
	}
	if raw, err := os.ReadFile(statusPath); err == nil {
		if err := json.Unmarshal(raw, &clientStatus); err != nil {
			clientStatus = nil
		}
	}
	processState = processStateForClient(processState, clientStatus)
	clientState, clientNextAction := clientDoctorView(clientStatus)
	checks := []map[string]any{
		{"name": "version", "ok": true, "detail": version.Version},
		{"name": "protocol", "ok": true, "detail": version.ProtocolVersion},
		{"name": "ipc", "ok": true, "detail": cfg.IPC.Path},
		{"name": "dataDir", "ok": true, "detail": cfg.DataDir},
	}
	if cfg.Manager != "" {
		checks = append(checks, map[string]any{"name": "manager", "ok": true, "detail": cfg.Manager})
	}
	writeJSON(writer, http.StatusOK, map[string]any{
		"version": version.Version, "state": processState,
		"nextAction": doctorNextAction(processState, lastErr, clientState, clientNextAction), "checks": checks,
	})
}

func processStateForClient(processState string, clientStatus map[string]any) string {
	if processState != "starting" {
		return processState
	}
	if state, _ := clientStatus["state"].(string); state == "ready" {
		return "running"
	}
	return processState
}

func clientDoctorView(clientStatus map[string]any) (string, string) {
	state, _ := clientStatus["state"].(string)
	nextAction, _ := clientStatus["nextAction"].(string)
	return state, nextAction
}

func doctorNextAction(state, lastErr, clientState, clientNextAction string) string {
	if state == "starting" && clientState == "ready" {
		state = "running"
	}
	switch state {
	case "running":
		if clientState == "ready" {
			return "No action required; use netp2p status --json for live manager state."
		}
		if clientNextAction != "" {
			return clientNextAction
		}
		if lastErr != "" {
			return "Inspect the last error with netp2p status, then rerun netp2p doctor."
		}
		return "No action required; use netp2p status --json for live manager state."
	case "idle", "stopped":
		return "Run netp2p up to connect using the configured trust bundle and credentials."
	case "needs-login":
		return "Run netp2p login with the network manager and setup key, then run netp2p up."
	case "stopping":
		return "Wait for the client to stop; run netp2p status if it does not finish."
	case "error":
		if lastErr != "" {
			return "Fix the reported failure (" + lastErr + "), then rerun netp2p doctor."
		}
		return "Inspect netp2pd logs, fix the failure, then rerun netp2p doctor."
	default:
		return "Run netp2p status and netp2p doctor to identify the client state."
	}
}

func (state *ipcState) handlePing(writer http.ResponseWriter, request *http.Request) {
	if request.Method == http.MethodGet {
		writeJSON(writer, http.StatusOK, map[string]any{"ok": true, "version": version.Version})
		return
	}
	if request.Method != http.MethodPost {
		http.Error(writer, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	current := activeClient.Load()
	if current == nil {
		writeJSON(writer, http.StatusServiceUnavailable, map[string]any{"error": "client data plane is not active"})
		return
	}
	if err := request.ParseForm(); err != nil {
		writeJSON(writer, http.StatusBadRequest, map[string]any{"error": "parse ping request"})
		return
	}
	target := net.ParseIP(request.FormValue("target"))
	if target == nil {
		writeJSON(writer, http.StatusBadRequest, map[string]any{"error": "invalid target"})
		return
	}
	timeout := 3 * time.Second
	if raw := request.FormValue("timeout_ms"); raw != "" {
		value, err := strconv.Atoi(raw)
		if err != nil || value <= 0 || value > 10000 {
			writeJSON(writer, http.StatusBadRequest, map[string]any{"error": "invalid timeout_ms"})
			return
		}
		timeout = time.Duration(value) * time.Millisecond
	}
	elapsed, err := current.Ping(request.Context(), target, timeout)
	if err != nil {
		writeJSON(writer, http.StatusGatewayTimeout, map[string]any{"ok": false, "error": err.Error()})
		return
	}
	writeJSON(writer, http.StatusOK, map[string]any{"ok": true, "rttMs": float64(elapsed.Microseconds()) / 1000})
}

func writeJSON(writer http.ResponseWriter, status int, payload any) {
	writer.Header().Set("Content-Type", "application/json")
	writer.WriteHeader(status)
	_ = json.NewEncoder(writer).Encode(payload)
}
