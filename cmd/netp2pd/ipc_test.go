package main

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestIPCClientLifecycleDoesNotCancelParent(t *testing.T) {
	parent, cancelParent := context.WithCancel(context.Background())
	defer cancelParent()
	started := make(chan struct{})
	state := newIPCState(parent, runtimeConfig{Role: "daemon"}, func(ctx context.Context) error {
		close(started)
		<-ctx.Done()
		return nil
	})

	up := httptest.NewRequest(http.MethodPost, "/v1/up", nil)
	state.handleUp(httptest.NewRecorder(), up)
	state.handleUp(httptest.NewRecorder(), httptest.NewRequest(http.MethodPost, "/v1/up", nil))
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("up did not start the client")
	}

	state.handleDown(httptest.NewRecorder(), httptest.NewRequest(http.MethodPost, "/v1/down", nil))
	if currentState := ipcStateForTest(t, state); currentState != "stopped" {
		t.Fatalf("state after down = %q, want stopped", currentState)
	}
	select {
	case <-parent.Done():
		t.Fatal("down canceled the parent daemon context")
	default:
	}
}

func TestIPCClientStartErrorIsRecorded(t *testing.T) {
	parent, cancelParent := context.WithCancel(context.Background())
	defer cancelParent()
	state := newIPCState(parent, runtimeConfig{Role: "daemon"}, func(context.Context) error {
		return errors.New("client failed")
	})
	state.handleUp(httptest.NewRecorder(), httptest.NewRequest(http.MethodPost, "/v1/up", nil))

	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		state.mu.RLock()
		currentState, lastErr := state.state, state.lastErr
		state.mu.RUnlock()
		if currentState == "error" && lastErr == "client failed" {
			select {
			case <-parent.Done():
				t.Fatal("client error canceled the parent daemon context")
			default:
				return
			}
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("client start error was not recorded")
}

func TestIPCUnsupportedRoleReturnsConflict(t *testing.T) {
	state := newIPCState(context.Background(), runtimeConfig{Role: "manager"}, nil)
	recorder := httptest.NewRecorder()
	state.handleUp(recorder, httptest.NewRequest(http.MethodPost, "/v1/up", nil))
	if recorder.Code != http.StatusConflict {
		t.Fatalf("up status = %d, want %d", recorder.Code, http.StatusConflict)
	}
	recorder = httptest.NewRecorder()
	state.handleDown(recorder, httptest.NewRequest(http.MethodPost, "/v1/down", nil))
	if recorder.Code != http.StatusConflict {
		t.Fatalf("down status = %d, want %d", recorder.Code, http.StatusConflict)
	}
}

func ipcStateForTest(t *testing.T, state *ipcState) string {
	t.Helper()
	recorder := httptest.NewRecorder()
	state.handleStatus(recorder, httptest.NewRequest(http.MethodGet, "/v1/status", nil))
	var payload struct {
		State string `json:"state"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &payload); err != nil {
		t.Fatal(err)
	}
	return payload.State
}
