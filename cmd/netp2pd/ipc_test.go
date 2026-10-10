package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
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
