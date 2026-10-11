package main

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestProvisionRejectsOversizedAndTrailingJSON(t *testing.T) {
	state := &ipcState{supervisor: &clientSupervisor{}, configPath: "unused"}

	request := httptest.NewRequest(http.MethodPost, "/v1/provision", bytes.NewReader(make([]byte, maxIPCJSONBody+1)))
	recorder := httptest.NewRecorder()
	state.handleProvision(recorder, request)
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("oversized body status = %d, want 400", recorder.Code)
	}

	request = httptest.NewRequest(http.MethodPost, "/v1/provision", strings.NewReader(`{}{}`))
	recorder = httptest.NewRecorder()
	state.handleProvision(recorder, request)
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("trailing JSON status = %d, want 400", recorder.Code)
	}
	if !strings.Contains(recorder.Body.String(), "exactly one JSON object") {
		t.Fatalf("response = %s", recorder.Body.String())
	}
}
