package web

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/netp2p/netp2p/internal/auth"
	"github.com/netp2p/netp2p/internal/model"
)

type failingSessionSyncer struct{}

func (failingSessionSyncer) Sync(context.Context) error {
	return errors.New("committee not ready")
}

type retrySessionSyncer struct {
	failures int
	calls    int
}

func (syncer *retrySessionSyncer) Sync(context.Context) error {
	syncer.calls++
	if syncer.calls <= syncer.failures {
		return errors.New("temporary replication failure")
	}
	return nil
}

func TestIssueLocalSessionSurvivesReplicationOutage(t *testing.T) {
	server, accounts, _ := newLocalAuthTestServer(t)
	accounts.users = []model.User{{ID: "user-1", Email: "user@example.com", Role: model.RoleUser}}
	server.sessionSyncer = failingSessionSyncer{}
	previousDelay := sessionReplicationRetryDelay
	sessionReplicationRetryDelay = 0
	t.Cleanup(func() { sessionReplicationRetryDelay = previousDelay })

	var logs bytes.Buffer
	previousOutput := log.Writer()
	log.SetOutput(&logs)
	t.Cleanup(func() { log.SetOutput(previousOutput) })

	token, _, err := server.issueLocalSession(auth.Identity{UserID: "user-1", Role: model.RoleUser}, time.Now())
	if err != nil {
		t.Fatalf("issue session during replication outage: %v", err)
	}
	if !server.sessionReplicationDegraded.Load() {
		t.Fatal("session replication was not marked degraded")
	}
	if strings.Contains(logs.String(), token) {
		t.Fatal("session token leaked into replication log")
	}

	request := httptest.NewRequest(http.MethodGet, "/api/v1/session", nil)
	request.Header.Set("Authorization", "Bearer "+token)
	if _, ok := server.authenticate(request); !ok {
		t.Fatal("locally persisted session was not accepted during replication outage")
	}
}

func TestIssueLocalSessionRetriesTransientReplicationFailure(t *testing.T) {
	server, accounts, _ := newLocalAuthTestServer(t)
	accounts.users = []model.User{{ID: "user-1", Email: "user@example.com", Role: model.RoleUser}}
	syncer := &retrySessionSyncer{failures: 2}
	server.sessionSyncer = syncer
	previousDelay := sessionReplicationRetryDelay
	sessionReplicationRetryDelay = 0
	t.Cleanup(func() { sessionReplicationRetryDelay = previousDelay })

	if _, _, err := server.issueLocalSession(auth.Identity{UserID: "user-1", Role: model.RoleUser}, time.Now()); err != nil {
		t.Fatalf("issue session after transient failure: %v", err)
	}
	if syncer.calls != 3 {
		t.Fatalf("replication calls = %d, want 3", syncer.calls)
	}
	if server.sessionReplicationDegraded.Load() {
		t.Fatal("session remained degraded after successful replication")
	}
}

func TestOwnerBootstrapReturnsSessionWhenReplicationIsDegraded(t *testing.T) {
	server, _, _ := newLocalAuthTestServer(t)
	server.sessionSyncer = failingSessionSyncer{}
	previousDelay := sessionReplicationRetryDelay
	sessionReplicationRetryDelay = 0
	t.Cleanup(func() { sessionReplicationRetryDelay = previousDelay })

	body, err := json.Marshal(ownerBootstrapRequest{
		Email: "owner@example.com", Name: "Owner", Password: "owner-password-2026",
	})
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodPost, "/api/v1/bootstrap/owner", bytes.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	recorder := httptest.NewRecorder()
	server.handleOwnerBootstrap(recorder, request)
	if recorder.Code != http.StatusOK {
		t.Fatalf("owner bootstrap status = %d body %q", recorder.Code, recorder.Body.String())
	}
	if !strings.Contains(recorder.Header().Get("Set-Cookie"), "netp2p_session=") {
		t.Fatal("owner bootstrap did not issue a local session cookie")
	}
	if !strings.Contains(recorder.Body.String(), `"sessionReplicationDegraded":true`) {
		t.Fatalf("owner bootstrap did not report degraded replication: %s", recorder.Body.String())
	}
}
