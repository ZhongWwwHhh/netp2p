package manager

import (
	"errors"
	"testing"
	"time"

	"github.com/libp2p/go-libp2p/core/peer"
	ma "github.com/multiformats/go-multiaddr"
	"github.com/netp2p/netp2p/internal/model"
)

func TestCommitteeReadinessCacheSuppressesProbeStorm(t *testing.T) {
	mesh := &CommitteeMesh{}
	mesh.readinessMu.Lock()
	mesh.readinessCache = CommitteeReadiness{}
	mesh.readinessErr = ErrCommitteeUnavailable
	mesh.readinessAt = time.Now()
	mesh.readinessMu.Unlock()

	for attempt := 0; attempt < 10; attempt++ {
		if _, err := mesh.ensureCommitteeAvailableCached(); !errors.Is(err, ErrCommitteeUnavailable) {
			t.Fatalf("attempt %d error = %v, want committee unavailable", attempt+1, err)
		}
	}
}

func TestSetupKeyPreflightDoesNotConsumeVerifierBudget(t *testing.T) {
	mesh := &CommitteeMesh{}
	mesh.readinessMu.Lock()
	mesh.readinessCache = CommitteeReadiness{}
	mesh.readinessErr = ErrCommitteeUnavailable
	mesh.readinessAt = time.Now()
	mesh.readinessMu.Unlock()
	manager := &Manager{mesh: mesh, tokenLimiter: newTokenRateLimiter()}

	for attempt := 0; attempt < setupKeyTokenAttempts; attempt++ {
		if err := manager.setupKeyPreflight(); !errors.Is(err, ErrCommitteeUnavailable) {
			t.Fatalf("attempt %d error = %v, want committee unavailable", attempt+1, err)
		}
	}
	if !manager.tokenLimiter.Allow("peer-a", setupKeyTokenAttempts) {
		t.Fatal("committee outage consumed the setup key verifier budget")
	}
}

func TestTokenRateLimiterAllowsLimitedAttempts(t *testing.T) {
	limiter := newTokenRateLimiter()
	for attempt := 1; attempt <= setupKeyTokenAttempts; attempt++ {
		if !limiter.Allow("peer-a", setupKeyTokenAttempts) {
			t.Fatalf("attempt %d was rejected before the configured limit", attempt)
		}
	}
	if limiter.Allow("peer-a", setupKeyTokenAttempts) {
		t.Fatal("attempt beyond the configured limit was allowed")
	}
	if !limiter.Allow("peer-b", setupKeyTokenAttempts) {
		t.Fatal("a different authenticated peer was incorrectly rate limited")
	}
}

func TestManagerJoinTokenConsumed(t *testing.T) {
	state := model.NetworkState{ManagerJoins: []model.ManagerJoinRequest{{
		ID: "join-d", ManagerID: "D", Status: model.ManagerJoinActivated,
	}}}
	if !managerJoinTokenConsumed(state) {
		t.Fatal("activated legacy state was not treated as consumed")
	}

	state = model.NetworkState{ManagerJoins: []model.ManagerJoinRequest{{
		ID: "join-d", ManagerID: "D", Status: model.ManagerJoinPending,
	}}}
	if managerJoinTokenConsumed(state) {
		t.Fatal("pending join incorrectly consumed the token")
	}
}

func TestTokenRateKeyCombinesPeerAndTransportAddress(t *testing.T) {
	address, err := ma.NewMultiaddr("/ip4/198.51.100.10/udp/4001/quic-v1")
	if err != nil {
		t.Fatal(err)
	}
	remote := peer.ID("manager-peer")
	got := tokenRateKey(remote, address)
	if got != remote.String()+"|198.51.100.10" {
		t.Fatalf("token rate key = %q", got)
	}
}

func TestAuthorizeManagerJoinRejectsConsumedQueriesFromUnknownPeers(t *testing.T) {
	state := model.NetworkState{ManagerJoinTokenConsumed: true}
	remote := peer.ID("unknown-candidate")
	if err := authorizeManagerJoin(state, "", model.StateTransition{}.Type, remote); err == nil {
		t.Fatal("consumed join mutation was authorized")
	}
	if err := authorizeManagerJoin(state, "snapshot", "", remote); err == nil {
		t.Fatal("consumed join query was authorized for an unknown candidate")
	}
}
