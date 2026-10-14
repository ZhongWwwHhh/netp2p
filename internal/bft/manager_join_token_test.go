package bft

import (
	"bytes"
	"strings"
	"testing"

	"github.com/netp2p/netp2p/internal/model"
)

func TestManagerJoinTokenRotationLifecycle(t *testing.T) {
	state := testState()
	state.EngineCommittee = []model.CommitteeMember{{ID: "A", PeerID: "peer-A", PublicKey: []byte{1}}}
	state.ManagerJoinTokenHash = bytes.Repeat([]byte{1}, 32)
	state.ManagerJoinTokenConsumed = true
	state.ManagerJoins = []model.ManagerJoinRequest{{
		ID: "join-old", ManagerID: "old", PeerID: "peer-old",
		PublicKey: []byte{2}, RequestedAt: "2026-10-11T00:00:00Z",
		Status: model.ManagerJoinRejected,
	}}

	nextHash := bytes.Repeat([]byte{2}, 32)
	transition := model.StateTransition{
		Type: TransitionRotateManagerJoinToken, ManagerJoinTokenHash: nextHash,
		Actor: &model.Actor{ID: "owner", Role: model.RoleOwner},
	}
	beforeStateHash := StateHash(state)
	beforeTransitionHash := TransitionHash(transition)
	if bytes.Equal(beforeStateHash, StateHash(model.NetworkState{})) {
		t.Fatal("test state unexpectedly produced an empty hash")
	}
	if err := ApplyTransition(&state, transition); err != nil {
		t.Fatalf("rotate manager join token: %v", err)
	}
	if state.ManagerJoinTokenConsumed {
		t.Fatal("rotation did not clear token consumption")
	}
	if !bytes.Equal(state.ManagerJoinTokenHash, nextHash) {
		t.Fatal("rotation did not install the new verifier")
	}
	if bytes.Equal(beforeStateHash, StateHash(state)) {
		t.Fatal("state hash ignored manager join token rotation")
	}
	other := transition
	other.ManagerJoinTokenHash = bytes.Repeat([]byte{3}, 32)
	if bytes.Equal(beforeTransitionHash, TransitionHash(other)) {
		t.Fatal("transition hash ignored manager join token verifier")
	}

	request := model.ManagerJoinRequest{
		ID: "join-new", ManagerID: "new", PeerID: "peer-new",
		Address:   "/dns4/manager-new.netp2p.example/udp/4001/quic-v1",
		PublicKey: []byte{3}, RequestedAt: "2026-10-11T01:00:00Z",
		Status: model.ManagerJoinPending,
	}
	if err := ApplyTransition(&state, model.StateTransition{
		Type: TransitionSubmitManagerJoin, ManagerJoin: &request,
	}); err != nil {
		t.Fatalf("submit after token rotation: %v", err)
	}

	reviewed := request
	reviewed.Status = model.ManagerJoinApproved
	reviewed.ReviewedBy = "owner@example.com"
	reviewed.ReviewedAt = "2026-10-11T01:01:00Z"
	if err := ApplyTransition(&state, model.StateTransition{
		Type: TransitionReviewManagerJoin, ManagerJoin: &reviewed,
		Actor: &model.Actor{ID: "owner", Role: model.RoleOwner},
	}); err != nil {
		t.Fatalf("review after token rotation: %v", err)
	}
}

func TestManagerJoinTokenRotationRejectsInvalidTransitions(t *testing.T) {
	actor := &model.Actor{ID: "owner", Role: model.RoleOwner}
	tests := []struct {
		name       string
		state      model.NetworkState
		transition model.StateTransition
		message    string
	}{
		{
			name:       "missing verifier",
			transition: model.StateTransition{Type: TransitionRotateManagerJoinToken, Actor: actor},
			message:    "32 bytes",
		},
		{
			name: "short verifier",
			transition: model.StateTransition{
				Type: TransitionRotateManagerJoinToken, ManagerJoinTokenHash: []byte{1}, Actor: actor,
			},
			message: "32 bytes",
		},
		{
			name:  "same verifier",
			state: model.NetworkState{ManagerJoinTokenHash: bytes.Repeat([]byte{7}, 32)},
			transition: model.StateTransition{
				Type: TransitionRotateManagerJoinToken, ManagerJoinTokenHash: bytes.Repeat([]byte{7}, 32), Actor: actor,
			},
			message: "must change",
		},
		{
			name: "missing actor",
			transition: model.StateTransition{
				Type: TransitionRotateManagerJoinToken, ManagerJoinTokenHash: bytes.Repeat([]byte{8}, 32),
			},
			message: "authenticated actor",
		},
		{
			name: "active request",
			state: model.NetworkState{ManagerJoins: []model.ManagerJoinRequest{{
				ID: "join-active", Status: model.ManagerJoinApproved,
			}}},
			transition: model.StateTransition{
				Type: TransitionRotateManagerJoinToken, ManagerJoinTokenHash: bytes.Repeat([]byte{9}, 32), Actor: actor,
			},
			message: "must be rejected",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := ApplyTransition(&test.state, test.transition)
			if err == nil || !strings.Contains(err.Error(), test.message) {
				t.Fatalf("error = %v, want containing %q", err, test.message)
			}
		})
	}
}

func TestManagerJoinTokenConsumptionBlocksSubmissionAndReview(t *testing.T) {
	state := testState()
	state.EngineCommittee = []model.CommitteeMember{{ID: "A", PeerID: "peer-A", PublicKey: []byte{1}}}
	state.ManagerJoinTokenConsumed = true
	state.ManagerJoins = []model.ManagerJoinRequest{{
		ID: "join-pending", ManagerID: "pending", PeerID: "peer-pending",
		PublicKey: []byte{2}, RequestedAt: "2026-10-11T00:00:00Z",
		Status: model.ManagerJoinPending,
	}}

	request := state.ManagerJoins[0]
	err := ApplyTransition(&state, model.StateTransition{
		Type: TransitionSubmitManagerJoin, ManagerJoin: &request,
	})
	if err == nil || !strings.Contains(err.Error(), "already been consumed") {
		t.Fatalf("submit error = %v, want token consumed", err)
	}

	reviewed := request
	reviewed.Status = model.ManagerJoinApproved
	reviewed.ReviewedBy = "owner@example.com"
	reviewed.ReviewedAt = "2026-10-11T00:01:00Z"
	err = ApplyTransition(&state, model.StateTransition{
		Type: TransitionReviewManagerJoin, ManagerJoin: &reviewed,
		Actor: &model.Actor{ID: "owner", Role: model.RoleOwner},
	})
	if err == nil || !strings.Contains(err.Error(), "already been consumed") {
		t.Fatalf("review error = %v, want token consumed", err)
	}
}

func TestManagerJoinTokenConsumptionAllowsStaleRequestRejection(t *testing.T) {
	state := testState()
	state.ManagerJoinTokenConsumed = true
	state.ManagerJoins = []model.ManagerJoinRequest{{
		ID: "join-stale", ManagerID: "stale", PeerID: "peer-stale",
		PublicKey: []byte{2}, RequestedAt: "2026-10-11T00:00:00Z",
		Status: model.ManagerJoinApproved,
	}}
	reviewed := state.ManagerJoins[0]
	reviewed.Status = model.ManagerJoinRejected
	reviewed.ReviewedBy = "owner@example.com"
	reviewed.ReviewedAt = "2026-10-11T00:01:00Z"
	if err := ApplyTransition(&state, model.StateTransition{
		Type: TransitionReviewManagerJoin, ManagerJoin: &reviewed,
		Actor: &model.Actor{ID: "owner", Role: model.RoleOwner},
	}); err != nil {
		t.Fatalf("reject stale request after token consumption: %v", err)
	}

	verifier := bytes.Repeat([]byte{4}, 32)
	if err := ApplyTransition(&state, model.StateTransition{
		Type: TransitionRotateManagerJoinToken, ManagerJoinTokenHash: verifier,
		Actor: &model.Actor{ID: "owner", Role: model.RoleOwner},
	}); err != nil {
		t.Fatalf("rotate after rejecting stale request: %v", err)
	}
	if state.ManagerJoinTokenConsumed || !bytes.Equal(state.ManagerJoinTokenHash, verifier) {
		t.Fatalf("unexpected token state after rotation: consumed=%v hash=%v", state.ManagerJoinTokenConsumed, state.ManagerJoinTokenHash)
	}
}
