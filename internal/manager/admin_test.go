package manager

import (
	"bytes"
	"testing"

	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/netp2p/netp2p/internal/bft"
	"github.com/netp2p/netp2p/internal/model"
)

func TestActiveManagerJoinTokenHashPrefersCertifiedVerifier(t *testing.T) {
	legacy := bytes.Repeat([]byte{1}, 32)
	certified := bytes.Repeat([]byte{2}, 32)

	state := model.NetworkState{ManagerJoinTokenHash: certified}
	if got := activeManagerJoinTokenHash(state, legacy); !bytes.Equal(got, certified) {
		t.Fatalf("certified verifier was not preferred: %x", got)
	}

	state = model.NetworkState{}
	if got := activeManagerJoinTokenHash(state, legacy); !bytes.Equal(got, legacy) {
		t.Fatalf("legacy verifier was not used for genesis state: %x", got)
	}

	state = model.NetworkState{ManagerJoinTokenHash: []byte("invalid")}
	if got := activeManagerJoinTokenHash(state, legacy); got != nil {
		t.Fatalf("malformed certified verifier fell back to legacy verifier: %x", got)
	}
}

func TestManagerJoinTokenMatches(t *testing.T) {
	verifier := model.ManagerJoinTokenHash("manager-join-token")
	if !managerJoinTokenMatches("manager-join-token", verifier) {
		t.Fatal("valid manager join token did not match its verifier")
	}
	if managerJoinTokenMatches("other-manager-join-token", verifier) {
		t.Fatal("different manager join token matched the verifier")
	}
	if managerJoinTokenMatches("manager-join-token", bytes.Repeat([]byte{9}, 31)) {
		t.Fatal("malformed verifier was accepted")
	}
}

func TestAuthorizeManagerJoinAfterRotationAndConsumption(t *testing.T) {
	remote := peer.ID("candidate-peer")
	state := model.NetworkState{
		ManagerJoinTokenHash:     bytes.Repeat([]byte{3}, 32),
		ManagerJoinTokenConsumed: true,
		ManagerJoins: []model.ManagerJoinRequest{{
			PeerID: remote.String(), Status: model.ManagerJoinApproved,
		}},
	}

	// Activation polling must remain available to the candidate that used the
	// token, even though no second manager may submit with that token.
	if err := authorizeManagerJoin(state, "snapshot", "", remote); err != nil {
		t.Fatalf("snapshot query rejected after consumption: %v", err)
	}
	if err := authorizeManagerJoin(state, "manager-snapshot", "", remote); err != nil {
		t.Fatalf("manager snapshot query rejected after consumption: %v", err)
	}
	err := authorizeManagerJoin(state, "", bft.TransitionSubmitManagerJoin, remote)
	if err == nil || err.Error() != "manager join token has already been consumed" {
		t.Fatalf("new join submission after consumption returned %v", err)
	}

	state.ManagerJoinTokenConsumed = false
	if err := authorizeManagerJoin(state, "", bft.TransitionSubmitManagerJoin, remote); err != nil {
		t.Fatalf("join submission after rotation was rejected: %v", err)
	}
	if err := authorizeManagerJoin(state, "", bft.TransitionUpsertGroup, remote); err == nil {
		t.Fatal("manager join token was allowed to submit an administrative transition")
	}
	if err := authorizeManagerJoin(state, "metrics", "", remote); err == nil {
		t.Fatal("manager join token was allowed to use an administrative query")
	}
}

func TestManagerJoinTokenConsumedRuntimeState(t *testing.T) {
	state := model.NetworkState{
		ManagerJoinTokenHash:     bytes.Repeat([]byte{4}, 32),
		ManagerJoinTokenConsumed: true,
	}
	if !managerJoinTokenConsumed(state) {
		t.Fatal("explicit consumed state was not honored")
	}

	state.ManagerJoinTokenConsumed = false
	if managerJoinTokenConsumed(state) {
		t.Fatal("certified verifier with unconsumed state was treated as consumed")
	}

	state = model.NetworkState{ManagerJoins: []model.ManagerJoinRequest{{
		ID: "legacy-manager", Status: model.ManagerJoinActivated,
	}}}
	if !managerJoinTokenConsumed(state) {
		t.Fatal("legacy activated manager join was not treated as consumed")
	}
}
