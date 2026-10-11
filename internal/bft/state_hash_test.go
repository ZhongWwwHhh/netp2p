package bft

import (
	"bytes"
	"testing"

	"github.com/netp2p/netp2p/internal/model"
)

func TestStateHashExcludesPasswordVerifiers(t *testing.T) {
	state := model.NetworkState{
		NetworkID:   "network",
		OverlayCIDR: "100.64.0.0/24",
		Users: []model.User{{
			ID:               "user-1",
			Email:            "user@example.com",
			Role:             model.RoleUser,
			PasswordVerifier: model.HashPassword("correct horse battery"),
		}},
	}
	first := StateHash(state)
	state.Users[0].PasswordVerifier = model.HashPassword("another password")
	second := StateHash(state)
	state.Users[0].PasswordVerifier = nil
	third := StateHash(state)
	if !bytes.Equal(first, second) || !bytes.Equal(first, third) {
		t.Fatal("password verifier changed the certified state hash")
	}
}
