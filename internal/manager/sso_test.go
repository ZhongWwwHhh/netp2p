package manager

import (
	"testing"
	"time"

	"github.com/netp2p/netp2p/internal/model"
)

func TestLoginExpired(t *testing.T) {
	now := time.Date(2026, 9, 19, 12, 0, 0, 0, time.UTC)
	old := now.Add(-40 * 24 * time.Hour)
	recent := now.Add(-2 * 24 * time.Hour)
	freshToken := now.Add(-time.Minute)
	staleToken := now.Add(-50 * 24 * time.Hour)

	if loginExpired(0, old, staleToken, now) {
		t.Fatal("expiration disabled must never expire")
	}
	if !loginExpired(30, old, staleToken, now) {
		t.Fatal("40-day-old login with a stale token must expire")
	}
	if loginExpired(30, old, freshToken, now) {
		t.Fatal("a token issued after the last login must refresh the window")
	}
	if loginExpired(30, recent, staleToken, now) {
		t.Fatal("a recent login must stay valid")
	}
}

func TestShouldRefreshLogin(t *testing.T) {
	if !shouldRefreshLogin("") {
		t.Fatal("an empty timestamp needs a refresh")
	}
	if !shouldRefreshLogin("not-a-time") {
		t.Fatal("an unparseable timestamp needs a refresh")
	}
	if shouldRefreshLogin(time.Now().Add(-time.Hour).Format(time.RFC3339)) {
		t.Fatal("an hour-old timestamp must not refresh")
	}
	if !shouldRefreshLogin(time.Now().Add(-48 * time.Hour).Format(time.RFC3339)) {
		t.Fatal("a two-day-old timestamp must refresh")
	}
}

func TestUniqueGroupID(t *testing.T) {
	state := model.NetworkState{Groups: []model.Group{{ID: "jwt-eng"}}}
	if got := uniqueGroupID(state, "Engineering Team"); got != "jwt-engineering-team" {
		t.Fatalf("id = %q", got)
	}
	if got := uniqueGroupID(state, "eng"); got != "jwt-eng-2" {
		t.Fatalf("collision should suffix, got %q", got)
	}
	if got := uniqueGroupID(model.NetworkState{}, "!!!"); got != "jwt-group" {
		t.Fatalf("unusable name = %q", got)
	}
}

func TestDedupeStringsSortsAndDropsEmpty(t *testing.T) {
	got := dedupeStrings([]string{"b", "", "a", "b"})
	if len(got) != 2 || got[0] != "a" || got[1] != "b" {
		t.Fatalf("dedupe = %v", got)
	}
}
