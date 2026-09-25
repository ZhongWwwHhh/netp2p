package client

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/netp2p/netp2p/internal/forward"
	"github.com/netp2p/netp2p/internal/model"
)

func newTestStore(t *testing.T) (*pathStore, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "paths.json")
	return loadPathStore(path, defaultPathTTL), path
}

func selectorWithStore(store *pathStore) *pathSelector {
	return newPathSelector(forward.NewTable(model.NetworkState{}, "manager", func(peer.ID, forward.Envelope) error { return nil }), store)
}

// TestPersistedLastGoodPathIsPreferred proves a restart resumes from the path
// that last worked, even when the certified order lists another first.
func TestPersistedLastGoodPathIsPreferred(t *testing.T) {
	store, path := newTestStore(t)
	source, _ := peer.Decode(peerSource)
	destination, _ := peer.Decode(peerDestination)

	first := selectorWithStore(store)
	first.replaceAssignments([]model.RouteAssignment{assignment()})
	if _, chosen, ok := first.selectFor(source, destination); !ok || chosen.ID != "direct" {
		t.Fatalf("initial selection = %+v ok=%v", chosen, ok)
	}
	// Mark direct unusable so the selector persists the via fallback as LKG.
	first.record("direct", false)
	first.record("direct", false)
	if _, chosen, ok := first.selectFor(source, destination); !ok || chosen.ID != "via" {
		t.Fatalf("fallback selection = %+v ok=%v", chosen, ok)
	}
	store.close()

	// A fresh selector over the same file must still prefer via, without any
	// admission activity of its own.
	reloaded := selectorWithStore(loadPathStore(path, defaultPathTTL))
	reloaded.replaceAssignments([]model.RouteAssignment{assignment()})
	_, chosen, ok := reloaded.selectFor(source, destination)
	if !ok || chosen.ID != "via" {
		t.Fatalf("reloaded selection = %+v ok=%v, want persistent last-known-good 'via'", chosen, ok)
	}
}

// TestPersistedAdmissionSkipsFailedPath proves a path the client proved dead
// before restarting is not retried blindly: the LKG hint must not resurrect it.
func TestPersistedAdmissionSkipsFailedPath(t *testing.T) {
	store, path := newTestStore(t)
	source, _ := peer.Decode(peerSource)
	destination, _ := peer.Decode(peerDestination)

	first := selectorWithStore(store)
	first.replaceAssignments([]model.RouteAssignment{assignment()})
	// Direct is the persisted last-good, but it is also proven unreachable.
	first.record("direct", false)
	first.record("direct", false)
	store.close()

	reloaded := selectorWithStore(loadPathStore(path, defaultPathTTL))
	reloaded.replaceAssignments([]model.RouteAssignment{assignment()})
	_, chosen, ok := reloaded.selectFor(source, destination)
	if !ok || chosen.ID != "via" {
		t.Fatalf("selection = %+v ok=%v, want fallback because direct is persisted as failed", chosen, ok)
	}
}

// TestPersistedHintOutsideAssignmentIsIgnored proves the store can only reorder
// paths the committee certified; it can never invent one.
func TestPersistedHintOutsideAssignmentIsIgnored(t *testing.T) {
	store, _ := newTestStore(t)
	store.setLastGood(peerDestination, "retired-path")
	selector := selectorWithStore(store)
	source, _ := peer.Decode(peerSource)
	destination, _ := peer.Decode(peerDestination)
	selector.replaceAssignments([]model.RouteAssignment{assignment()})
	if _, chosen, ok := selector.selectFor(source, destination); !ok || chosen.ID != "direct" {
		t.Fatalf("selection = %+v ok=%v, want certified primary despite stale hint", chosen, ok)
	}
}

// TestExpiredEntriesAreDropped proves a hint older than the TTL is discarded
// rather than trusted indefinitely.
func TestExpiredEntriesAreDropped(t *testing.T) {
	path := filepath.Join(t.TempDir(), "paths.json")
	stale := time.Now().Add(-2 * defaultPathTTL)
	store := loadPathStore(path, defaultPathTTL)
	store.now = func() time.Time { return stale }
	store.setLastGood(peerDestination, "direct")
	store.recordAdmission("direct", true)
	store.close()

	fresh := loadPathStore(path, defaultPathTTL)
	if _, ok := fresh.lastGood(peerDestination); ok {
		t.Fatal("expired destination hint was not dropped")
	}
	if _, ok := fresh.admission("direct"); ok {
		t.Fatal("expired admission entry was not dropped")
	}
}

// TestCorruptStoreStartsEmpty proves a damaged cache degrades to no cache
// rather than crashing the client.
func TestCorruptStoreStartsEmpty(t *testing.T) {
	path := filepath.Join(t.TempDir(), "paths.json")
	if err := os.WriteFile(path, []byte("{not json"), 0o644); err != nil {
		t.Fatal(err)
	}
	store := loadPathStore(path, defaultPathTTL)
	if _, ok := store.lastGood(peerDestination); ok {
		t.Fatal("corrupt store returned a hint")
	}
	store.setLastGood(peerDestination, "direct")
	store.close()
	if _, ok := loadPathStore(path, defaultPathTTL).lastGood(peerDestination); !ok {
		t.Fatal("store did not recover after being rewritten")
	}
}

// TestNilStoreKeepsLegacyBehavior proves the default (no state dir) path never
// consults persistence.
func TestNilStoreKeepsLegacyBehavior(t *testing.T) {
	selector := newPathSelector(forward.NewTable(model.NetworkState{}, "manager", func(peer.ID, forward.Envelope) error { return nil }), nil)
	source, _ := peer.Decode(peerSource)
	destination, _ := peer.Decode(peerDestination)
	selector.replaceAssignments([]model.RouteAssignment{assignment()})
	if _, chosen, ok := selector.selectFor(source, destination); !ok || chosen.ID != "direct" {
		t.Fatalf("selection = %+v ok=%v", chosen, ok)
	}
	selector.record("direct", false)
	if selector.store != nil {
		t.Fatal("selector without a state dir should not have a store")
	}
}
