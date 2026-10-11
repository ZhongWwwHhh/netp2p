package client

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/netp2p/netp2p/internal/bft"
	"github.com/netp2p/netp2p/internal/forward"
	"github.com/netp2p/netp2p/internal/model"
	"github.com/netp2p/netp2p/internal/p2p"
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
	if err := first.syncSnapshot(pathSnapshot(true, assignment())); err != nil {
		t.Fatal(err)
	}
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
	if err := reloaded.syncSnapshot(pathSnapshot(true, assignment())); err != nil {
		t.Fatal(err)
	}
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
	if err := first.syncSnapshot(pathSnapshot(true, assignment())); err != nil {
		t.Fatal(err)
	}
	// Direct is the persisted last-good, but it is also proven unreachable.
	first.record("direct", false)
	first.record("direct", false)
	store.close()

	reloaded := selectorWithStore(loadPathStore(path, defaultPathTTL))
	if err := reloaded.syncSnapshot(pathSnapshot(true, assignment())); err != nil {
		t.Fatal(err)
	}
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
	if err := selector.syncSnapshot(pathSnapshot(true, assignment())); err != nil {
		t.Fatal(err)
	}
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
	if err := selector.syncSnapshot(pathSnapshot(true, assignment())); err != nil {
		t.Fatal(err)
	}
	if _, chosen, ok := selector.selectFor(source, destination); !ok || chosen.ID != "direct" {
		t.Fatalf("selection = %+v ok=%v", chosen, ok)
	}
	selector.record("direct", false)
	if selector.store != nil {
		t.Fatal("selector without a state dir should not have a store")
	}
}

func TestClientStatePersistenceAndRestart(t *testing.T) {
	manager := newTestP2PNode(t)
	local := newTestP2PNode(t)
	managerAddress := manager.Addresses()[0]
	stateDir := t.TempDir()
	snapshot := certifiedClientSnapshot(t, "netp2p-client-state-test")
	self := model.PeerRecord{PeerID: local.Host.ID().String(), OverlayIP: "10.80.0.11"}

	first, err := New(local, managerAddress, nil, WithStateDir(stateDir))
	if err != nil {
		t.Fatal(err)
	}
	first.applySnapshot(snapshot, self)
	if first.State() != ClientStateReady {
		t.Fatalf("state after validated snapshot = %q, want ready", first.State())
	}
	first.Close()

	restarted, err := New(local, managerAddress, nil, WithStateDir(stateDir))
	if err != nil {
		t.Fatal(err)
	}
	if restarted.State() != ClientStateDegraded {
		t.Fatalf("state after restart = %q, want degraded", restarted.State())
	}
	if restarted.SnapshotHeight() != snapshot.Height {
		t.Fatalf("restored height = %d, want %d", restarted.SnapshotHeight(), snapshot.Height)
	}
	if restarted.Self().PeerID != self.PeerID {
		t.Fatalf("restored self = %q, want %q", restarted.Self().PeerID, self.PeerID)
	}
	restarted.Close()

	otherIdentity := newTestP2PNode(t)
	mismatch, err := New(otherIdentity, managerAddress, nil, WithStateDir(stateDir))
	if err != nil {
		t.Fatal(err)
	}
	if mismatch.State() != ClientStateNeedsLogin {
		t.Fatalf("state for mismatched identity = %q, want needs-login", mismatch.State())
	}
	if mismatch.SnapshotHeight() != 0 {
		t.Fatalf("mismatched identity restored height %d, want 0", mismatch.SnapshotHeight())
	}
	mismatch.Close()

	// Closing the mismatched identity must not destroy the original peer's
	// validated snapshot.
	afterMismatch, err := New(local, managerAddress, nil, WithStateDir(stateDir))
	if err != nil {
		t.Fatal(err)
	}
	if afterMismatch.State() != ClientStateDegraded || afterMismatch.SnapshotHeight() != snapshot.Height {
		t.Fatalf("state after mismatched close = %q height %d, want degraded height %d",
			afterMismatch.State(), afterMismatch.SnapshotHeight(), snapshot.Height)
	}
	afterMismatch.Close()
}

func TestClientManagerFailoverBetweenThreeEndpoints(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	managers := make([]*p2p.Node, 3)
	addresses := make([]string, 3)
	for index := range managers {
		managers[index] = newTestP2PNode(t)
		available := managers[index].Addresses()
		if len(available) == 0 {
			t.Fatalf("manager %d has no addresses", index)
		}
		addresses[index] = available[0]
	}
	local := newTestP2PNode(t)
	netClient, err := New(local, addresses[0], nil,
		WithManagerFailover(addresses[1], addresses[2]))
	if err != nil {
		t.Fatal(err)
	}
	defer netClient.Close()
	if netClient.State() != ClientStateNeedsLogin {
		t.Fatalf("initial state = %q, want needs-login", netClient.State())
	}

	managers[0].Close()
	if err := netClient.connect(ctx); err != nil {
		t.Fatalf("failover to second manager: %v", err)
	}
	if netClient.ManagerStatus().ActiveManager != managers[1].Host.ID() {
		t.Fatalf("active manager after first failover = %q, want %q",
			netClient.ManagerStatus().ActiveManager, managers[1].Host.ID())
	}
	if netClient.State() != ClientStateNeedsLogin {
		t.Fatalf("state after first failover = %q, want needs-login", netClient.State())
	}

	snapshot := certifiedClientSnapshot(t, "netp2p-client-failover-test")
	netClient.applySnapshot(snapshot, model.PeerRecord{PeerID: local.Host.ID().String()})
	if netClient.State() != ClientStateReady {
		t.Fatalf("state after snapshot = %q, want ready", netClient.State())
	}

	_ = local.Host.Network().ClosePeer(managers[1].Host.ID())
	managers[1].Close()
	if err := netClient.connect(ctx); err != nil {
		t.Fatalf("failover to third manager: %v", err)
	}
	status := netClient.ManagerStatus()
	if status.ActiveManager != managers[2].Host.ID() {
		t.Fatalf("active manager after second failover = %q, want %q",
			status.ActiveManager, managers[2].Host.ID())
	}
	if status.State != ClientStateReady {
		t.Fatalf("state after second failover = %q, want ready", status.State)
	}
	if len(status.Managers) != 3 {
		t.Fatalf("failover endpoint count = %d, want 3", len(status.Managers))
	}
	if status.ActiveIndex != 2 {
		t.Fatalf("active failover index = %d, want 2", status.ActiveIndex)
	}

	_ = local.Host.Network().ClosePeer(managers[2].Host.ID())
	managers[2].Close()
	if err := netClient.connect(ctx); err == nil {
		t.Fatal("connect unexpectedly succeeded after all managers stopped")
	}
	status = netClient.ManagerStatus()
	if status.State != ClientStateDegraded {
		t.Fatalf("state with snapshot but no manager = %q, want degraded", status.State)
	}
	if status.LastError == "" {
		t.Fatal("degraded status has no last manager error")
	}

	bareNode := newTestP2PNode(t)
	bareClient, err := New(bareNode, addresses[0], nil)
	if err != nil {
		t.Fatal(err)
	}
	defer bareClient.Close()
	if err := bareClient.connect(ctx); err == nil {
		t.Fatal("bare client connect unexpectedly succeeded after all managers stopped")
	}
	if bareClient.State() != ClientStateFailed {
		t.Fatalf("bare client state = %q, want failed", bareClient.State())
	}
}

func newTestP2PNode(t *testing.T) *p2p.Node {
	t.Helper()
	node, err := p2p.New(context.Background(), p2p.Config{})
	if err != nil {
		t.Fatalf("create p2p node: %v", err)
	}
	t.Cleanup(func() { _ = node.Close() })
	return node
}

func certifiedClientSnapshot(t *testing.T, networkID string, peers ...model.PeerRecord) model.SignedSnapshot {
	t.Helper()
	state := model.NetworkState{NetworkID: networkID, OverlayCIDR: "10.80.0.0/24", Peers: peers}
	committee := make([]model.CommitteeMember, bft.CommitteeSize)
	for index := range committee {
		committee[index] = model.CommitteeMember{
			ID: fmt.Sprintf("manager-%d", index), KeySeed: int64(201 + index),
		}
	}
	engines := make([]*bft.Engine, bft.CommitteeSize)
	for index, member := range committee {
		engine, err := bft.NewEngine(state, committee, member.ID, bft.SeededPrivateKey(member.KeySeed))
		if err != nil {
			t.Fatalf("create engine %s: %v", member.ID, err)
		}
		engines[index] = engine
	}
	leader := engines[0].Leader(1, 0)
	var leaderEngine *bft.Engine
	for _, engine := range engines {
		if engine.LocalID() == leader.ID {
			leaderEngine = engine
			break
		}
	}
	if leaderEngine == nil {
		t.Fatalf("leader %s not found", leader.ID)
	}
	proposal, localVote, err := leaderEngine.Propose(model.StateTransition{Type: bft.TransitionGenesis}, 0)
	if err != nil {
		t.Fatalf("propose genesis: %v", err)
	}
	votes := []model.Vote{localVote}
	for _, engine := range engines {
		if engine.LocalID() == leader.ID {
			continue
		}
		vote, err := engine.ProcessProposal(proposal)
		if err != nil {
			t.Fatalf("process genesis proposal on %s: %v", engine.LocalID(), err)
		}
		votes = append(votes, vote)
	}
	var quorum model.QuorumCertificate
	ready := false
	for _, vote := range votes {
		quorum, ready, err = leaderEngine.ProcessVote(vote)
		if err != nil {
			t.Fatalf("process genesis vote from %s: %v", vote.VoterID, err)
		}
		if ready {
			break
		}
	}
	if !ready {
		t.Fatal("genesis quorum was not reached")
	}
	snapshot, err := leaderEngine.Commit(proposal, quorum)
	if err != nil {
		t.Fatalf("commit genesis: %v", err)
	}
	return snapshot
}
