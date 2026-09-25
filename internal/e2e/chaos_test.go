package e2e

import (
	"bytes"
	"context"
	"testing"
	"time"

	"github.com/netp2p/netp2p/internal/bft"
	"github.com/netp2p/netp2p/internal/chaos"
	"github.com/netp2p/netp2p/internal/manager"
	"github.com/netp2p/netp2p/internal/model"
)

// waitForCommitteeHeight blocks until every committee engine has adopted at
// least the given height. Genesis is broadcast asynchronously, so a test that
// submits immediately can otherwise observe a partially-adopted committee.
func waitForCommitteeHeight(t *testing.T, group *cluster, want uint64) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		ready := true
		for _, engine := range group.engines {
			if engine.Height() < want {
				ready = false
				break
			}
		}
		if ready {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	for index, engine := range group.engines {
		t.Logf("engine %d height %d", index, engine.Height())
	}
	t.Fatalf("committee did not reach height %d", want)
}

// TestChaosPartitionAndCatchUp isolates the last committee member, proves the
// remaining three still certify a new height, then reconnects the isolated
// manager and proves it catches up from certified state. This is the failure
// mode of a manager restarting after a network split.
func TestChaosPartitionAndCatchUp(t *testing.T) {
	controller := chaos.New()
	group := newClusterWithHook(t, testState(), manager.Config{}, controller.HookFor)
	waitForCommitteeHeight(t, group, 1)

	isolated := group.members[3]
	controller.Isolate(isolated.PeerID)

	transition := model.StateTransition{Type: bft.TransitionUpsertGroup, Group: &model.Group{ID: "chaos-group"}}
	snapshot, err := group.meshes[0].Submit(transition)
	if err != nil {
		t.Fatalf("submit with one member isolated: %v", err)
	}
	if snapshot.Height < 2 {
		t.Fatalf("committed height %d, want >= 2", snapshot.Height)
	}
	if got := group.engines[3].Height(); got >= snapshot.Height {
		t.Fatalf("isolated manager advanced to %d, want less than %d", got, snapshot.Height)
	}
	if dropped := controller.Stats().Dropped; dropped == 0 {
		t.Fatal("chaos controller dropped nothing during the partition")
	}

	controller.Reconnect(isolated.PeerID)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := group.meshes[3].CatchUp(ctx); err != nil {
		t.Fatalf("catch up after reconnect: %v", err)
	}
	if got := group.engines[3].Height(); got != snapshot.Height {
		t.Fatalf("reconnected manager height %d, want %d", got, snapshot.Height)
	}
	if !bytes.Equal(bft.StateHash(group.engines[3].CurrentState()), bft.StateHash(group.engines[0].CurrentState())) {
		t.Fatal("reconnected manager state hash diverged after catch-up")
	}
}

// TestChaosDuplicateMessagesDoNotBreakConsensus replays every committee
// message and proves the committee still reaches the same certified state:
// duplicate proposals and votes must be idempotent.
func TestChaosDuplicateMessagesDoNotBreakConsensus(t *testing.T) {
	controller := chaos.New()
	controller.SetFaults(chaos.Fault{Protocol: "state-update", Duplicate: 1})
	group := newClusterWithHook(t, testState(), manager.Config{}, controller.HookFor)
	waitForCommitteeHeight(t, group, 1)

	transition := model.StateTransition{Type: bft.TransitionUpsertGroup, Group: &model.Group{ID: "replayed-group"}}
	snapshot, err := group.meshes[1].Submit(transition)
	if err != nil {
		t.Fatalf("submit with duplicated messages: %v", err)
	}

	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		converged := true
		for _, engine := range group.engines {
			if engine.Height() < snapshot.Height {
				converged = false
				break
			}
		}
		if converged {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	for index, engine := range group.engines {
		if engine.Height() != snapshot.Height {
			t.Fatalf("manager %d height %d, want %d", index, engine.Height(), snapshot.Height)
		}
		if !bytes.Equal(bft.StateHash(engine.CurrentState()), snapshot.StateHash) {
			t.Fatalf("manager %d state hash diverged under replay", index)
		}
	}
	if duplicated := controller.Stats().Duplicated; duplicated == 0 {
		t.Fatal("chaos controller duplicated nothing")
	}
}
