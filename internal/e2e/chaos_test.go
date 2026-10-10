package e2e

import (
	"bytes"
	"context"
	"sync"
	"testing"
	"time"

	"github.com/netp2p/netp2p/internal/alerts"
	"github.com/netp2p/netp2p/internal/bft"
	"github.com/netp2p/netp2p/internal/chaos"
	"github.com/netp2p/netp2p/internal/manager"
	"github.com/netp2p/netp2p/internal/model"
	"github.com/netp2p/netp2p/internal/p2p"
	"github.com/netp2p/netp2p/internal/wire"

	"github.com/libp2p/go-libp2p/core/peer"
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

// TestChaosPartitionAndCatchUp isolates one committee member, proves a 3-of-3
// committee blocks writes while it is unavailable, then reconnects it and
// proves the committee commits and the isolated manager catches up.
func TestChaosPartitionAndCatchUp(t *testing.T) {
	controller := chaos.New()
	group := newClusterWithHook(t, testState(), manager.Config{}, controller.HookFor)
	waitForCommitteeHeight(t, group, 1)

	isolatedIndex := len(group.members) - 1
	isolated := group.members[isolatedIndex]
	controller.Isolate(isolated.PeerID)

	transition := model.StateTransition{Type: bft.TransitionUpsertGroup, Group: &model.Group{ID: "chaos-group"}}
	if _, err := group.meshes[0].Submit(transition); err == nil {
		t.Fatal("submit with one member isolated unexpectedly reached quorum")
	}
	for index, engine := range group.engines {
		if got := engine.Height(); got != 1 {
			t.Fatalf("manager %d advanced to height %d while quorum was unavailable", index, got)
		}
	}
	if dropped := controller.Stats().Dropped; dropped == 0 {
		t.Fatal("chaos controller dropped nothing during the partition")
	}

	controller.Reconnect(isolated.PeerID)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	snapshot, err := group.meshes[0].Submit(transition)
	if err != nil {
		t.Fatalf("submit after reconnect: %v", err)
	}
	if snapshot.Height < 2 {
		t.Fatalf("committed height %d, want >= 2", snapshot.Height)
	}
	if group.engines[isolatedIndex].Height() < snapshot.Height {
		if err := group.meshes[isolatedIndex].CatchUp(ctx); err != nil {
			t.Fatalf("catch up after reconnect: %v", err)
		}
	}
	if got := group.engines[isolatedIndex].Height(); got != snapshot.Height {
		t.Fatalf("reconnected manager height %d, want %d", got, snapshot.Height)
	}
	if !bytes.Equal(bft.StateHash(group.engines[isolatedIndex].CurrentState()), bft.StateHash(group.engines[0].CurrentState())) {
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

// TestChaosLeaderIsolationBlocksWrites isolates whoever leads the next height.
// With a 3-of-3 committee, leader isolation must block the write rather than
// allowing a smaller set of managers to certify state.
func TestChaosLeaderIsolationBlocksWrites(t *testing.T) {
	controller := chaos.New()
	group := newClusterWithHook(t, testState(), manager.Config{}, controller.HookFor)
	waitForCommitteeHeight(t, group, 1)

	leader := group.engines[0].Leader(2, 0)
	leaderIndex := -1
	for index, member := range group.members {
		if member.ID == leader.ID {
			leaderIndex = index
		}
	}
	if leaderIndex < 0 {
		t.Fatalf("height-2 leader %q is not a committee member", leader.ID)
	}
	controller.Isolate(group.members[leaderIndex].PeerID)

	// Submit through a survivor so the originating node can still reach the
	// rotated leader once it moves past the isolated round 0.
	submitter := (leaderIndex + 1) % len(group.meshes)
	transition := model.StateTransition{Type: bft.TransitionUpsertGroup, Group: &model.Group{ID: "churn-group"}}
	if _, err := group.meshes[submitter].Submit(transition); err == nil {
		t.Fatal("write unexpectedly certified after isolating the next leader")
	}
	if got := group.engines[submitter].Height(); got != 1 {
		t.Fatalf("height advanced to %d while the leader was isolated", got)
	}
}

// TestChaosDegradedInboundForwardIsReadOnly bypasses Submit and sends a
// forwarded transition directly to a healthy leader. While one member of a
// 3-of-3 committee is isolated, the inbound state-change path must stay
// read-only instead of starting a proposal that cannot reach quorum.
func TestChaosDegradedInboundForwardIsReadOnly(t *testing.T) {
	controller := chaos.New()
	group := newClusterWithHook(t, testState(), manager.Config{}, controller.HookFor)
	waitForCommitteeHeight(t, group, 1)

	isolatedIndex := len(group.members) - 1
	controller.Isolate(group.members[isolatedIndex].PeerID)

	leaderIndex := -1
	round := uint64(0)
	for candidateRound := uint64(0); candidateRound < uint64(len(group.members)); candidateRound++ {
		leader := group.engines[0].Leader(2, candidateRound)
		for index, member := range group.members {
			if member.ID == leader.ID && index != isolatedIndex {
				leaderIndex = index
				round = candidateRound
			}
		}
		if leaderIndex >= 0 {
			break
		}
	}
	if leaderIndex < 0 {
		t.Fatal("no healthy leader exists for height 2")
	}
	senderIndex := (leaderIndex + 1) % len(group.members)
	if senderIndex == isolatedIndex {
		senderIndex = (senderIndex + 1) % len(group.members)
	}

	leaderPeer, err := peer.Decode(group.members[leaderIndex].PeerID)
	if err != nil {
		t.Fatal(err)
	}
	transition := model.StateTransition{Type: bft.TransitionUpsertGroup, Group: &model.Group{ID: "degraded-group"}}
	message := model.CommitteeEnvelope{Type: "forward", Transition: &transition, Round: round}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := group.nodes[senderIndex].Send(ctx, leaderPeer, p2p.StateUpdateProtocol, wire.CommitteeEnvelopeToProto(message)); err != nil {
		t.Fatalf("send degraded forward: %v", err)
	}

	deadline := time.Now().Add(750 * time.Millisecond)
	for time.Now().Before(deadline) {
		if _, ok := group.engines[leaderIndex].Proposal(2); ok {
			t.Fatal("degraded committee accepted an inbound state-changing forward")
		}
		time.Sleep(20 * time.Millisecond)
	}
	for index, engine := range group.engines {
		if got := engine.Height(); got != 1 {
			t.Fatalf("manager %d advanced to height %d while degraded", index, got)
		}
	}
}

// recordingSink captures alert transitions for the chaos assertions.
type recordingSink struct {
	mu     sync.Mutex
	events []alerts.Event
}

func (sink *recordingSink) Send(_ context.Context, event alerts.Event) error {
	sink.mu.Lock()
	defer sink.mu.Unlock()
	sink.events = append(sink.events, event)
	return nil
}

func (sink *recordingSink) rules(status string) map[string]bool {
	sink.mu.Lock()
	defer sink.mu.Unlock()
	found := make(map[string]bool)
	for _, event := range sink.events {
		if event.Status == status {
			found[event.Alert.Rule] = true
		}
	}
	return found
}

// TestChaosQuorumDegradedAlertFires proves the manager-local alerting reacts to
// a partition and clears when the member returns. Alerts are not certified, so
// this asserts observation behavior rather than consensus.
func TestChaosQuorumDegradedAlertFires(t *testing.T) {
	controller := chaos.New()
	group := newClusterWithHook(t, testState(), manager.Config{}, controller.HookFor)
	waitForCommitteeHeight(t, group, 1)

	sink := &recordingSink{}
	alerter := alerts.New(alerts.Config{Interval: time.Second}, sink)
	observer := group.managers[0]

	// Baseline: the mesh is connected, so nothing fires.
	alerter.Evaluate(t.Context(), observer.AlertInput())
	if len(alerter.Active()) != 0 {
		t.Fatalf("healthy committee fired %+v", alerter.Active())
	}

	// The alert rule reads transport connectivity, so the test must actually
	// drop the connection rather than only dropping application messages.
	member := group.members[len(group.members)-1]
	memberPeer, err := peer.Decode(member.PeerID)
	if err != nil {
		t.Fatal(err)
	}
	if err := group.nodes[0].Host.Network().ClosePeer(memberPeer); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		alerter.Evaluate(t.Context(), observer.AlertInput())
		if len(alerter.Active()) > 0 {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if !sink.rules("firing")[alerts.RuleQuorumDegraded] {
		t.Fatalf("quorum_degraded did not fire after isolation; active=%+v", alerter.Active())
	}

	// Redial to clear the observation.
	if err := group.meshes[0].Connect(t.Context()); err != nil {
		t.Fatalf("redial: %v", err)
	}
	deadline = time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		alerter.Evaluate(t.Context(), observer.AlertInput())
		if len(alerter.Active()) == 0 {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if len(alerter.Active()) != 0 {
		t.Fatalf("alert did not resolve after reconnect: %+v", alerter.Active())
	}
	if !sink.rules("resolved")[alerts.RuleQuorumDegraded] {
		t.Fatal("quorum_degraded did not resolve")
	}
}
