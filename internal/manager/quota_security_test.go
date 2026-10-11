package manager

import (
	"context"
	"testing"
	"time"

	"github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/netp2p/netp2p/internal/bft"
	"github.com/netp2p/netp2p/internal/model"
	"github.com/netp2p/netp2p/internal/p2p"
	"github.com/netp2p/netp2p/internal/version"
	"github.com/netp2p/netp2p/internal/wire/pb"
)

func TestQuotaReportProtocolIsScopedAndOverflowSafe(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	managerKey := bft.SeededPrivateKey(901)
	managerIdentity, _, err := crypto.KeyPairFromStdKey(&managerKey)
	if err != nil {
		t.Fatal(err)
	}
	managerNode, err := p2p.New(ctx, p2p.Config{Identity: managerIdentity})
	if err != nil {
		t.Fatal(err)
	}
	defer managerNode.Close()
	reporter, err := p2p.New(ctx, p2p.Config{})
	if err != nil {
		t.Fatal(err)
	}
	defer reporter.Close()

	state := model.NetworkState{
		NetworkID:       "quota-security",
		OverlayCIDR:     "100.64.0.0/24",
		CommitteeConfig: model.CommitteeConfig{Threshold: 1, Size: 1},
		Groups:          []model.Group{{ID: "reporters", PeerIDs: []string{reporter.Host.ID().String()}}},
		Peers: []model.PeerRecord{
			{PeerID: reporter.Host.ID().String(), OverlayIP: "100.64.0.1", Groups: []string{"reporters"}},
			{PeerID: "victim-peer", OverlayIP: "100.64.0.2", Groups: []string{"victims"}},
		},
		Budgets: []model.TrafficBudget{
			{ID: "reporter-budget", SubjectType: "group", SubjectID: "reporters", DailyBytes: 100, MonthlyBytes: 100},
			{ID: "victim-budget", SubjectType: "peer", SubjectID: "victim-peer", DailyBytes: 100, MonthlyBytes: 100},
		},
	}
	member := model.CommitteeMember{
		ID: "manager-1", PeerID: managerNode.Host.ID().String(), KeySeed: 901, ForwardingEnabled: true,
	}
	engine, err := bft.NewEngine(state, []model.CommitteeMember{member}, member.ID, managerKey)
	if err != nil {
		t.Fatal(err)
	}
	mesh, err := NewCommitteeMesh(managerNode, engine, []model.CommitteeMember{member})
	if err != nil {
		t.Fatal(err)
	}
	manager := New(managerNode, engine, mesh, Config{})
	if _, err := manager.Submit(model.StateTransition{Type: bft.TransitionGenesis}); err != nil {
		t.Fatalf("genesis: %v", err)
	}

	target, err := peer.AddrInfoFromString(managerNode.Addresses()[0])
	if err != nil {
		t.Fatal(err)
	}
	if err := reporter.Host.Connect(ctx, *target); err != nil {
		t.Fatalf("connect manager: %v", err)
	}
	sendReport := func(budgetID string, bytes uint64) {
		t.Helper()
		message := &pb.QuotaReport{
			PeerId:          reporter.Host.ID().String(),
			ReportedAt:      time.Now().UTC().Format(time.RFC3339Nano),
			ProtocolVersion: version.ProtocolVersion,
			Increments:      []*pb.BudgetIncrement{{BudgetId: budgetID, Bytes: bytes}},
		}
		if err := reporter.Send(ctx, managerNode.Host.ID(), p2p.QuotaProtocol, message); err != nil {
			t.Fatalf("send quota report for %s: %v", budgetID, err)
		}
	}

	sendReport("victim-budget", 40)
	sendReport("reporter-budget", 20)
	waitForPending(t, manager, "reporter-budget", 20)
	if got := pendingBytes(manager, "victim-budget"); got != 0 {
		t.Fatalf("reporter moved %d bytes into a peer budget it does not own", got)
	}

	now := time.Now().UTC()
	manager.SettleQuotaNow(now)
	waitForUsage(t, manager, "reporter-budget", 20)

	sendReport("reporter-budget", ^uint64(0)-10)
	waitForPending(t, manager, "reporter-budget", ^uint64(0)-10)
	sendReport("reporter-budget", 20)
	time.Sleep(100 * time.Millisecond)
	if got := pendingBytes(manager, "reporter-budget"); got != ^uint64(0)-10 {
		t.Fatalf("overflowing report changed pending usage to %d", got)
	}

	manager.SettleQuotaNow(now.Add(time.Second))
	waitForUsage(t, manager, "reporter-budget", ^uint64(0))
}

func pendingBytes(manager *Manager, budgetID string) uint64 {
	manager.mu.RLock()
	defer manager.mu.RUnlock()
	return manager.quotaPending[budgetID]
}

func waitForPending(t *testing.T, manager *Manager, budgetID string, want uint64) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if pendingBytes(manager, budgetID) == want {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("pending usage for %s = %d, want %d", budgetID, pendingBytes(manager, budgetID), want)
}

func waitForUsage(t *testing.T, manager *Manager, budgetID string, want uint64) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		for _, budget := range manager.engine.CurrentState().Budgets {
			if budget.ID == budgetID && budget.UsedDailyBytes == want {
				return
			}
		}
		time.Sleep(10 * time.Millisecond)
	}
	for _, budget := range manager.engine.CurrentState().Budgets {
		if budget.ID == budgetID {
			t.Fatalf("used daily bytes for %s = %d, want %d", budgetID, budget.UsedDailyBytes, want)
		}
	}
	t.Fatalf("budget %s not found", budgetID)
}
