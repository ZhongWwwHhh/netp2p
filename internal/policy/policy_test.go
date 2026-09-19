package policy

import (
	"testing"

	"github.com/netp2p/netp2p/internal/model"
)

func testState() State {
	return State{
		NetworkID: "net-1",
		Groups: []model.Group{
			{ID: "workers", PeerIDs: []string{"worker-a", "worker-b"}},
			{ID: "database", PeerIDs: []string{"db-1"}},
		},
		Policies: []model.Policy{
			{
				ID:                "allow-postgres",
				SourceGroups:      []string{"workers"},
				DestinationGroups: []string{"database"},
				Services:          []model.Service{{Protocol: "tcp", StartPort: 5432, EndPort: 5432}},
				Effect:            model.EffectAllow,
			},
		},
	}
}

func TestCompileAllowOnlyMatchingPeer(t *testing.T) {
	networkMap := Compile(testState(), "worker-a", 7)
	if _, ok := networkMap.AllowedPeers["db-1"]; !ok {
		t.Fatal("db-1 should be visible to worker-a")
	}
	if _, ok := networkMap.AllowedPeers["worker-b"]; ok {
		t.Fatal("worker-b should not be visible without a policy")
	}
	if networkMap.Epoch != 7 || networkMap.NetworkID != "net-1" {
		t.Fatalf("unexpected metadata: %+v", networkMap)
	}
}

func TestAuthorizeDenyPrecedence(t *testing.T) {
	state := testState()
	state.Policies = append(state.Policies, model.Policy{
		ID: "deny-db", SourceGroups: []string{"workers"}, DestinationGroups: []string{"database"},
		Services: []model.Service{{Protocol: "tcp", StartPort: 0, EndPort: 65535}}, Effect: model.EffectDeny, Priority: 10,
	})
	allowed, err := Authorize(state, "worker-a", "db-1", "tcp", 5432)
	if err != nil {
		t.Fatal(err)
	}
	if allowed {
		t.Fatal("deny should have precedence over allow")
	}
}
