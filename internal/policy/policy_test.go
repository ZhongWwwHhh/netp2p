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

// A TCP policy must match the actual destination port, which the client now
// parses out of the packet rather than reporting as zero.
func TestAuthorizeMatchesPort(t *testing.T) {
	state := testState()
	allowed, err := Authorize(state, "worker-a", "db-1", "tcp", 5432)
	if err != nil || !allowed {
		t.Fatalf("tcp/5432 allowed = %v err = %v, want true", allowed, err)
	}
	if allowed, err = Authorize(state, "worker-a", "db-1", "tcp", 22); err != nil || allowed {
		t.Fatalf("tcp/22 allowed = %v err = %v, want false", allowed, err)
	}
	if allowed, err = Authorize(state, "worker-a", "db-1", "udp", 5432); err != nil || allowed {
		t.Fatalf("udp/5432 allowed = %v err = %v, want false", allowed, err)
	}
}

// An empty or "all" protocol means any transport, and a zero port range means
// any port.
func TestAuthorizeMatchesAnyProtocol(t *testing.T) {
	state := testState()
	state.Policies = []model.Policy{
		{
			ID:                "allow-any",
			SourceGroups:      []string{"workers"},
			DestinationGroups: []string{"database"},
			Services:          []model.Service{{Protocol: "all"}},
			Effect:            model.EffectAllow,
		},
	}
	for _, probe := range []struct {
		protocol string
		port     uint16
	}{
		{"tcp", 443}, {"udp", 53}, {"icmp", 0}, {"tcp", 5432},
	} {
		allowed, err := Authorize(state, "worker-a", "db-1", probe.protocol, probe.port)
		if err != nil || !allowed {
			t.Fatalf("%s/%d allowed = %v err = %v, want true", probe.protocol, probe.port, allowed, err)
		}
	}
}

func TestAuthorizeEmptyProtocolMeansAny(t *testing.T) {
	state := testState()
	state.Policies = []model.Policy{
		{
			ID:                "allow-unspecified",
			SourceGroups:      []string{"workers"},
			DestinationGroups: []string{"database"},
			Services:          []model.Service{{}},
			Effect:            model.EffectAllow,
		},
	}
	allowed, err := Authorize(state, "worker-a", "db-1", "tcp", 8080)
	if err != nil || !allowed {
		t.Fatalf("allowed = %v err = %v, want true", allowed, err)
	}
}
