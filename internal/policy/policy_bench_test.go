package policy

import (
	"fmt"
	"testing"

	"github.com/netp2p/netp2p/internal/model"
)

func benchmarkState(peers, policyCount int) State {
	groups := make([]model.Group, peers)
	for index := range groups {
		groups[index] = model.Group{
			ID:      fmt.Sprintf("group-%03d", index),
			PeerIDs: []string{fmt.Sprintf("peer-%03d", index)},
			Managed: true,
			Issued:  model.GroupIssuedAPI,
		}
	}
	policies := make([]model.Policy, policyCount)
	for index := range policies {
		source := index % peers
		destination := (index + 1) % peers
		policies[index] = model.Policy{
			ID:                fmt.Sprintf("policy-%03d", index),
			SourceGroups:      []string{fmt.Sprintf("group-%03d", source)},
			DestinationGroups: []string{fmt.Sprintf("group-%03d", destination)},
			Services: []model.Service{
				{Protocol: "tcp", StartPort: 1, EndPort: 65535},
				{Protocol: "udp", StartPort: 1, EndPort: 65535},
			},
			Effect:    model.EffectAllow,
			Direction: model.DirectionBidirectional,
		}
	}
	return State{
		NetworkID: "benchmark",
		Groups:    groups,
		Policies:  policies,
		Routes: []model.Route{
			{ID: "default", Destination: "10.20.0.0/16", RoutingGroup: "group-000", DistributionGroup: []string{"group-001"}},
		},
		Budgets: []model.TrafficBudget{
			{ID: "default", SubjectType: "peer", SubjectID: "peer-000", DailyBytes: 1 << 30, MonthlyBytes: 1 << 34},
		},
	}
}

func BenchmarkPolicyAuthorize(b *testing.B) {
	state := benchmarkState(128, 128)
	b.ReportAllocs()
	b.ResetTimer()
	for index := 0; index < b.N; index++ {
		allowed, err := Authorize(state, "peer-000", "peer-001", "tcp", 443, nil)
		if err != nil {
			b.Fatal(err)
		}
		if !allowed {
			b.Fatal("expected benchmark policy to allow traffic")
		}
	}
}

func BenchmarkPolicyCompile(b *testing.B) {
	state := benchmarkState(512, 128)
	b.ReportAllocs()
	b.ResetTimer()
	for index := 0; index < b.N; index++ {
		networkMap := Compile(state, "peer-000", 1)
		if len(networkMap.AllowedPeers) == 0 {
			b.Fatal("expected benchmark network map to contain peers")
		}
	}
}
