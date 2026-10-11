package loadtest

import (
	"fmt"
	"net/netip"

	"github.com/netp2p/netp2p/internal/model"
	"github.com/netp2p/netp2p/internal/packet"
)

type ScaleConfig struct {
	Peers    int
	Flows    int
	Domains  int
	Managers int
}

func DefaultScaleConfig() ScaleConfig {
	return ScaleConfig{Peers: 100000, Flows: 1000000, Domains: 10000, Managers: 3}
}

type ScaleFixture struct {
	Config        ScaleConfig
	Peers         []model.PeerRecord
	Groups        []model.Group
	Policies      []model.Policy
	Families      []PathFamily
	Paths         []PathRuntime
	EdgeCapacity  map[string]float64
	Authorization *AuthorizationIndex
	Flows         []packet.Flow
}

func sourceGroupID(config ScaleConfig, peerIndex int) string {
	return fmt.Sprintf("source-group-%02d", peerIndex%config.Managers)
}

func managerID(config ScaleConfig, peerIndex int) string {
	return fmt.Sprintf("manager-%02d", peerIndex%config.Managers)
}

func destinationScopeID(config ScaleConfig, peerIndex int) string {
	return fmt.Sprintf("scope-%05d", peerIndex%config.Domains)
}

func overlayIP(index int) string {
	second := 64 + (index/65536)%64
	third := (index / 256) % 256
	fourth := index%254 + 1
	return fmt.Sprintf("100.%d.%d.%d", second, third, fourth)
}

func BuildScaleFixture(config ScaleConfig, includeFlows bool) (*ScaleFixture, error) {
	if config.Peers <= 0 || config.Domains <= 0 || config.Managers <= 0 {
		return nil, fmt.Errorf("invalid scale config: %+v", config)
	}
	if config.Flows < 0 {
		return nil, fmt.Errorf("flow count cannot be negative")
	}
	fixture := &ScaleFixture{Config: config}
	fixture.Peers = make([]model.PeerRecord, config.Peers)
	for index := 0; index < config.Peers; index++ {
		sourceGroup := sourceGroupID(config, index)
		destinationScope := destinationScopeID(config, index)
		fixture.Peers[index] = model.PeerRecord{
			PeerID:        fmt.Sprintf("peer-%07d", index),
			OverlayIP:     overlayIP(index),
			Groups:        []string{sourceGroup, destinationScope},
			Hostname:      fmt.Sprintf("peer-%07d", index),
			OS:            "linux",
			ClientVersion: "3.0.0",
			DNSLabel:      fmt.Sprintf("peer-%07d", index),
			Posture:       []string{"loadtest"},
		}
	}

	fixture.Groups = make([]model.Group, 0, config.Managers+config.Domains)
	groupManagers := make(map[string]string, config.Managers)
	for index := 0; index < config.Managers; index++ {
		groupID := fmt.Sprintf("source-group-%02d", index)
		manager := fmt.Sprintf("manager-%02d", index)
		fixture.Groups = append(fixture.Groups, model.Group{ID: groupID, Managed: true, Issued: model.GroupIssuedAPI})
		groupManagers[groupID] = manager
	}
	sourceGroups := make([]string, config.Managers)
	for index := range sourceGroups {
		sourceGroups[index] = fmt.Sprintf("source-group-%02d", index)
	}
	destinationScopes := make([]string, config.Domains)
	for index := 0; index < config.Domains; index++ {
		destinationScopes[index] = fmt.Sprintf("scope-%05d", index)
		fixture.Groups = append(fixture.Groups, model.Group{ID: destinationScopes[index], Managed: true, Issued: model.GroupIssuedAPI})
	}

	fixture.Families = []PathFamily{
		{
			ID: "path-direct", Kind: model.PathKindDirect, SourceGroups: sourceGroups,
			DestinationScopes: destinationScopes, FlowClasses: AllFlowClasses,
			MaxRTTMilliseconds: 180, MaxLossPercent: 3, MinBandwidthMbps: 50,
		},
		{
			ID: "path-via-manager-0", Kind: model.PathKindViaManager, ManagerHops: []string{"manager-00"},
			SourceGroups: sourceGroups, DestinationScopes: destinationScopes, FlowClasses: AllFlowClasses,
			MaxRTTMilliseconds: 220, MaxLossPercent: 2, MinBandwidthMbps: 200,
		},
		{
			ID: "path-via-manager-1", Kind: model.PathKindViaManager, ManagerHops: []string{"manager-01"},
			SourceGroups: sourceGroups, DestinationScopes: destinationScopes, FlowClasses: AllFlowClasses,
			MaxRTTMilliseconds: 240, MaxLossPercent: 2, MinBandwidthMbps: 250,
		},
		{
			ID: "path-multihop-0-1", Kind: model.PathKindMultiHop, ManagerHops: []string{"manager-00", "manager-01"},
			SourceGroups: sourceGroups, DestinationScopes: destinationScopes, FlowClasses: AllFlowClasses,
			MaxRTTMilliseconds: 300, MaxLossPercent: 2, MinBandwidthMbps: 180,
		},
	}

	fixture.Policies = make([]model.Policy, config.Domains)
	for index := 0; index < config.Domains; index++ {
		fixture.Policies[index] = model.Policy{
			ID:                fmt.Sprintf("policy-%05d", index),
			SourceGroups:      sourceGroups,
			DestinationGroups: []string{destinationScopes[index]},
			Services: []model.Service{
				{Protocol: "all", StartPort: 1, EndPort: 65535},
			},
			Effect:    model.EffectAllow,
			Direction: model.DirectionBidirectional,
			Priority:  100,
		}
	}

	authorization, err := CompileAuthorization(AuthorizationFixture{
		Peers: fixture.Peers, Groups: fixture.Groups, Policies: fixture.Policies,
		Families: fixture.Families, GroupManagers: groupManagers,
	})
	if err != nil {
		return nil, err
	}
	fixture.Authorization = authorization

	fixture.Paths = []PathRuntime{
		{PathID: "path-direct", Edges: []string{"edge-direct"}, RTTMilliseconds: 80, JitterMilliseconds: 8,
			LossPercent: .5, BandwidthMbps: 120, Stability: .95, Congestion: .1, ForwardingCost: 0, Healthy: true},
		{PathID: "path-via-manager-0", Edges: []string{"edge-manager-00"}, RTTMilliseconds: 120, JitterMilliseconds: 6,
			LossPercent: .2, BandwidthMbps: 500, Stability: .98, Congestion: .2, ForwardingCost: 20, Healthy: true},
		{PathID: "path-via-manager-1", Edges: []string{"edge-manager-01"}, RTTMilliseconds: 140, JitterMilliseconds: 7,
			LossPercent: .2, BandwidthMbps: 600, Stability: .97, Congestion: .15, ForwardingCost: 18, Healthy: true},
		{PathID: "path-multihop-0-1", Edges: []string{"edge-manager-00", "edge-manager-01"}, RTTMilliseconds: 190,
			JitterMilliseconds: 10, LossPercent: .3, BandwidthMbps: 350, Stability: .96, Congestion: .25,
			ForwardingCost: 35, Healthy: true},
	}
	fixture.EdgeCapacity = map[string]float64{
		"edge-direct":     10_000_000_000,
		"edge-manager-00": 8_000_000_000,
		"edge-manager-01": 9_000_000_000,
	}

	if includeFlows {
		fixture.Flows = make([]packet.Flow, config.Flows)
		for index := 0; index < config.Flows; index++ {
			sourceIndex := index % config.Peers
			destinationIndex := (index*7919 + 1) % config.Peers
			source := fixture.Peers[sourceIndex]
			destination := fixture.Peers[destinationIndex]
			sourceAddress, err := netip.ParseAddr(source.OverlayIP)
			if err != nil {
				return nil, err
			}
			destinationAddress, err := netip.ParseAddr(destination.OverlayIP)
			if err != nil {
				return nil, err
			}
			protocol := uint8(6)
			destinationPort := uint16(443)
			if index%2 == 1 {
				protocol = 17
				destinationPort = 53
			}
			fixture.Flows[index] = packet.Flow{
				Protocol: protocol, Source: sourceAddress, Destination: destinationAddress,
				SourcePort: uint16(1024 + index%64512), DestinationPort: destinationPort,
			}
		}
	}
	return fixture, nil
}

func RegistryPeerGenerator(config ScaleConfig) func(index int) RegistryPeer {
	return func(index int) RegistryPeer {
		sourceGroup := sourceGroupID(config, index)
		destinationScope := destinationScopeID(config, index)
		return RegistryPeer{
			Record: model.PeerRecord{
				PeerID:        fmt.Sprintf("peer-%07d", index),
				OverlayIP:     overlayIP(index),
				Groups:        []string{sourceGroup, destinationScope},
				Hostname:      fmt.Sprintf("peer-%07d", index),
				OS:            "linux",
				ClientVersion: "3.0.0",
				DNSLabel:      fmt.Sprintf("peer-%07d", index),
				Posture:       []string{"loadtest"},
			},
			ManagerID:        managerID(config, index),
			SourceGroupID:    sourceGroup,
			DestinationScope: destinationScope,
		}
	}
}

func BuildDemands(fixture *ScaleFixture) []Demand {
	domains := make([]Demand, 0, fixture.Config.Domains*len(AllFlowClasses))
	for domainIndex := 0; domainIndex < fixture.Config.Domains; domainIndex++ {
		scope := fmt.Sprintf("scope-%05d", domainIndex)
		for classIndex, class := range AllFlowClasses {
			domains = append(domains, Demand{
				Key: RoutingDomainKey{
					SourceManagerID: "manager-aggregated", SourceGroupID: "source-group-all",
					DestinationScope: scope, FlowClass: class,
				},
				BytesPerSecond: float64(1_000_000 + domainIndex*100 + classIndex*10),
				EligiblePaths:  []int{0, 1, 2, 3},
			})
		}
	}
	return domains
}
