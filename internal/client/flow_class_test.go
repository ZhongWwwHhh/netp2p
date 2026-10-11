package client

import (
	"testing"

	"github.com/netp2p/netp2p/internal/model"
	"github.com/netp2p/netp2p/internal/packet"
)

func TestClassifierSupportsAllFiveFlowClasses(t *testing.T) {
	classes := []struct {
		value string
		want  FlowClass
	}{
		{"latency", FlowClassLatency},
		{"throughput", FlowClassThroughput},
		{"cost", FlowClassCost},
		{"reliability", FlowClassReliability},
		{"realtime", FlowClassRealtime},
	}
	for _, item := range classes {
		if got := classifyFlow("tcp", 443, item.value, "latency"); got != item.want {
			t.Fatalf("classify(%q) = %q, want %q", item.value, got, item.want)
		}
	}
	if got := classifyFlow("tcp", 443, "invalid", "cost"); got != FlowClassCost {
		t.Fatalf("fallback class = %q, want cost", got)
	}
}

func TestClassifierUsesProtocolHeuristicsOnlyWithoutCertifiedClass(t *testing.T) {
	tests := []struct {
		protocol string
		port     uint16
		want     FlowClass
	}{
		{"udp", 3478, FlowClassRealtime},
		{"udp", 53, FlowClassLatency},
		{"tcp", 443, FlowClassThroughput},
		{"tcp", 22, FlowClassLatency},
		{"tcp", 12345, FlowClassLatency},
	}
	for _, item := range tests {
		if got := classifyFlow(item.protocol, item.port, "", ""); got != item.want {
			t.Fatalf("classify(%s/%d) = %q, want %q", item.protocol, item.port, got, item.want)
		}
	}
}

func TestClientFlowClassPrefersCertifiedPolicyAnnotation(t *testing.T) {
	netClient := &Client{
		snapshot: model.SignedSnapshot{State: model.NetworkState{
			NetworkID: "flow-class-test",
			Groups: []model.Group{
				{ID: "clients", PeerIDs: []string{"peer-a"}},
				{ID: "servers", PeerIDs: []string{"peer-b"}},
			},
			Policies: []model.Policy{{
				ID: "realtime-policy", SourceGroups: []string{"clients"}, DestinationGroups: []string{"servers"},
				Services: []model.Service{{Protocol: "udp", StartPort: 3478, EndPort: 3478}},
				Effect:   model.EffectAllow, FlowClass: "realtime", Priority: 10,
			}},
			Settings: model.NetworkSettings{DefaultFlowClass: "throughput"},
		}},
		self: model.PeerRecord{PeerID: "peer-a", OverlayIP: "100.64.0.1"},
	}
	destination := model.PeerRecord{PeerID: "peer-b", OverlayIP: "100.64.0.2"}
	raw := synthUDPPacket(t, "100.64.0.1", "100.64.0.2", 50000, 3478)

	if got := netClient.flowClassFor(destination, packet.IPv4Packet(raw)); got != FlowClassRealtime {
		t.Fatalf("flow class = %q, want realtime", got)
	}
}
