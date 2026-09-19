package client

import (
	"testing"

	"github.com/netp2p/netp2p/internal/model"
)

func TestBuildDNSConfigScopesToPeerGroups(t *testing.T) {
	state := model.NetworkState{
		Settings: model.NetworkSettings{DNSDomain: "netp2p.internal"},
		Peers: []model.PeerRecord{
			{PeerID: "self", OverlayIP: "100.64.0.1", DNSLabel: "self", Groups: []string{"eng"}},
			{PeerID: "peer-b", OverlayIP: "100.64.0.2", DNSLabel: "peer-b", Groups: []string{"ops"}},
		},
		Nameservers: []model.Nameserver{
			{ID: "ns-all", Servers: []string{"1.1.1.1"}, Enabled: true},
			{ID: "ns-ops", Groups: []string{"ops"}, Servers: []string{"8.8.8.8"}, Enabled: true},
		},
		Zones: []model.DNSZone{
			{ID: "z-all", Domain: "corp.internal", Enabled: true},
			{ID: "z-ops", Domain: "ops.internal", Groups: []string{"ops"}, Enabled: true},
		},
	}
	self := state.Peers[0]
	config := buildDNSConfig(state, self, []string{"9.9.9.9:53"})

	if config.Domain != "netp2p.internal" {
		t.Fatalf("domain = %q", config.Domain)
	}
	if got := config.Peers["peer-b"]; got != "100.64.0.2" {
		t.Fatalf("peer label peer-b = %q", got)
	}
	if len(config.Nameservers) != 1 || config.Nameservers[0].ID != "ns-all" {
		t.Fatalf("nameservers = %+v, want only the unscoped one", config.Nameservers)
	}
	if len(config.Zones) != 1 || config.Zones[0].ID != "z-all" {
		t.Fatalf("zones = %+v, want only the unscoped one", config.Zones)
	}
	if config.Disabled {
		t.Fatal("dns should be enabled")
	}
	if len(config.Upstreams) != 1 || config.Upstreams[0] != "9.9.9.9:53" {
		t.Fatalf("upstreams = %v", config.Upstreams)
	}
}

func TestDNSDisabledForGroupScope(t *testing.T) {
	self := model.PeerRecord{PeerID: "self", Groups: []string{"eng"}}
	if !dnsDisabledFor(model.NetworkState{DNSSettings: model.DNSSettings{Disabled: true}}, self) {
		t.Fatal("empty scope should disable dns for everyone")
	}
	if dnsDisabledFor(model.NetworkState{DNSSettings: model.DNSSettings{Disabled: true, Groups: []string{"ops"}}}, self) {
		t.Fatal("peer outside the scope must keep dns")
	}
	if !dnsDisabledFor(model.NetworkState{DNSSettings: model.DNSSettings{Disabled: true, Groups: []string{"eng"}}}, self) {
		t.Fatal("peer inside the scope must lose dns")
	}
	if dnsDisabledFor(model.NetworkState{DNSSettings: model.DNSSettings{}}, self) {
		t.Fatal("dns must stay on when the toggle is off")
	}
}
