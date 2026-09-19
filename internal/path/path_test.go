package path

import "testing"

func TestSelectPrefersGoodDirectForLatency(t *testing.T) {
	direct := LinkProfile{PathID: "direct", Type: PathDirect, NextPeer: "peer-2", RTTMilliseconds: 20, JitterMilliseconds: 3, BandwidthMbps: 80, Stability: .98}
	relay := LinkProfile{PathID: "relay", Type: PathRelay, NextPeer: "relay-1", RTTMilliseconds: 70, JitterMilliseconds: 10, BandwidthMbps: 90, Stability: .95, RelayCost: 2}
	decision := Select([]LinkProfile{relay, direct}, Constraints{FlowClass: FlowLatency, MaxRTTMilliseconds: 100}, "")
	if decision.Path.PathID != direct.PathID {
		t.Fatalf("selected %q, want direct", decision.Path.PathID)
	}
	if decision.Fallback == nil || decision.Fallback.PathID != relay.PathID {
		t.Fatalf("relay fallback missing: %+v", decision)
	}
}

func TestSelectHonorsHardConstraintsAndCost(t *testing.T) {
	fastPublic := LinkProfile{PathID: "public", Type: PathRelay, NextPeer: "public-relay", RTTMilliseconds: 30, LossPercent: 0, BandwidthMbps: 300, Stability: .99, PublicRelay: true}
	slowPrivate := LinkProfile{PathID: "private", Type: PathRelay, NextPeer: "private-relay", RTTMilliseconds: 65, LossPercent: 0, BandwidthMbps: 60, Stability: .98}
	decision := Select([]LinkProfile{fastPublic, slowPrivate}, Constraints{FlowClass: FlowCost, AllowPublicRelay: false}, "")
	if decision.Path.PathID != slowPrivate.PathID {
		t.Fatalf("selected %q, want private", decision.Path.PathID)
	}
}
