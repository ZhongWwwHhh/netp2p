package path

import "testing"

func TestSelectPrefersGoodDirectForLatency(t *testing.T) {
	direct := LinkProfile{PathID: "direct", Type: PathDirect, NextPeer: "peer-2", RTTMilliseconds: 20, JitterMilliseconds: 3, BandwidthMbps: 80, Stability: .98}
	viaManager := LinkProfile{PathID: "via", Type: PathViaManager, NextPeer: "manager-1", RTTMilliseconds: 70, JitterMilliseconds: 10, BandwidthMbps: 90, Stability: .95, ForwardingCost: 2}
	decision := Select([]LinkProfile{viaManager, direct}, Constraints{FlowClass: FlowLatency, MaxRTTMilliseconds: 100}, "")
	if decision.Path.PathID != direct.PathID {
		t.Fatalf("selected %q, want direct", decision.Path.PathID)
	}
	if decision.Fallback == nil || decision.Fallback.PathID != viaManager.PathID {
		t.Fatalf("via-manager fallback missing: %+v", decision)
	}
}

func TestSelectHonorsForwardingCostLimit(t *testing.T) {
	fastExpensive := LinkProfile{PathID: "expensive", Type: PathViaManager, NextPeer: "manager-a", RTTMilliseconds: 30, LossPercent: 0, BandwidthMbps: 300, Stability: .99, ForwardingCost: 80}
	slowCheap := LinkProfile{PathID: "cheap", Type: PathViaManager, NextPeer: "manager-b", RTTMilliseconds: 65, LossPercent: 0, BandwidthMbps: 60, Stability: .98, ForwardingCost: 5}
	decision := Select([]LinkProfile{fastExpensive, slowCheap}, Constraints{FlowClass: FlowCost, MaxForwardingCost: 50}, "")
	if decision.Path.PathID != slowCheap.PathID {
		t.Fatalf("selected %q, want cheap path", decision.Path.PathID)
	}
}

// Unknown bandwidth means "not measured", not "no bandwidth": it must not trip
// the minimum-bandwidth hard constraint, while a measured low value still does.
func TestSelectUnknownBandwidthIsNotRejected(t *testing.T) {
	unknown := LinkProfile{PathID: "direct", Type: PathDirect, RTTMilliseconds: 25, LossPercent: 0, Stability: 1}
	if score := Score(unknown, Constraints{FlowClass: FlowLatency, MinBandwidthMbps: 10}); score <= 0 {
		t.Fatalf("score = %f, want > 0 for unknown bandwidth", score)
	}
	measuredLow := LinkProfile{PathID: "direct", Type: PathDirect, RTTMilliseconds: 25, LossPercent: 0, BandwidthMbps: 4, Stability: 1}
	if got := Score(measuredLow, Constraints{FlowClass: FlowLatency, MinBandwidthMbps: 10}); got != 0 {
		t.Fatalf("measured-bandwidth score = %f, want 0", got)
	}
}
