package path

import "testing"

// When both direct and via-manager are healthy, direct wins because of the
// switch penalty and latency-dominant weighting.
func TestBDirectWinsWhenBothHealthy(t *testing.T) {
	direct := LinkProfile{PathID: "direct", Type: PathDirect, RTTMilliseconds: 20, LossPercent: 0, BandwidthMbps: 100, Stability: 1}
	viaManager := LinkProfile{PathID: "via", Type: PathViaManager, RTTMilliseconds: 25, LossPercent: 0, BandwidthMbps: 100, Stability: 1, ForwardingCost: 1}
	decision := Select([]LinkProfile{direct, viaManager}, Constraints{FlowClass: FlowLatency, MinBandwidthMbps: 10, ViaManagerLatencyAdvantageMs: 50, ViaManagerLossAdvantagePct: 5}, "")
	if decision.Path.PathID != "direct" {
		t.Fatalf("selected %q, want direct", decision.Path.PathID)
	}
}

// A via-manager path that is 60ms faster than direct must win the score.
func TestBFastViaManagerWins(t *testing.T) {
	direct := LinkProfile{PathID: "direct", Type: PathDirect, RTTMilliseconds: 80, LossPercent: 2, BandwidthMbps: 50, Stability: 1}
	viaManager := LinkProfile{PathID: "via", Type: PathViaManager, RTTMilliseconds: 15, LossPercent: 0, BandwidthMbps: 100, Stability: 1, ForwardingCost: 0}
	decision := Select([]LinkProfile{direct, viaManager}, Constraints{FlowClass: FlowLatency, MinBandwidthMbps: 10, ViaManagerLatencyAdvantageMs: 50, ViaManagerLossAdvantagePct: 5}, "")
	if decision.Path.PathID != "via" {
		t.Fatalf("selected %q, want via-manager (large latency advantage)", decision.Path.PathID)
	}
}

// A via-manager path that is only 30ms faster does not beat direct: the
// advantage is within the threshold and the switch penalty holds direct.
func TestBMarginalViaManagerDoesNotWin(t *testing.T) {
	direct := LinkProfile{PathID: "direct", Type: PathDirect, RTTMilliseconds: 60, LossPercent: 0, BandwidthMbps: 100, Stability: 1}
	viaManager := LinkProfile{PathID: "via", Type: PathViaManager, RTTMilliseconds: 30, LossPercent: 0, BandwidthMbps: 100, Stability: 1, ForwardingCost: 0}
	decision := Select([]LinkProfile{direct, viaManager}, Constraints{FlowClass: FlowLatency, MinBandwidthMbps: 10, ViaManagerLossAdvantagePct: 5}, "")
	if decision.Path.PathID != "direct" {
		t.Fatalf("selected %q, want direct", decision.Path.PathID)
	}
}

// A via-manager path with significantly lower loss should win over a lossy
// direct connection.
func TestBLowLossViaManagerWins(t *testing.T) {
	direct := LinkProfile{PathID: "direct", Type: PathDirect, RTTMilliseconds: 30, LossPercent: 8, BandwidthMbps: 100, Stability: 1}
	viaManager := LinkProfile{PathID: "via", Type: PathViaManager, RTTMilliseconds: 35, LossPercent: 0, BandwidthMbps: 100, Stability: 1, ForwardingCost: 0}
	decision := Select([]LinkProfile{direct, viaManager}, Constraints{FlowClass: FlowLatency, MinBandwidthMbps: 10, ViaManagerLatencyAdvantageMs: 50, ViaManagerLossAdvantagePct: 5}, "")
	if decision.Path.PathID != "via" {
		t.Fatalf("selected %q, want via-manager for lower loss", decision.Path.PathID)
	}
}

// Bandwidth below the minimum is a hard reject once it has been measured.
func TestBBelowBandwidthRejected(t *testing.T) {
	direct := LinkProfile{PathID: "direct", Type: PathDirect, RTTMilliseconds: 20, LossPercent: 0, BandwidthMbps: 5, Stability: 1}
	score := Score(direct, Constraints{FlowClass: FlowLatency, MinBandwidthMbps: 10})
	if score != 0 {
		t.Fatalf("score = %f, want 0 (bandwidth below hard constraint)", score)
	}
}

// Only direct available: the via-manager candidate is absent.
func TestBDirectOnly(t *testing.T) {
	direct := LinkProfile{PathID: "direct", Type: PathDirect, RTTMilliseconds: 20, LossPercent: 0, BandwidthMbps: 100, Stability: 1}
	decision := Select([]LinkProfile{direct}, Constraints{FlowClass: FlowLatency, MinBandwidthMbps: 10}, "")
	if decision.Path.PathID != "direct" {
		t.Fatal("direct should win when it is the only candidate")
	}
}

// Direct unavailable (not in candidates): via-manager is the winner.
func TestBViaManagerOnly(t *testing.T) {
	viaManager := LinkProfile{PathID: "via", Type: PathViaManager, RTTMilliseconds: 70, LossPercent: 0, BandwidthMbps: 80, Stability: 1, ForwardingCost: 0}
	decision := Select([]LinkProfile{viaManager}, Constraints{FlowClass: FlowLatency, MinBandwidthMbps: 10}, "")
	if decision.Path.PathID != "via" {
		t.Fatal("via-manager should win when direct is unavailable")
	}
}
