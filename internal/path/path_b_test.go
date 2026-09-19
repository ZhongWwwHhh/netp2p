package path

import "testing"

// When both direct and relay are healthy, direct wins because of the switch
// penalty and latency-dominant weighting.
func TestBDirectWinsWhenBothHealthy(t *testing.T) {
	direct := LinkProfile{PathID: "direct", Type: PathDirect, RTTMilliseconds: 20, LossPercent: 0, BandwidthMbps: 100, Stability: 1}
	relay := LinkProfile{PathID: "relay", Type: PathRelay, RTTMilliseconds: 25, LossPercent: 0, BandwidthMbps: 100, Stability: 1, RelayCost: 1}
	decision := Select([]LinkProfile{direct, relay}, Constraints{FlowClass: FlowLatency, MinBandwidthMbps: 10, RelayLatencyAdvantageMs: 50, RelayLossAdvantagePct: 5}, "")
	if decision.Path.PathID != "direct" {
		t.Fatalf("selected %q, want direct", decision.Path.PathID)
	}
}

// A relay that is 60ms faster than direct must win the score.
func TestBFastRelayWins(t *testing.T) {
	direct := LinkProfile{PathID: "direct", Type: PathDirect, RTTMilliseconds: 80, LossPercent: 2, BandwidthMbps: 50, Stability: 1}
	relay := LinkProfile{PathID: "relay", Type: PathRelay, RTTMilliseconds: 15, LossPercent: 0, BandwidthMbps: 100, Stability: 1, RelayCost: 0}
	decision := Select([]LinkProfile{direct, relay}, Constraints{FlowClass: FlowLatency, MinBandwidthMbps: 10, RelayLatencyAdvantageMs: 50, RelayLossAdvantagePct: 5}, "")
	if decision.Path.PathID != "relay" {
		t.Fatalf("selected %q, want relay (relay has large latency advantage)", decision.Path.PathID)
	}
}

// A relay that is only 30ms faster does not beat direct: the advantage is
// within the threshold and the switch penalty holds direct.
func TestBMarginalRelayDoesNotWin(t *testing.T) {
	direct := LinkProfile{PathID: "direct", Type: PathDirect, RTTMilliseconds: 60, LossPercent: 0, BandwidthMbps: 100, Stability: 1}
	relay := LinkProfile{PathID: "relay", Type: PathRelay, RTTMilliseconds: 30, LossPercent: 0, BandwidthMbps: 100, Stability: 1, RelayCost: 0}
	decision := Select([]LinkProfile{direct, relay}, Constraints{FlowClass: FlowLatency, MinBandwidthMbps: 10, RelayLossAdvantagePct: 5}, "")
	if decision.Path.PathID != "direct" {
		t.Fatalf("selected %q, want direct", decision.Path.PathID)
	}
}

// A relay with significantly lower loss should win over a lossy direct.
func TestBLowLossRelayWins(t *testing.T) {
	direct := LinkProfile{PathID: "direct", Type: PathDirect, RTTMilliseconds: 30, LossPercent: 8, BandwidthMbps: 100, Stability: 1}
	relay := LinkProfile{PathID: "relay", Type: PathRelay, RTTMilliseconds: 35, LossPercent: 0, BandwidthMbps: 100, Stability: 1, RelayCost: 0}
	decision := Select([]LinkProfile{direct, relay}, Constraints{FlowClass: FlowLatency, MinBandwidthMbps: 10, RelayLatencyAdvantageMs: 50, RelayLossAdvantagePct: 5}, "")
	if decision.Path.PathID != "relay" {
		t.Fatalf("selected %q, want relay for lower loss", decision.Path.PathID)
	}
}

// Bandwidth below the minimum is a hard reject.
func TestBBelowBandwidthRejected(t *testing.T) {
	direct := LinkProfile{PathID: "direct", Type: PathDirect, RTTMilliseconds: 20, LossPercent: 0, BandwidthMbps: 5, Stability: 1}
	score := Score(direct, Constraints{FlowClass: FlowLatency, MinBandwidthMbps: 10})
	if score != 0 {
		t.Fatalf("score = %f, want 0 (bandwidth below hard constraint)", score)
	}
}

// Only direct available: relay is filtered out.
func TestBDirectOnly(t *testing.T) {
	direct := LinkProfile{PathID: "direct", Type: PathDirect, RTTMilliseconds: 20, LossPercent: 0, BandwidthMbps: 100, Stability: 1}
	decision := Select([]LinkProfile{direct}, Constraints{FlowClass: FlowLatency, MinBandwidthMbps: 10}, "")
	if decision.Path.PathID != "direct" {
		t.Fatal("direct should win when it is the only candidate")
	}
}

// Direct unavailable (not in candidates): relay is the winner.
func TestBRelayOnly(t *testing.T) {
	relay := LinkProfile{PathID: "relay", Type: PathRelay, RTTMilliseconds: 70, LossPercent: 0, BandwidthMbps: 80, Stability: 1, RelayCost: 0}
	decision := Select([]LinkProfile{relay}, Constraints{FlowClass: FlowLatency, MinBandwidthMbps: 10}, "")
	if decision.Path.PathID != "relay" {
		t.Fatal("relay should win when direct is unavailable")
	}
}
