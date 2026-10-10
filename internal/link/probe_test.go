package link

import (
	"testing"
	"time"

	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/netp2p/netp2p/internal/model"
	"github.com/netp2p/netp2p/internal/p2p"
)

func TestSummarizePingsComputesRTTJitterAndLoss(t *testing.T) {
	samples := []time.Duration{10 * time.Millisecond, 20 * time.Millisecond, 30 * time.Millisecond}
	rtt, jitter, loss := summarizePings(samples, 5)
	if rtt != 20 {
		t.Fatalf("rtt = %f, want 20", rtt)
	}
	if jitter != 10 {
		t.Fatalf("jitter = %f, want 10", jitter)
	}
	if loss != 40 {
		t.Fatalf("loss = %f, want 40", loss)
	}
	if _, _, loss := summarizePings(nil, 5); loss != 100 {
		t.Fatalf("total-loss probe = %f, want 100", loss)
	}
}

func TestBandwidthMbps(t *testing.T) {
	// 128 KiB in 100ms is roughly 10.5 Mbps.
	got := bandwidthMbps(128*1024, 100*time.Millisecond)
	if got < 10 || got > 11 {
		t.Fatalf("bandwidth = %f, want ~10.5", got)
	}
	if bandwidthMbps(0, time.Second) != 0 || bandwidthMbps(10, 0) != 0 {
		t.Fatal("degenerate inputs must report zero bandwidth")
	}
}

func TestProbeResponderAndProberOverLibp2p(t *testing.T) {
	prober, responderID := newProbeTargetPair(t)
	ctx := t.Context()

	elapsed, err := prober.ping(ctx, responderID, 2*time.Second)
	if err != nil {
		t.Fatalf("ping: %v", err)
	}
	// Fast local stream round-trips can resolve to zero on low-resolution clocks.
	if elapsed < 0 {
		t.Fatalf("ping elapsed = %v", elapsed)
	}
	total, received, err := prober.bandwidth(ctx, responderID, 5*time.Second, 64*1024)
	if err != nil {
		t.Fatalf("bandwidth: %v", err)
	}
	if received != 64*1024 {
		t.Fatalf("received = %d, want %d", received, 64*1024)
	}
	if total <= 0 || bandwidthMbps(received, total) <= 0 {
		t.Fatalf("bandwidth estimate is not positive: total=%v", total)
	}
}

// TestProberSkipsBandwidthWhenBudgetExhausted verifies the per-cycle budget:
// once too little remains, only the latency/loss measurement is taken.
func TestProberSkipsBandwidthWhenBudgetExhausted(t *testing.T) {
	prober, responderID := newProbeTargetPair(t)
	target := probeTarget{peerID: responderID, scope: ScopeAccess}
	observation, used := prober.probeTarget(t.Context(), target, 2*time.Second, minBandwidthBurst-1)
	if observation == nil {
		t.Fatal("probe returned no observation")
	}
	if used != 0 {
		t.Fatalf("budget used = %d, want 0", used)
	}
	if observation.BandwidthMbps != 0 {
		t.Fatalf("bandwidth = %f, want 0 when the budget is exhausted", observation.BandwidthMbps)
	}
}

func TestProberProbeOncePublishesAccessSegment(t *testing.T) {
	prober, responderID := newProbeTargetPair(t)
	gossiper := NewGossiper(prober.node, nil, prober.localID, time.Minute, time.Minute, 0)
	prober.gossiper = gossiper
	state := func() model.NetworkState {
		return model.NetworkState{Peers: []model.PeerRecord{{PeerID: responderID.String()}}}
	}
	prober.state = state
	prober.committee = func() []model.CommitteeMember { return nil }
	prober.ProbeOnce(t.Context(), model.NetworkSettings{})

	view := gossiper.View()
	if len(view.AccessSegments) != 1 {
		t.Fatalf("access segments = %d, want 1", len(view.AccessSegments))
	}
	if len(view.Segments) != 0 {
		t.Fatalf("mesh segments = %d, want 0 (access must not enter the mesh matrix)", len(view.Segments))
	}
}

// newProbeTargetPair builds two connected libp2p nodes and installs the probe
// responder on the second one.
func newProbeTargetPair(t *testing.T) (*Prober, peer.ID) {
	t.Helper()
	ctx := t.Context()
	proberNode, err := p2p.New(ctx, p2p.Config{Listen: []string{"/ip4/127.0.0.1/tcp/0"}})
	if err != nil {
		t.Fatal(err)
	}
	responder, err := p2p.New(ctx, p2p.Config{Listen: []string{"/ip4/127.0.0.1/tcp/0"}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = proberNode.Close()
		_ = responder.Close()
	})
	responder.Handle(p2p.ProbeProtocol, NewProbeResponder().Handle)
	addresses := responder.Addresses()
	if len(addresses) == 0 {
		t.Fatal("responder has no addresses")
	}
	info, err := peer.AddrInfoFromString(addresses[0])
	if err != nil {
		t.Fatal(err)
	}
	if err := proberNode.Host.Connect(ctx, *info); err != nil {
		t.Fatalf("connect: %v", err)
	}
	prober := NewProber(proberNode, func() model.NetworkState { return model.NetworkState{} }, func() []model.CommitteeMember { return nil }, nil)
	return prober, info.ID
}
