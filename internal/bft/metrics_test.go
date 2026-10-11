package bft

import (
	"testing"
	"time"

	"github.com/netp2p/netp2p/internal/metrics"
	"github.com/netp2p/netp2p/internal/model"
	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
)

func TestEngineMetricsRestoreAndTrackView(t *testing.T) {
	committee, privateKeys := testCommittee()
	engines := make([]*Engine, len(committee))
	for index, member := range committee {
		engine, err := NewEngine(testState(), committee, member.ID, privateKeys[index])
		if err != nil {
			t.Fatal(err)
		}
		engines[index] = engine
	}
	snapshot := advance(t, privateKeys, engines, model.StateTransition{
		Type: TransitionUpsertGroup, Group: &model.Group{ID: "metrics"},
	})

	collector := metrics.New()
	leader := engineForMember(t, engines, committee[0].ID)
	leader.SetMetrics(collector)
	if got := gaugeValue(t, collector.BFTHeight); got != float64(snapshot.Height) {
		t.Fatalf("restored height = %v, want %v", got, snapshot.Height)
	}
	if got := gaugeValue(t, collector.BFTRound); got != 0 {
		t.Fatalf("restored round = %v, want 0", got)
	}
	if got := gaugeValue(t, collector.BFTHeightLag); got != 0 {
		t.Fatalf("restored height lag = %v, want 0", got)
	}

	if err := leader.SetRoundTimeout(time.Nanosecond); err != nil {
		t.Fatal(err)
	}
	time.Sleep(2 * time.Nanosecond)
	if round := leader.AdvanceExpiredRound(snapshot.Height + 1); round != 1 {
		t.Fatalf("advanced round = %d, want 1", round)
	}
	if got := gaugeValue(t, collector.BFTRound); got != 1 {
		t.Fatalf("round gauge = %v, want 1", got)
	}
	if got := counterValue(t, collector.BFTRoundTimeouts); got != 1 {
		t.Fatalf("round timeout count = %v, want 1", got)
	}

	leader.ObserveCertifiedHeight(snapshot.Height + 3)
	if got := gaugeValue(t, collector.BFTHeightLag); got != 3 {
		t.Fatalf("height lag = %v, want 3", got)
	}
	if got := leader.KnownHeight(); got != snapshot.Height+3 {
		t.Fatalf("known height = %d, want %d", got, snapshot.Height+3)
	}

}

func gaugeValue(t *testing.T, gauge prometheus.Gauge) float64 {
	t.Helper()
	var metric dto.Metric
	if err := gauge.Write(&metric); err != nil {
		t.Fatal(err)
	}
	return metric.GetGauge().GetValue()
}

func counterValue(t *testing.T, counter prometheus.Counter) float64 {
	t.Helper()
	var metric dto.Metric
	if err := counter.Write(&metric); err != nil {
		t.Fatal(err)
	}
	return metric.GetCounter().GetValue()
}
