// Package metrics exposes Prometheus instrumentation for the manager. Metrics
// are opt-in: nothing is exported until an operator starts the metrics listener.
package metrics

import (
	"net/http"
	"strconv"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// Metrics bundles the collectors the manager updates. All fields are safe to
// use concurrently.
type Metrics struct {
	registry *prometheus.Registry

	BFTHeight              prometheus.Gauge
	BFTCommits             prometheus.Counter
	BFTRejected            prometheus.Counter
	BFTLastCommitTime      prometheus.Gauge
	BFTRound               prometheus.Gauge
	BFTUncommitted         prometheus.Gauge
	BFTRoundTimeouts       prometheus.Counter
	BFTHeightLag           prometheus.Gauge
	BFTSubmitAttempts      *prometheus.CounterVec
	BFTSubmitFailures      *prometheus.CounterVec
	BFTSubmitTotal         prometheus.Counter
	BFTSubmitFailuresTotal prometheus.Counter
	BFTCatchUps            prometheus.Counter
	BFTCatchupFailures     prometheus.Counter
	Forwarded              prometheus.Counter
	ForwardDrops           prometheus.Counter
	ForwardQueueDepth      prometheus.Gauge
	SyncRequests           prometheus.Counter
	SyncErrors             prometheus.Counter
	SyncTimeouts           prometheus.Counter
	QuotaBlocked           prometheus.Counter
	DNSFailures            prometheus.Counter
	CertifiedPeers         prometheus.Gauge
	LinkSegments           prometheus.Gauge
	LinkConfidence         prometheus.Gauge
}

// New builds an isolated registry so tests and multiple managers do not share
// global state.
func New() *Metrics {
	registry := prometheus.NewRegistry()
	metrics := &Metrics{
		registry: registry,
		BFTHeight: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "netp2p_bft_height", Help: "Latest committed consensus height.",
		}),
		BFTCommits: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "netp2p_bft_commits_total", Help: "Number of committed heights observed locally.",
		}),
		BFTLastCommitTime: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "netp2p_bft_last_commit_timestamp_seconds",
			Help: "Unix timestamp of the latest certified height known to this process.",
		}),
		BFTRejected: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "netp2p_bft_rejected_total", Help: "Number of rejected votes or certificates.",
		}),
		BFTRound: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "netp2p_bft_round", Help: "Current local consensus round or view.",
		}),
		BFTUncommitted: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "netp2p_bft_uncommitted_proposals", Help: "Uncommitted proposals stored for the next height.",
		}),
		BFTRoundTimeouts: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "netp2p_bft_round_timeouts_total", Help: "Local consensus rounds that expired.",
		}),
		BFTHeightLag: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "netp2p_bft_height_lag", Help: "Difference between the highest known certified height and the local committed height.",
		}),
		BFTSubmitAttempts: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "netp2p_bft_submit_attempts_by_result_total",
			Help: "State transition submission attempts by result and consensus round.",
		}, []string{"result", "round"}),
		BFTSubmitFailures: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "netp2p_bft_submit_failures_by_result_total",
			Help: "State transition submission failures by result and consensus round.",
		}, []string{"result", "round"}),
		BFTSubmitTotal: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "netp2p_bft_submit_attempts_total", Help: "State transitions submitted to the committee.",
		}),
		BFTSubmitFailuresTotal: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "netp2p_bft_submit_failures_total", Help: "State transitions that failed to reach a certified quorum.",
		}),
		BFTCatchUps: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "netp2p_bft_catchup_success_total", Help: "Committee catch-up passes that advanced the local ledger.",
		}),
		BFTCatchupFailures: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "netp2p_bft_catchup_failures_total", Help: "Committee catch-up passes that failed or did not advance.",
		}),
		Forwarded: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "netp2p_forward_forwarded_total", Help: "Frames forwarded on behalf of other peers.",
		}),
		ForwardDrops: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "netp2p_forward_dropped_total", Help: "Forwarded frames dropped by validation or backpressure.",
		}),
		ForwardQueueDepth: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "netp2p_forward_queue_depth", Help: "Frames currently being handed to the forwarding transport.",
		}),
		SyncRequests: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "netp2p_sync_requests_total", Help: "Client sync requests served.",
		}),
		SyncErrors: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "netp2p_sync_errors_total", Help: "Client sync requests that failed validation or response writes.",
		}),
		SyncTimeouts: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "netp2p_sync_timeouts_total", Help: "Client sync long polls closed at the session lifetime limit.",
		}),
		QuotaBlocked: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "netp2p_quota_blocked_packets_total", Help: "Packets dropped because a budget was exhausted.",
		}),
		DNSFailures: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "netp2p_dns_failures_total", Help: "DNS queries that could not be resolved.",
		}),
		CertifiedPeers: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "netp2p_certified_peers", Help: "Peers present in certified state.",
		}),
		LinkSegments: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "netp2p_link_segments", Help: "Number of measured link segments in the current view.",
		}),
		LinkConfidence: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "netp2p_link_min_confidence", Help: "Lowest segment confidence in the current link view.",
		}),
	}
	registry.MustRegister(
		metrics.BFTHeight, metrics.BFTCommits, metrics.BFTRejected, metrics.BFTLastCommitTime,
		metrics.BFTRound, metrics.BFTUncommitted, metrics.BFTRoundTimeouts, metrics.BFTHeightLag,
		metrics.BFTSubmitTotal, metrics.BFTSubmitFailuresTotal,
		metrics.BFTCatchUps, metrics.BFTCatchupFailures,
		metrics.BFTSubmitAttempts, metrics.BFTSubmitFailures,
		metrics.Forwarded, metrics.ForwardDrops, metrics.SyncRequests, metrics.SyncErrors, metrics.SyncTimeouts,
		metrics.QuotaBlocked, metrics.CertifiedPeers, metrics.LinkSegments,
		metrics.LinkConfidence, metrics.ForwardQueueDepth, metrics.DNSFailures,
		collectors.NewGoCollector(),
		collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}),
	)
	return metrics
}

// RestoreBFTSnapshot initializes gauges after a manager restart. It does not
// increment commit counters: those describe commits observed by this process.
func (metrics *Metrics) RestoreBFTSnapshot(height uint64, certifiedAt time.Time) {
	if metrics == nil {
		return
	}
	metrics.BFTHeight.Set(float64(height))
	if !certifiedAt.IsZero() {
		metrics.BFTLastCommitTime.Set(unixSeconds(certifiedAt))
	}
}

// SetBFTView initializes or refreshes the local round and proposal gauges.
func (metrics *Metrics) SetBFTView(round uint64, uncommitted int) {
	if metrics == nil {
		return
	}
	metrics.BFTRound.Set(float64(round))
	metrics.BFTUncommitted.Set(float64(uncommitted))
}

// SetBFTHeightLag reports how far the local ledger is behind the highest
// certified snapshot this process has authenticated.
func (metrics *Metrics) SetBFTHeightLag(local, known uint64) {
	if metrics == nil || known <= local {
		if metrics != nil {
			metrics.BFTHeightLag.Set(0)
		}
		return
	}
	metrics.BFTHeightLag.Set(float64(known - local))
}

// RecordBFTRoundTimeout counts an expired local consensus view.
func (metrics *Metrics) RecordBFTRoundTimeout() {
	if metrics == nil {
		return
	}
	metrics.BFTRoundTimeouts.Inc()
}

// RecordBFTSubmit classifies one submission outcome at the round where the
// engine attempted or waited for consensus.
func (metrics *Metrics) RecordBFTSubmit(result string, round uint64, failed bool) {
	if metrics == nil || result == "" {
		return
	}
	label := strconv.FormatUint(round, 10)
	metrics.BFTSubmitTotal.Inc()
	metrics.BFTSubmitAttempts.WithLabelValues(result, label).Inc()
	if failed {
		metrics.BFTSubmitFailuresTotal.Inc()
		metrics.BFTSubmitFailures.WithLabelValues(result, label).Inc()
	}
}

// PublishBFTCommit records a newly observed certified height.
func (metrics *Metrics) PublishBFTCommit(height uint64, committedAt time.Time) {
	if metrics == nil {
		return
	}
	metrics.RestoreBFTSnapshot(height, committedAt)
	metrics.BFTCommits.Inc()
}

func (metrics *Metrics) RecordSyncRequest() {
	if metrics == nil {
		return
	}
	metrics.SyncRequests.Inc()
}

func (metrics *Metrics) RecordSyncError() {
	if metrics == nil {
		return
	}
	metrics.SyncErrors.Inc()
}

func (metrics *Metrics) RecordSyncTimeout() {
	if metrics == nil {
		return
	}
	metrics.SyncTimeouts.Inc()
}

func unixSeconds(timestamp time.Time) float64 {
	return float64(timestamp.UnixNano()) / float64(time.Second)
}

// Handler serves the Prometheus exposition format.
func (metrics *Metrics) Handler() http.Handler {
	return promhttp.HandlerFor(metrics.registry, promhttp.HandlerOpts{})
}
