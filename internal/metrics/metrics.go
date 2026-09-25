// Package metrics exposes Prometheus instrumentation for the manager. Metrics
// are opt-in: nothing is exported until an operator starts the metrics listener.
package metrics

import (
	"net/http"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// Metrics bundles the collectors the manager updates. All fields are safe to
// use concurrently.
type Metrics struct {
	registry *prometheus.Registry

	BFTHeight      prometheus.Gauge
	BFTCommits     prometheus.Counter
	BFTRejected    prometheus.Counter
	Forwarded      prometheus.Counter
	ForwardDrops   prometheus.Counter
	SyncRequests   prometheus.Counter
	QuotaBlocked   prometheus.Counter
	CertifiedPeers prometheus.Gauge
	LinkSegments   prometheus.Gauge
	LinkConfidence prometheus.Gauge
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
		BFTRejected: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "netp2p_bft_rejected_total", Help: "Number of rejected votes or certificates.",
		}),
		Forwarded: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "netp2p_forward_forwarded_total", Help: "Frames forwarded on behalf of other peers.",
		}),
		ForwardDrops: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "netp2p_forward_dropped_total", Help: "Forwarded frames dropped by validation or backpressure.",
		}),
		SyncRequests: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "netp2p_sync_requests_total", Help: "Client sync requests served.",
		}),
		QuotaBlocked: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "netp2p_quota_blocked_packets_total", Help: "Packets dropped because a budget was exhausted.",
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
		metrics.BFTHeight, metrics.BFTCommits, metrics.BFTRejected,
		metrics.Forwarded, metrics.ForwardDrops, metrics.SyncRequests,
		metrics.QuotaBlocked, metrics.CertifiedPeers, metrics.LinkSegments,
		metrics.LinkConfidence,
	)
	return metrics
}

// Handler serves the Prometheus exposition format.
func (metrics *Metrics) Handler() http.Handler {
	return promhttp.HandlerFor(metrics.registry, promhttp.HandlerOpts{})
}
