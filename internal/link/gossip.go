package link

import (
	"context"
	"encoding/json"
	"sort"
	"sync"
	"time"

	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/netp2p/netp2p/internal/p2p"
)

// maxObservations bounds the gossip cache so a chatty peer cannot grow it
// without limit. The newest observations are kept.
const maxObservations = 4096

type gossipMessage struct {
	ObservedAt   time.Time     `json:"observedAt"`
	Observations []Observation `json:"observations"`
}

type Gossiper struct {
	node     *p2p.Node
	peers    []peer.ID
	localID  string
	interval time.Duration
	ttl      time.Duration
	maxRTT   float64

	mu           sync.RWMutex
	observations []Observation
	view         LinkView
}

func NewGossiper(node *p2p.Node, peers []peer.ID, localID string, interval time.Duration, ttl time.Duration, maxRTT float64) *Gossiper {
	if interval <= 0 {
		interval = 10 * time.Second
	}
	if ttl <= 0 {
		ttl = 90 * time.Second
	}
	if localID == "" {
		localID = node.Host.ID().String()
	}
	return &Gossiper{node: node, peers: peers, localID: localID, interval: interval, ttl: ttl, maxRTT: maxRTT}
}

// Publish records this manager's own observations and recomputes the view. Only
// observations attributed to the local manager are replaced; everything learned
// from other managers via gossip is preserved.
func (gossiper *Gossiper) Publish(observations []Observation) {
	gossiper.mu.Lock()
	defer gossiper.mu.Unlock()
	merged := make([]Observation, 0, len(gossiper.observations)+len(observations))
	for _, observation := range gossiper.observations {
		if observation.ObserverID == gossiper.localID {
			continue
		}
		merged = append(merged, observation)
	}
	merged = append(merged, observations...)
	gossiper.rebuildLocked(merged)
}

func (gossiper *Gossiper) View() LinkView {
	gossiper.mu.RLock()
	defer gossiper.mu.RUnlock()
	return gossiper.view
}

// Observations returns a copy of the merged, non-certified observation cache.
func (gossiper *Gossiper) Observations() []Observation {
	gossiper.mu.RLock()
	defer gossiper.mu.RUnlock()
	return append([]Observation{}, gossiper.observations...)
}

func (gossiper *Gossiper) Run(ctx context.Context) {
	ticker := time.NewTicker(gossiper.interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			gossiper.exchange(ctx)
		}
	}
}

func (gossiper *Gossiper) exchange(ctx context.Context) {
	gossiper.mu.RLock()
	message := gossipMessage{ObservedAt: time.Now().UTC(), Observations: append([]Observation{}, gossiper.observations...)}
	gossiper.mu.RUnlock()
	for _, peerID := range gossiper.peers {
		sendContext, cancel := context.WithTimeout(ctx, 2*time.Second)
		if err := gossiper.node.Send(sendContext, peerID, p2p.LinkGossipProtocol, message); err != nil {
			_ = err
		}
		cancel()
	}
}

func (gossiper *Gossiper) Handle(stream network.Stream) {
	defer stream.Close()
	envelope, err := p2p.DecodeEnvelope(stream)
	if err != nil {
		return
	}
	var message gossipMessage
	if err := json.Unmarshal(envelope.Payload, &message); err != nil {
		return
	}
	remote := stream.Conn().RemotePeer().String()
	for _, observation := range message.Observations {
		// A manager may only speak for itself: reject anything attributed to a
		// different observer so nobody can forge another manager's measurement.
		if observation.ObserverID != remote {
			return
		}
	}
	gossiper.mu.Lock()
	defer gossiper.mu.Unlock()
	gossiper.rebuildLocked(append(gossiper.observations, message.Observations...))
}

// rebuildLocked prunes, deduplicates and re-aggregates the observation cache.
// The caller must hold the write lock.
func (gossiper *Gossiper) rebuildLocked(observations []Observation) {
	gossiper.observations = pruneObservations(observations, time.Now().UTC(), gossiper.ttl)
	gossiper.view = Aggregate(gossiper.observations, time.Now().UTC(), gossiper.ttl, gossiper.maxRTT)
}

// pruneObservations drops expired entries, deduplicates by
// (observer, subject, scope, sequence) keeping the freshest copy, and caps the
// cache size.
func pruneObservations(observations []Observation, now time.Time, ttl time.Duration) []Observation {
	fresh := make([]Observation, 0, len(observations))
	for _, observation := range observations {
		if !observation.fresh(now, ttl) {
			continue
		}
		fresh = append(fresh, observation)
	}
	sort.SliceStable(fresh, func(i, j int) bool {
		if !fresh[i].MeasuredAt.Equal(fresh[j].MeasuredAt) {
			return fresh[i].MeasuredAt.After(fresh[j].MeasuredAt)
		}
		return fresh[i].Sequence > fresh[j].Sequence
	})
	seen := make(map[observationKey]struct{}, len(fresh))
	result := make([]Observation, 0, len(fresh))
	for _, observation := range fresh {
		key := observationKey{
			observer: observation.ObserverID, subject: observation.SubjectID,
			scope: observation.Scope, sequence: observation.Sequence,
		}
		if _, exists := seen[key]; exists {
			continue
		}
		seen[key] = struct{}{}
		result = append(result, observation)
		if len(result) >= maxObservations {
			break
		}
	}
	return result
}

type observationKey struct {
	observer string
	subject  string
	scope    Scope
	sequence uint64
}
