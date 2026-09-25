package link

import (
	"context"
	"encoding/json"
	"sync"
	"time"

	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/netp2p/netp2p/internal/p2p"
)

type gossipMessage struct {
	ObservedAt   time.Time     `json:"observedAt"`
	Observations []Observation `json:"observations"`
}

type Gossiper struct {
	node     *p2p.Node
	interval time.Duration
	ttl      time.Duration
	maxRTT   float64
	peers    []peer.ID

	mu           sync.RWMutex
	observations []Observation
	view         LinkView
}

func NewGossiper(node *p2p.Node, peers []peer.ID, interval time.Duration, ttl time.Duration, maxRTT float64) *Gossiper {
	if interval <= 0 {
		interval = 10 * time.Second
	}
	if ttl <= 0 {
		ttl = 90 * time.Second
	}
	return &Gossiper{node: node, peers: peers, interval: interval, ttl: ttl, maxRTT: maxRTT}
}

// Publish records the local manager's own observations.
func (gossiper *Gossiper) Publish(observations []Observation) {
	gossiper.mu.Lock()
	gossiper.observations = append([]Observation{}, observations...)
	gossiper.view = Aggregate(gossiper.observations, time.Now().UTC(), gossiper.ttl, gossiper.maxRTT)
	gossiper.mu.Unlock()
}

func (gossiper *Gossiper) View() LinkView {
	gossiper.mu.RLock()
	defer gossiper.mu.RUnlock()
	return gossiper.view
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
	message := gossipMessage{ObservedAt: time.Now().UTC(), Observations: gossiper.observations}
	gossiper.mu.RUnlock()
	for _, peerID := range gossiper.peers {
		sendContext, cancel := context.WithTimeout(ctx, 2*time.Second)
		if err := gossiper.node.Send(sendContext, peerID, p2p.ProbeProtocol, message); err != nil {
			_ = err
		}
		cancel()
	}
}

// PublishManagerObservation feeds a manager-to-manager measurement into the
// certified-observer matrix. Client admissions never enter this path.
func (gossiper *Gossiper) PublishManagerObservation(observer, subject string, rttMs, lossPct float64) {
	observation := Observation{
		ObserverID: observer, SubjectID: subject, Scope: ScopeManagerMesh,
		Direction: DirectionRoundTrip, RTTMilliseconds: rttMs, LossPercent: lossPct,
		BandwidthMbps: 0, Samples: 1, MeasuredAt: time.Now().UTC(), Sequence: uint64(time.Now().UnixNano()),
	}
	gossiper.Publish([]Observation{observation})
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
	for _, observation := range message.Observations {
		if observation.ObserverID != stream.Conn().RemotePeer().String() {
			return
		}
	}
	gossiper.mu.Lock()
	gossiper.observations = append(gossiper.observations, message.Observations...)
	gossiper.view = Aggregate(gossiper.observations, time.Now().UTC(), gossiper.ttl, gossiper.maxRTT)
	gossiper.mu.Unlock()
}
