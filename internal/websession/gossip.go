// Package websession replicates browser-session records between committee
// managers without putting interactive console logins into the BFT decision log.
package websession

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/netp2p/netp2p/internal/p2p"
	"github.com/netp2p/netp2p/internal/store"
)

const (
	pageSize = 500
	interval = 10 * time.Second
)

type gossipMessage struct {
	Sessions []store.WebSession `json:"sessions,omitempty"`
	Cursor   string             `json:"cursor,omitempty"`
	Limit    int                `json:"limit,omitempty"`
}

// Gossiper exchanges the manager-local web_sessions table with the other
// committee members. The peer allow-list is installed before the handler is
// registered, so non-committee streams are rejected before any payload is read.
type Gossiper struct {
	node   *p2p.Node
	store  *store.Store
	peers  map[peer.ID]struct{}
	peerMu sync.RWMutex
	ctxMu  sync.Mutex
	ctx    context.Context
	cancel context.CancelFunc
}

func NewGossiper(node *p2p.Node, stateStore *store.Store, peers []peer.ID) *Gossiper {
	peerSet := make(map[peer.ID]struct{}, len(peers))
	for _, peerID := range peers {
		peerSet[peerID] = struct{}{}
	}
	gossiper := &Gossiper{node: node, store: stateStore, peers: peerSet}
	node.Handle(p2p.WebSessionProtocol, gossiper.handle)
	return gossiper
}

// SetPeers atomically replaces the committee allow-list. It is called after a
// certified committee resize so a newly activated manager can exchange session
// records and a removed manager immediately loses stream access.
func (gossiper *Gossiper) SetPeers(peers []peer.ID) {
	peerSet := make(map[peer.ID]struct{}, len(peers))
	for _, peerID := range peers {
		peerSet[peerID] = struct{}{}
	}
	gossiper.peerMu.Lock()
	gossiper.peers = peerSet
	gossiper.peerMu.Unlock()
}

func (gossiper *Gossiper) peerSnapshot() map[peer.ID]struct{} {
	gossiper.peerMu.RLock()
	defer gossiper.peerMu.RUnlock()
	peers := make(map[peer.ID]struct{}, len(gossiper.peers))
	for peerID := range gossiper.peers {
		peers[peerID] = struct{}{}
	}
	return peers
}

// Run exchanges session state immediately and then on a fixed interval. The
// immediate pass lets a restarted or newly joined manager catch up before it
// serves a round-robin console request.
func (gossiper *Gossiper) Run(ctx context.Context) {
	gossiper.ctxMu.Lock()
	if gossiper.cancel != nil {
		gossiper.cancel()
	}
	gossiper.ctx, gossiper.cancel = context.WithCancel(ctx)
	runCtx := gossiper.ctx
	gossiper.ctxMu.Unlock()

	_ = gossiper.Sync(runCtx)
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-runCtx.Done():
			return
		case <-ticker.C:
			_ = gossiper.Sync(runCtx)
		}
	}
}

// Sync exchanges all pages with every configured committee peer. A single
// successful peer is enough for eventual propagation; all failures are returned
// so login can refuse to hand out a cookie that no other manager can validate.
func (gossiper *Gossiper) Sync(ctx context.Context) error {
	peers := gossiper.peerSnapshot()
	if len(peers) == 0 {
		return nil
	}
	syncCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()

	var (
		waitGroup sync.WaitGroup
		mutex     sync.Mutex
		failures  []error
		successes int
	)
	for peerID := range peers {
		waitGroup.Add(1)
		go func(peerID peer.ID) {
			defer waitGroup.Done()
			if err := gossiper.exchangeWith(syncCtx, peerID); err != nil {
				mutex.Lock()
				failures = append(failures, fmt.Errorf("%s: %w", peerID.String(), err))
				mutex.Unlock()
				return
			}
			if err := gossiper.pullFrom(syncCtx, peerID); err != nil {
				mutex.Lock()
				failures = append(failures, fmt.Errorf("%s: %w", peerID.String(), err))
				mutex.Unlock()
				return
			}
			mutex.Lock()
			successes++
			mutex.Unlock()
		}(peerID)
	}
	waitGroup.Wait()
	if successes == 0 {
		return errors.Join(failures...)
	}
	return nil
}

func (gossiper *Gossiper) exchangeWith(ctx context.Context, peerID peer.ID) error {
	// Push and pull use independent cursors. Coupling them would let a remote
	// page cursor skip local records whose IDs sort before it.
	cursor := ""
	for {
		sessions, err := gossiper.store.WebSessionsAfter(cursor, pageSize)
		if err != nil {
			return err
		}
		response, err := gossiper.roundTrip(ctx, peerID, gossipMessage{
			Sessions: sessions, Limit: 0,
		})
		if err != nil {
			return err
		}
		_ = response
		if len(sessions) < pageSize {
			return nil
		}
		cursor = sessions[len(sessions)-1].ID
	}
}

func (gossiper *Gossiper) pullFrom(ctx context.Context, peerID peer.ID) error {
	cursor := ""
	for {
		response, err := gossiper.roundTrip(ctx, peerID, gossipMessage{
			Cursor: cursor, Limit: pageSize,
		})
		if err != nil {
			return err
		}
		if len(response.Sessions) == 0 {
			return nil
		}
		lastID := response.Sessions[len(response.Sessions)-1].ID
		if lastID <= cursor {
			return fmt.Errorf("web session pagination did not advance")
		}
		cursor = lastID
		if len(response.Sessions) < pageSize {
			return nil
		}
	}
}

func (gossiper *Gossiper) roundTrip(
	ctx context.Context, peerID peer.ID, message gossipMessage,
) (gossipMessage, error) {
	payload, err := json.Marshal(message)
	if err != nil {
		return gossipMessage{}, fmt.Errorf("encode web session gossip: %w", err)
	}
	if len(payload) > p2p.MaxEnvelopePayloadLength {
		return gossipMessage{}, fmt.Errorf("web session gossip payload too large: %d", len(payload))
	}
	stream, err := gossiper.node.Host.NewStream(ctx, peerID, p2p.WebSessionProtocol)
	if err != nil {
		return gossipMessage{}, fmt.Errorf("open web session stream: %w", err)
	}
	defer stream.Close()
	if err := p2p.EncodeEnvelope(stream, p2p.WebSessionProtocol, payload); err != nil {
		return gossipMessage{}, fmt.Errorf("write web session gossip: %w", err)
	}
	envelope, err := p2p.DecodeEnvelope(stream)
	if err != nil {
		return gossipMessage{}, fmt.Errorf("read web session gossip: %w", err)
	}
	if envelope.Protocol != p2p.WebSessionProtocol {
		return gossipMessage{}, fmt.Errorf("unexpected web session protocol %q", envelope.Protocol)
	}
	var response gossipMessage
	if err := json.Unmarshal(envelope.Payload, &response); err != nil {
		return gossipMessage{}, fmt.Errorf("decode web session gossip: %w", err)
	}
	if len(response.Sessions) > pageSize {
		return gossipMessage{}, fmt.Errorf("web session page too large: %d", len(response.Sessions))
	}
	if err := gossiper.store.MergeWebSessions(response.Sessions, time.Now()); err != nil {
		return gossipMessage{}, err
	}
	return response, nil
}

func (gossiper *Gossiper) handle(stream network.Stream) {
	defer stream.Close()
	if _, allowed := gossiper.peerSnapshot()[stream.Conn().RemotePeer()]; !allowed {
		return
	}
	envelope, err := p2p.DecodeEnvelope(stream)
	if err != nil {
		return
	}
	if envelope.Protocol != p2p.WebSessionProtocol {
		return
	}
	var message gossipMessage
	if err := json.Unmarshal(envelope.Payload, &message); err != nil {
		return
	}
	if message.Limit < 0 || message.Limit > pageSize {
		return
	}
	if err := gossiper.store.MergeWebSessions(message.Sessions, time.Now()); err != nil {
		return
	}
	limit := pageSize
	if message.Limit > 0 {
		limit = message.Limit
	}
	sessions, err := gossiper.store.WebSessionsAfter(message.Cursor, limit)
	if err != nil {
		return
	}
	payload, err := json.Marshal(gossipMessage{Sessions: sessions, Cursor: message.Cursor, Limit: limit})
	if err != nil || len(payload) > p2p.MaxEnvelopePayloadLength {
		return
	}
	_ = p2p.EncodeEnvelope(stream, p2p.WebSessionProtocol, payload)
}
