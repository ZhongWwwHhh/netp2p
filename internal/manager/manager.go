// Package manager exposes certified state over libp2p control streams.
package manager

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"github.com/libp2p/go-libp2p/core/network"
	"github.com/netp2p/netp2p/internal/bft"
	"github.com/netp2p/netp2p/internal/model"
	"github.com/netp2p/netp2p/internal/p2p"
	"github.com/netp2p/netp2p/internal/protocol"
)

type Manager struct {
	node     *p2p.Node
	engine   *bft.Engine
	mesh     *CommitteeMesh
	mu       sync.RWMutex
	snapshot model.SignedSnapshot
	waiters  map[chan model.SignedSnapshot]struct{}
}

func New(node *p2p.Node, engine *bft.Engine, mesh *CommitteeMesh) *Manager {
	manager := &Manager{node: node, engine: engine, mesh: mesh, waiters: make(map[chan model.SignedSnapshot]struct{})}
	node.Handle(p2p.LoginProtocol, manager.handleLogin)
	node.Handle(p2p.SyncProtocol, manager.handleSync)
	engine.OnCommit(manager.onCommit)
	return manager
}

func (manager *Manager) LatestSnapshot() (model.SignedSnapshot, bool) {
	if snapshot := manager.Snapshot(); snapshot.Height > 0 {
		return snapshot, true
	}
	return manager.engine.LatestSnapshot()
}

func (manager *Manager) Committee() []model.CommitteeMember {
	return manager.engine.CommitteeMembers()
}

func (manager *Manager) Height() uint64 {
	return manager.engine.Height()
}

func (manager *Manager) LocalID() string {
	return manager.engine.LocalID()
}

func (manager *Manager) Leader(height, round uint64) model.CommitteeMember {
	return manager.engine.Leader(height, round)
}

func (manager *Manager) NetworkID() string {
	return manager.engine.CurrentState().NetworkID
}

func (manager *Manager) Submit(transition model.StateTransition) (model.SignedSnapshot, error) {
	return manager.mesh.Submit(transition)
}

func (manager *Manager) handleLogin(stream network.Stream) {
	defer stream.Close()
	envelope, err := p2p.DecodeEnvelope(stream)
	if err != nil {
		manager.respond(stream, protocol.LoginResponse{Error: "invalid envelope"})
		return
	}
	var request protocol.LoginRequest
	if err := json.Unmarshal(envelope.Payload, &request); err != nil {
		manager.respond(stream, protocol.LoginResponse{Error: "invalid request"})
		return
	}
	if request.PeerID != stream.Conn().RemotePeer().String() {
		manager.respond(stream, protocol.LoginResponse{Error: "peer id mismatch"})
		return
	}
	snapshot, peerRecord, err := manager.Register(request.SetupKey, request.PeerID, request.Addresses)
	if err != nil {
		manager.respond(stream, protocol.LoginResponse{Error: err.Error()})
		return
	}
	manager.respond(stream, protocol.LoginResponse{Snapshot: snapshot, Peer: peerRecord})
}

func (manager *Manager) handleSync(stream network.Stream) {
	defer stream.Close()
	envelope, err := p2p.DecodeEnvelope(stream)
	if err != nil {
		return
	}
	var request protocol.SyncRequest
	if err := json.Unmarshal(envelope.Payload, &request); err != nil {
		return
	}
	if request.PeerID != stream.Conn().RemotePeer().String() {
		return
	}
	snapshot := manager.Snapshot()
	if snapshot.Height > request.Height {
		writeJSON(stream, snapshot)
		return
	}
	waiter := make(chan model.SignedSnapshot, 1)
	manager.mu.Lock()
	manager.waiters[waiter] = struct{}{}
	manager.mu.Unlock()
	defer func() {
		manager.mu.Lock()
		delete(manager.waiters, waiter)
		manager.mu.Unlock()
	}()
	waitContext, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	select {
	case snapshot := <-waiter:
		writeJSON(stream, snapshot)
	case <-waitContext.Done():
	}
}

func (manager *Manager) Register(setupKey, peerID string, addresses []string) (model.SignedSnapshot, model.PeerRecord, error) {
	transition := model.StateTransition{
		Type:     bft.TransitionRegisterPeer,
		SetupKey: setupKey,
		Peer:     model.PeerRecord{PeerID: peerID, Addresses: addresses},
	}
	snapshot, err := manager.mesh.Submit(transition)
	if err != nil {
		return model.SignedSnapshot{}, model.PeerRecord{}, err
	}
	for _, peer := range snapshot.State.Peers {
		if peer.PeerID == peerID {
			return snapshot, peer, nil
		}
	}
	return model.SignedSnapshot{}, model.PeerRecord{}, fmt.Errorf("peer %s missing from certified state", peerID)
}

func (manager *Manager) onCommit(snapshot model.SignedSnapshot) {
	manager.mu.Lock()
	manager.snapshot = snapshot
	waiters := make([]chan model.SignedSnapshot, 0, len(manager.waiters))
	for waiter := range manager.waiters {
		waiters = append(waiters, waiter)
	}
	manager.waiters = make(map[chan model.SignedSnapshot]struct{})
	manager.mu.Unlock()
	for _, waiter := range waiters {
		waiter <- snapshot
	}
}

func (manager *Manager) Snapshot() model.SignedSnapshot {
	manager.mu.RLock()
	defer manager.mu.RUnlock()
	return manager.snapshot
}

func (manager *Manager) respond(stream network.Stream, response protocol.LoginResponse) {
	writeJSON(stream, response)
}

func writeJSON(stream network.Stream, value any) {
	if err := json.NewEncoder(stream).Encode(value); err != nil {
		stream.Reset()
	}
}
