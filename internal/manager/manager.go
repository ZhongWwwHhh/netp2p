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
	"github.com/netp2p/netp2p/internal/presence"
	"github.com/netp2p/netp2p/internal/protocol"
)

type Manager struct {
	node     *p2p.Node
	engine   *bft.Engine
	mesh     *CommitteeMesh
	presence *presence.Table
	gossiper *presence.Gossiper
	mu       sync.RWMutex
	snapshot model.SignedSnapshot
	waiters  map[chan model.SignedSnapshot]struct{}
}

func New(node *p2p.Node, engine *bft.Engine, mesh *CommitteeMesh) *Manager {
	table := presence.NewTable()
	manager := &Manager{
		node: node, engine: engine, mesh: mesh, presence: table,
		gossiper: presence.NewGossiper(node, table, engine.LocalID(), mesh.PeerIDs()),
		waiters:  make(map[chan model.SignedSnapshot]struct{}),
	}
	node.Handle(p2p.LoginProtocol, manager.handleLogin)
	node.Handle(p2p.SyncProtocol, manager.handleSync)
	engine.OnCommit(manager.onCommit)
	return manager
}

// RunPresenceGossip exchanges observed peer presence with the other committee
// members until ctx is cancelled.
func (manager *Manager) RunPresenceGossip(ctx context.Context) {
	manager.gossiper.Run(ctx)
}

// Presence returns the merged, non-certified view of which peers are online.
func (manager *Manager) Presence() []presence.Observation {
	return manager.presence.Snapshot()
}

// Activity returns certified decision-log records, newest first.
func (manager *Manager) Activity(limit int, before uint64) []model.SignedSnapshot {
	return manager.engine.Activity(limit, before)
}

// SnapshotAt returns the certified snapshot committed at a given height.
func (manager *Manager) SnapshotAt(height uint64) (model.SignedSnapshot, bool) {
	return manager.engine.Snapshot(height)
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
	manager.presence.Observe(request.PeerID, stream.Conn().RemoteMultiaddr().String(), manager.engine.LocalID())
	snapshot, peerRecord, err := manager.Register(toRegistration(request))
	if err != nil {
		manager.respond(stream, protocol.LoginResponse{Error: err.Error()})
		return
	}
	manager.respond(stream, protocol.LoginResponse{Snapshot: snapshot, Peer: peerRecord})
}

func toRegistration(request protocol.LoginRequest) Registration {
	return Registration{
		SetupKey:      request.SetupKey,
		PeerID:        request.PeerID,
		Addresses:     request.Addresses,
		Hostname:      request.Hostname,
		OS:            request.OS,
		ClientVersion: request.ClientVersion,
	}
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
	manager.presence.Observe(request.PeerID, stream.Conn().RemoteMultiaddr().String(), manager.engine.LocalID())
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

// Registration is what a client presents when it logs in.
type Registration struct {
	SetupKey      string
	PeerID        string
	Addresses     []string
	Hostname      string
	OS            string
	ClientVersion string
}

// Register adds a peer to certified state, or refreshes its metadata when the
// peer already exists. Both paths go through consensus: a returning peer only
// produces a transition when something actually changed, so restarts do not
// grow the decision log.
func (manager *Manager) Register(registration Registration) (model.SignedSnapshot, model.PeerRecord, error) {
	for _, peer := range manager.engine.CurrentState().Peers {
		if peer.PeerID != registration.PeerID {
			continue
		}
		if peer.Hostname == registration.Hostname && peer.OS == registration.OS &&
			peer.ClientVersion == registration.ClientVersion && sameAddresses(peer.Addresses, registration.Addresses) {
			snapshot, ok := manager.LatestSnapshot()
			if !ok {
				return model.SignedSnapshot{}, model.PeerRecord{}, fmt.Errorf("no certified snapshot")
			}
			return snapshot, peer, nil
		}
		transition := model.StateTransition{
			Type: bft.TransitionUpdatePeer,
			Peer: model.PeerRecord{
				PeerID: registration.PeerID, Addresses: registration.Addresses,
				Hostname: registration.Hostname, OS: registration.OS, ClientVersion: registration.ClientVersion,
			},
		}
		snapshot, err := manager.mesh.Submit(transition)
		if err != nil {
			return model.SignedSnapshot{}, model.PeerRecord{}, err
		}
		return snapshot, findPeer(snapshot, registration.PeerID), nil
	}
	transition := model.StateTransition{
		Type:     bft.TransitionRegisterPeer,
		SetupKey: registration.SetupKey,
		Peer: model.PeerRecord{
			PeerID: registration.PeerID, Addresses: registration.Addresses,
			Hostname: registration.Hostname, OS: registration.OS, ClientVersion: registration.ClientVersion,
		},
	}
	snapshot, err := manager.mesh.Submit(transition)
	if err != nil {
		return model.SignedSnapshot{}, model.PeerRecord{}, err
	}
	peer := findPeer(snapshot, registration.PeerID)
	if peer.PeerID == "" {
		return model.SignedSnapshot{}, model.PeerRecord{}, fmt.Errorf("peer %s missing from certified state", registration.PeerID)
	}
	return snapshot, peer, nil
}

func findPeer(snapshot model.SignedSnapshot, peerID string) model.PeerRecord {
	for _, peer := range snapshot.State.Peers {
		if peer.PeerID == peerID {
			return peer
		}
	}
	return model.PeerRecord{}
}

func sameAddresses(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
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
