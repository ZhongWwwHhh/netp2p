// Package manager exposes certified state over libp2p control streams.
package manager

import (
	"context"
	"fmt"
	"log"
	"sync"
	"time"

	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/core/peerstore"
	libprotocol "github.com/libp2p/go-libp2p/core/protocol"
	"github.com/multiformats/go-multiaddr"
	"github.com/netp2p/netp2p/internal/bft"
	"github.com/netp2p/netp2p/internal/forward"
	"github.com/netp2p/netp2p/internal/link"
	"github.com/netp2p/netp2p/internal/model"
	"github.com/netp2p/netp2p/internal/oidc"
	"github.com/netp2p/netp2p/internal/p2p"
	"github.com/netp2p/netp2p/internal/presence"
	"github.com/netp2p/netp2p/internal/protocol"
	"github.com/netp2p/netp2p/internal/transport"
	"github.com/netp2p/netp2p/internal/version"
	"github.com/netp2p/netp2p/internal/wire"
	"github.com/netp2p/netp2p/internal/wire/pb"
	"google.golang.org/protobuf/proto"
)

type Manager struct {
	node          *p2p.Node
	engine        *bft.Engine
	mesh          *CommitteeMesh
	presence      *presence.Table
	gossiper      *presence.Gossiper
	links         *link.Gossiper
	prober        *link.Prober
	forwarding    *forward.Table
	dataTransport *transport.Transport
	admissions    map[string]map[string]protocol.AdmissionReport
	sso           *oidc.Verifier
	mu            sync.RWMutex
	snapshot      model.SignedSnapshot
	waiters       map[chan model.SignedSnapshot]struct{}
}

// Config wires optional capabilities into the manager.
type Config struct {
	// SSO, when set, verifies ID tokens for peer and console logins.
	SSO        *oidc.Verifier
	Links      *link.Gossiper
	Forwarding bool
}

func New(node *p2p.Node, engine *bft.Engine, mesh *CommitteeMesh, config Config) *Manager {
	table := presence.NewTable()
	manager := &Manager{
		node: node, engine: engine, mesh: mesh, presence: table, sso: config.SSO, links: config.Links,
		gossiper:   presence.NewGossiper(node, table, engine.LocalID(), mesh.PeerIDs()),
		admissions: make(map[string]map[string]protocol.AdmissionReport),
		waiters:    make(map[chan model.SignedSnapshot]struct{}),
	}
	if config.Forwarding {
		// The forwarding table keys hops by libp2p PeerID, so the local
		// identity must be the host peer ID rather than the committee label.
		manager.forwarding = forward.NewTable(engine.CurrentState(), node.Host.ID().String(), func(remote peer.ID, envelope forward.Envelope) error {
			wire, err := forward.EncodeEnvelope(envelope)
			if err != nil {
				return err
			}
			if manager.dataTransport == nil {
				return fmt.Errorf("frame transport not started")
			}
			return manager.dataTransport.Send(remote, wire)
		})
	}
	if config.Links != nil {
		manager.prober = link.NewProber(node, engine.CurrentState, engine.CommitteeMembers, config.Links)
	}
	node.Handle(p2p.ProbeProtocol, link.NewProbeResponder().Handle)
	node.Handle(p2p.LoginProtocol, manager.handleLogin)
	node.Handle(p2p.SyncProtocol, manager.handleSync)
	engine.OnCommit(manager.onCommit)
	return manager
}

// RunLinkProbe measures the manager mesh and its client access links until ctx
// is cancelled. Measurements are non-certified observations; only the planner
// output is certified.
func (manager *Manager) RunLinkProbe(ctx context.Context) {
	if manager.prober == nil {
		return
	}
	manager.prober.Run(ctx)
}

// EnableForwarding installs the persistent binary frame listener used for
// certified via-manager paths.
func (manager *Manager) EnableForwarding(ctx context.Context) {
	if manager.forwarding == nil {
		return
	}
	manager.dataTransport = transport.NewWithEnvelope(ctx, manager.node.Host, p2p.FrameProtocol, nil, manager.handleForwardedWire)
	manager.forwarding.Replace(manager.engine.CurrentState())
}

func (manager *Manager) handleForwardedWire(remote peer.ID, wire []byte) {
	if manager.forwarding == nil {
		return
	}
	envelope, err := forward.DecodeEnvelope(wire)
	if err != nil {
		return
	}
	if _, err := manager.forwarding.Accept(remote, envelope); err != nil {
		log.Printf("forward frame: %v", err)
	}
}

// RunScheduler periodically converts manager mesh observations into certified
// route assignments. Transitions remain quorum-certified.
func (manager *Manager) RunScheduler(ctx context.Context) {
	scheduler := link.NewScheduler(manager.mesh, manager.engine.CommitteeMembers(), manager.LinkView)
	scheduler.Run(ctx, manager.engine.CurrentState)
}

// ReconcileAssignments runs a single planner pass now and submits at most one
// changed assignment. It is exposed for tests and admin tooling that need to
// drive the planner deterministically instead of waiting for the ticker.
func (manager *Manager) ReconcileAssignments() error {
	scheduler := link.NewScheduler(manager.mesh, manager.engine.CommitteeMembers(), manager.LinkView)
	scheduler.SetCooldown(0)
	return scheduler.Reconcile(manager.engine.CurrentState())
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

// LinkView returns the non-certified manager mesh observation snapshot.
func (manager *Manager) LinkView() link.LinkView {
	if manager.links == nil {
		return link.LinkView{}
	}
	return manager.links.View()
}

// Admissions returns non-certified client observations, newest per path. They
// can influence the planner but cannot alter certified state by themselves.
func (manager *Manager) Admissions() map[string]map[string]protocol.AdmissionReport {
	manager.mu.RLock()
	defer manager.mu.RUnlock()
	result := make(map[string]map[string]protocol.AdmissionReport, len(manager.admissions))
	for peerID, paths := range manager.admissions {
		result[peerID] = make(map[string]protocol.AdmissionReport, len(paths))
		for pathID, report := range paths {
			result[peerID][pathID] = report
		}
	}
	return result
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

// Users returns the certified user records.
func (manager *Manager) Users() []model.User {
	return manager.engine.CurrentState().Users
}

func (manager *Manager) Height() uint64 {
	return manager.engine.Height()
}

func (manager *Manager) LocalID() string {
	return manager.engine.LocalID()
}

// ForwardingStats reports how many frames this manager forwarded onward and
// how many it dropped. It is a diagnostic for tests and operators.
func (manager *Manager) ForwardingStats() (forwarded, dropped uint64) {
	if manager.forwarding == nil {
		return 0, 0
	}
	return manager.forwarding.Stats()
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
		manager.respond(stream, p2p.LoginProtocol, protocol.LoginResponse{Error: "invalid envelope"})
		return
	}
	var loginMessage pb.LoginRequest
	if err := proto.Unmarshal(envelope.Payload, &loginMessage); err != nil {
		manager.respond(stream, p2p.LoginProtocol, protocol.LoginResponse{Error: "invalid request"})
		return
	}
	request := wire.LoginRequestFromProto(&loginMessage)
	if request.ProtocolVersion != version.ProtocolVersion {
		manager.respond(stream, p2p.LoginProtocol, protocol.LoginResponse{
			Error:           fmt.Sprintf("protocol version mismatch: manager %s, client %s", version.ProtocolVersion, request.ProtocolVersion),
			Code:            protocol.CodeProtocolMismatch,
			ProtocolVersion: version.ProtocolVersion,
		})
		return
	}
	if request.PeerID != stream.Conn().RemotePeer().String() {
		manager.respond(stream, p2p.LoginProtocol, protocol.LoginResponse{Error: "peer id mismatch"})
		return
	}
	// Remember how to reach the client so the link prober can dial it back and
	// measure the access segment even when the client is idle.
	manager.rememberAddrs(request.PeerID, request.Addresses)
	manager.presence.Observe(request.PeerID, stream.Conn().RemoteMultiaddr().String(), manager.engine.LocalID())
	registration, code, message := manager.authenticate(request)
	if message != "" {
		manager.respond(stream, p2p.LoginProtocol, protocol.LoginResponse{Error: message, Code: code, ProtocolVersion: version.ProtocolVersion})
		return
	}
	snapshot, peerRecord, err := manager.Register(registration)
	if err != nil {
		manager.respond(stream, p2p.LoginProtocol, protocol.LoginResponse{Error: err.Error(), Code: protocol.CodeRegistrationRequired, ProtocolVersion: version.ProtocolVersion})
		return
	}
	manager.respond(stream, p2p.LoginProtocol, protocol.LoginResponse{Snapshot: snapshot, Peer: peerRecord, ProtocolVersion: version.ProtocolVersion, Capabilities: version.Capabilities()})
}

func (manager *Manager) rememberAddrs(peerID string, addresses []string) {
	target, err := peer.Decode(peerID)
	if err != nil {
		return
	}
	parsed := make([]multiaddr.Multiaddr, 0, len(addresses))
	for _, value := range addresses {
		address, err := multiaddr.NewMultiaddr(value)
		if err != nil {
			continue
		}
		parsed = append(parsed, address)
	}
	if len(parsed) == 0 {
		return
	}
	manager.node.Host.Peerstore().AddAddrs(target, parsed, peerstore.PermanentAddrTTL)
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
	var syncMessage pb.SyncRequest
	if err := proto.Unmarshal(envelope.Payload, &syncMessage); err != nil {
		return
	}
	request := wire.SyncRequestFromProto(&syncMessage)
	if request.ProtocolVersion != version.ProtocolVersion {
		return
	}
	if request.PeerID != stream.Conn().RemotePeer().String() {
		return
	}
	manager.presence.Observe(request.PeerID, stream.Conn().RemoteMultiaddr().String(), manager.engine.LocalID())
	manager.observeAdmissions(request.PeerID, request.Admissions)
	snapshot := manager.Snapshot()
	if snapshot.Height > request.Height {
		writeSnapshot(stream, snapshot)
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
		writeSnapshot(stream, snapshot)
	case <-waitContext.Done():
	}
}

func (manager *Manager) observeAdmissions(peerID string, reports []protocol.AdmissionReport) {
	if len(reports) == 0 {
		return
	}
	state := manager.engine.CurrentState()
	for _, report := range reports {
		if !validAdmission(state, peerID, report) {
			continue
		}
		manager.mu.Lock()
		paths := manager.admissions[peerID]
		if paths == nil {
			paths = make(map[string]protocol.AdmissionReport)
			manager.admissions[peerID] = paths
		}
		if existing, ok := paths[report.PathID]; !ok || !report.ObservedAt.Before(existing.ObservedAt) {
			paths[report.PathID] = report
		}
		manager.mu.Unlock()
	}
}

func validAdmission(state model.NetworkState, peerID string, report protocol.AdmissionReport) bool {
	if report.AssignmentID == "" || report.PathID == "" || report.RTTMs < 0 || report.LossPct < 0 || report.LossPct > 100 {
		return false
	}
	for _, assignment := range state.Assignments {
		if assignment.ID != report.AssignmentID || assignment.SourcePeerID != peerID {
			continue
		}
		for _, path := range assignment.Paths() {
			if path.ID == report.PathID {
				return true
			}
		}
	}
	return false
}

// Registration is what a client presents when it logs in.
type Registration struct {
	SetupKey      string
	UserID        string
	LastLogin     string
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
		metadataChanged := peer.Hostname != registration.Hostname || peer.OS != registration.OS ||
			peer.ClientVersion != registration.ClientVersion || !sameAddresses(peer.Addresses, registration.Addresses)
		userChanged := registration.UserID != "" && peer.UserID != registration.UserID
		loginRefresh := registration.LastLogin != "" && shouldRefreshLogin(peer.LastLogin)
		if !metadataChanged && !userChanged && !loginRefresh {
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
				UserID: registration.UserID, LastLogin: registration.LastLogin,
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
			UserID: registration.UserID, LastLogin: registration.LastLogin,
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
	if manager.forwarding != nil {
		manager.forwarding.Replace(snapshot.State)
	}
}

func (manager *Manager) Snapshot() model.SignedSnapshot {
	manager.mu.RLock()
	defer manager.mu.RUnlock()
	return manager.snapshot
}

func (manager *Manager) respond(stream network.Stream, id libprotocol.ID, response protocol.LoginResponse) {
	if err := p2p.WriteMessage(stream, id, wire.LoginResponseToProto(response)); err != nil {
		stream.Reset()
	}
}

func writeSnapshot(stream network.Stream, snapshot model.SignedSnapshot) {
	if err := p2p.WriteMessage(stream, p2p.SyncProtocol, wire.SignedSnapshotToProto(snapshot)); err != nil {
		stream.Reset()
	}
}
