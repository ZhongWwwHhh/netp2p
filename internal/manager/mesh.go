package manager

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log"
	"sync"
	"time"

	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/multiformats/go-multiaddr"
	"github.com/netp2p/netp2p/internal/bft"
	"github.com/netp2p/netp2p/internal/model"
	"github.com/netp2p/netp2p/internal/p2p"
	"github.com/netp2p/netp2p/internal/tracing"
	"github.com/netp2p/netp2p/internal/wire"
	"github.com/netp2p/netp2p/internal/wire/pb"
	"go.opentelemetry.io/otel"
	"google.golang.org/protobuf/proto"
)

type CommitteeMesh struct {
	node            *p2p.Node
	engine          *bft.Engine
	members         []model.CommitteeMember
	peers           map[string]peer.ID
	mu              sync.Mutex
	submitMu        sync.Mutex
	probeMu         sync.Mutex
	subscribers     map[chan model.SignedSnapshot]struct{}
	probeGeneration uint64
	probeResponses  map[peer.ID]committeeProbe
}

type committeeProbe struct {
	generation uint64
	response   chan struct{}
}

const committeeProbeTimeout = 500 * time.Millisecond

var ErrCommitteeUnavailable = errors.New("committee unavailable")

func NewCommitteeMesh(node *p2p.Node, engine *bft.Engine, members []model.CommitteeMember) (*CommitteeMesh, error) {
	peers := make(map[string]peer.ID)
	localID := node.Host.ID().String()
	for _, member := range members {
		if member.PeerID == "" || member.PeerID == localID {
			continue
		}
		peerID, err := peer.Decode(member.PeerID)
		if err != nil {
			return nil, fmt.Errorf("invalid committee peer id: %w", err)
		}
		peers[member.ID] = peerID
	}
	mesh := &CommitteeMesh{
		node: node, engine: engine, members: members, peers: peers,
		subscribers:    make(map[chan model.SignedSnapshot]struct{}),
		probeResponses: make(map[peer.ID]committeeProbe),
	}
	node.Handle(p2p.StateUpdateProtocol, mesh.handleStateUpdate)
	engine.OnCommit(mesh.onCommit)
	return mesh, nil
}

// onCommit fans a committed snapshot out to subscribers and, when the
// transition changed the committee, reconciles the mesh membership so new
// members are dialled and removed members stop receiving traffic.
func (mesh *CommitteeMesh) onCommit(snapshot model.SignedSnapshot) {
	mesh.publish(snapshot)
	mesh.syncMembers()
}

// peerSnapshot returns a stable copy of the current member peer map.
func (mesh *CommitteeMesh) peerSnapshot() map[string]peer.ID {
	mesh.mu.Lock()
	defer mesh.mu.Unlock()
	result := make(map[string]peer.ID, len(mesh.peers))
	for memberID, peerID := range mesh.peers {
		result[memberID] = peerID
	}
	return result
}

// isCommitteePeer reports whether a remote libp2p identity belongs to the
// configured committee. State-update streams are authenticated by this allow
// list before any payload is decoded or applied.
func (mesh *CommitteeMesh) isCommitteePeer(remote peer.ID) bool {
	for _, peerID := range mesh.peerSnapshot() {
		if peerID == remote {
			return true
		}
	}
	return false
}

func (mesh *CommitteeMesh) memberIDForPeer(remote peer.ID) (string, bool) {
	mesh.mu.Lock()
	defer mesh.mu.Unlock()
	for memberID, peerID := range mesh.peers {
		if peerID == remote {
			return memberID, true
		}
	}
	return "", false
}

// ensureCommitteeAvailable proves that enough remote members answer an
// application-level handshake to combine their votes with this manager's vote.
// Transport connectedness is not sufficient: a partitioned peer can remain
// connected while every state-update message is dropped.
func (mesh *CommitteeMesh) ensureCommitteeAvailable() error {
	mesh.probeMu.Lock()
	defer mesh.probeMu.Unlock()

	peers := mesh.peerSnapshot()
	params := mesh.engine.CommitteeParams()
	required := params.QuorumSize - 1
	if required > len(peers) {
		required = len(peers)
	}
	if required <= 0 {
		return nil
	}

	mesh.mu.Lock()
	mesh.probeGeneration++
	generation := mesh.probeGeneration
	response := make(chan struct{}, len(peers))
	for _, peerID := range peers {
		mesh.probeResponses[peerID] = committeeProbe{generation: generation, response: response}
	}
	mesh.mu.Unlock()
	defer func() {
		mesh.mu.Lock()
		for _, peerID := range peers {
			if current := mesh.probeResponses[peerID]; current.response == response {
				delete(mesh.probeResponses, peerID)
			}
		}
		mesh.mu.Unlock()
	}()

	for _, peerID := range peers {
		go func(peerID peer.ID) {
			ctx, cancel := context.WithTimeout(context.Background(), committeeProbeTimeout)
			defer cancel()
			_ = mesh.node.Send(ctx, peerID, p2p.StateUpdateProtocol, wire.CommitteeEnvelopeToProto(
				model.CommitteeEnvelope{Type: "ready", Height: generation},
			))
		}(peerID)
	}

	timer := time.NewTimer(committeeProbeTimeout)
	defer timer.Stop()
	answered := 0
	for answered < required {
		select {
		case <-response:
			answered++
		case <-timer.C:
			return fmt.Errorf("%w: %d of %d remote committee members answered", ErrCommitteeUnavailable, answered, len(peers))
		}
	}
	return nil
}

func (mesh *CommitteeMesh) markProbeResponse(remote peer.ID, generation uint64) {
	mesh.mu.Lock()
	probe, ok := mesh.probeResponses[remote]
	mesh.mu.Unlock()
	if !ok || probe.generation != generation {
		return
	}
	select {
	case probe.response <- struct{}{}:
	default:
	}
}

// syncMembers rebuilds the member list from the engine's current committee and
// dials any member that was not part of the previous committee.
func (mesh *CommitteeMesh) syncMembers() {
	members := mesh.engine.CommitteeMembers()
	localID := mesh.node.Host.ID().String()
	peers := make(map[string]peer.ID)
	for _, member := range members {
		if member.PeerID == "" || member.PeerID == localID {
			continue
		}
		peerID, err := peer.Decode(member.PeerID)
		if err != nil {
			continue
		}
		peers[member.ID] = peerID
	}
	mesh.mu.Lock()
	previous := mesh.peers
	mesh.members = members
	mesh.peers = peers
	mesh.mu.Unlock()
	for memberID, peerID := range peers {
		if _, known := previous[memberID]; known {
			continue
		}
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		info := mesh.connectInfo(memberID, peerID)
		if err := mesh.node.Host.Connect(ctx, info); err != nil {
			log.Printf("committee member %s did not accept a connection: %v", memberID, err)
		}
		cancel()
	}
}

// PeerIDs returns the libp2p identities of the other committee members.
func (mesh *CommitteeMesh) PeerIDs() []peer.ID {
	mesh.mu.Lock()
	defer mesh.mu.Unlock()
	result := make([]peer.ID, 0, len(mesh.peers))
	for _, peerID := range mesh.peers {
		result = append(result, peerID)
	}
	return result
}

func (mesh *CommitteeMesh) connectInfo(memberID string, peerID peer.ID) peer.AddrInfo {
	mesh.mu.Lock()
	defer mesh.mu.Unlock()
	for _, member := range mesh.members {
		if member.ID != memberID {
			continue
		}
		transport, err := multiaddr.NewMultiaddr(member.Address)
		if err != nil {
			break
		}
		return peer.AddrInfo{ID: peerID, Addrs: []multiaddr.Multiaddr{transport}}
	}
	return peer.AddrInfo{ID: peerID}
}

// Connect dials every committee peer, retrying until ctx expires. Retrying is
// required for cold start because managers come up in unspecified order.
func (mesh *CommitteeMesh) Connect(ctx context.Context) error {
	peers := mesh.peerSnapshot()
	var waitGroup sync.WaitGroup
	errors := make(chan error, len(peers))
	for memberID, peerID := range peers {
		waitGroup.Add(1)
		go func(memberID string, peerID peer.ID) {
			defer waitGroup.Done()
			info := mesh.connectInfo(memberID, peerID)
			for {
				if err := mesh.node.Host.Connect(ctx, info); err == nil {
					return
				}
				select {
				case <-ctx.Done():
					errors <- fmt.Errorf("connect committee member %s: %w", memberID, ctx.Err())
					return
				case <-time.After(300 * time.Millisecond):
				}
			}
		}(memberID, peerID)
	}
	waitGroup.Wait()
	close(errors)
	for err := range errors {
		if err != nil {
			return err
		}
	}
	return nil
}

func (mesh *CommitteeMesh) handleStateUpdate(stream network.Stream) {
	defer stream.Close()
	remote := stream.Conn().RemotePeer()
	if _, ok := mesh.memberIDForPeer(remote); !ok {
		return
	}
	envelope, err := p2p.DecodeEnvelope(stream)
	if err != nil {
		return
	}
	var wireMessage pb.CommitteeEnvelope
	if err := proto.Unmarshal(envelope.Payload, &wireMessage); err != nil {
		return
	}
	message := wire.CommitteeEnvelopeFromProto(&wireMessage)
	switch message.Type {
	case "proposal":
		if message.Proposal == nil {
			return
		}
		senderID, ok := mesh.memberIDForPeer(remote)
		if !ok || senderID != message.Proposal.LeaderID {
			return
		}
		if err := mesh.ensureCommitteeAvailable(); err != nil {
			return
		}
		vote, err := mesh.engine.ProcessProposal(*message.Proposal)
		if err == nil {
			_ = mesh.send(stream.Conn().RemotePeer(), model.CommitteeEnvelope{Type: "vote", Vote: &vote})
		}
	case "vote":
		if message.Vote == nil {
			return
		}
		senderID, ok := mesh.memberIDForPeer(remote)
		if !ok || senderID != message.Vote.VoterID {
			return
		}
		if err := mesh.ensureCommitteeAvailable(); err != nil {
			return
		}
		qc, ready, err := mesh.engine.ProcessVote(*message.Vote)
		if err != nil || !ready {
			return
		}
		proposal, ok := mesh.engine.CurrentProposal()
		if !ok {
			return
		}
		if proposal.Height != qc.Height || proposal.Round != qc.Round {
			return
		}
		snapshot, err := mesh.engine.Commit(proposal, qc)
		if err != nil {
			return
		}
		mesh.broadcast(model.CommitteeEnvelope{Type: "snapshot", Snapshot: &snapshot})
	case "snapshot", "sync_response":
		if message.Snapshot == nil {
			return
		}
		mesh.adoptSnapshot(*message.Snapshot)
	case "forward":
		if message.Transition == nil {
			return
		}
		if err := mesh.ensureCommitteeAvailable(); err != nil {
			return
		}
		mesh.proposeLocal(*message.Transition, message.Round)
	case "sync_request":
		// The requester asks for one specific height at a time, which keeps the
		// engine's single-step CatchUp valid. A gap is bridged by repeating the
		// request, not by returning a snapshot the engine cannot adopt.
		snapshot, ok := mesh.engine.Snapshot(message.Height)
		if !ok {
			return
		}
		_ = mesh.send(stream.Conn().RemotePeer(), model.CommitteeEnvelope{Type: "sync_response", Snapshot: &snapshot})
	case "ready":
		_ = mesh.send(remote, model.CommitteeEnvelope{Type: "ready_ack", Height: message.Height})
	case "ready_ack":
		mesh.markProbeResponse(remote, message.Height)
	}
}

// WaitReady blocks until every committee peer accepts a state-update stream.
// Connect only proves the transport is dialable; WaitReady proves the remote
// engine and stream handler are installed, which genesis requires before it can
// collect a quorum.
func (mesh *CommitteeMesh) WaitReady(ctx context.Context) error {
	peers := mesh.peerSnapshot()
	var waitGroup sync.WaitGroup
	errors := make(chan error, len(peers))
	for memberID, peerID := range peers {
		waitGroup.Add(1)
		go func(memberID string, peerID peer.ID) {
			defer waitGroup.Done()
			for {
				stream, err := mesh.node.Host.NewStream(ctx, peerID, p2p.StateUpdateProtocol)
				if err == nil {
					_ = stream.Close()
					return
				}
				select {
				case <-ctx.Done():
					errors <- fmt.Errorf("committee member %s not ready: %w", memberID, ctx.Err())
					return
				case <-time.After(200 * time.Millisecond):
				}
			}
		}(memberID, peerID)
	}
	waitGroup.Wait()
	close(errors)
	for err := range errors {
		if err != nil {
			return err
		}
	}
	return nil
}

// adoptSnapshot validates and commits a certified snapshot. If the local
// engine has the matching proposal (the normal live path), it uses Commit; if
// the manager is lagging or restarting, it uses CatchUp to bridge the gap.
func (mesh *CommitteeMesh) adoptSnapshot(snapshot model.SignedSnapshot) error {
	if err := bft.ValidateSnapshot(snapshot); err != nil {
		return err
	}
	if snapshot.Height <= mesh.engine.Height() {
		return fmt.Errorf("stale snapshot at height %d", snapshot.Height)
	}
	proposal, ok := mesh.engine.CurrentProposal()
	if !ok || proposal.Height != snapshot.Height || proposal.Round != snapshot.QC.Round {
		return mesh.engine.CatchUp(snapshot)
	}
	_, err := mesh.engine.Commit(proposal, snapshot.QC)
	return err
}

func (mesh *CommitteeMesh) proposeLocal(transition model.StateTransition, round uint64) {
	height := mesh.engine.Height() + 1
	if existing, exists := mesh.engine.CurrentProposal(); exists && existing.Height == height {
		if existing.Round == round {
			log.Printf("committee already has a proposal at height %d round %d, skipping", height, round)
			return
		}
		if existing.Round > round {
			log.Printf("committee proposal at height %d round %d is newer than round %d, skipping", height, existing.Round, round)
			return
		}
		log.Printf("committee replacing stale proposal at height %d round %d with round %d", height, existing.Round, round)
	} else if exists {
		log.Printf("committee discarding stale proposal at height %d round %d for height %d round %d", existing.Height, existing.Round, height, round)
	}
	// Propose records the leader's own vote internally, so a quorum is reached
	// when the outstanding peer votes arrive. Calling ProcessVote on the local
	// vote here would race with the vote handler that commits the height and
	// deletes the proposal.
	proposal, _, err := mesh.engine.Propose(transition, round)
	if err != nil {
		log.Printf("committee propose failed at height %d round %d: %v", height, round, err)
		return
	}
	mesh.broadcast(model.CommitteeEnvelope{Type: "proposal", Proposal: &proposal})
}

// CatchUp advances a lagging or restarting manager to the certified height by
// requesting one height at a time from every committee peer. The engine only
// adopts snapshots that close a single-height gap, so the loop stops as soon as
// a round produces no progress — that is the top of the chain.
func (mesh *CommitteeMesh) CatchUp(ctx context.Context) error {
	start := mesh.engine.Height()
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		next := mesh.engine.Height() + 1
		for _, peerID := range mesh.peerSnapshot() {
			if err := mesh.send(peerID, model.CommitteeEnvelope{Type: "sync_request", Height: next}); err != nil {
				continue
			}
		}
		// Give the responses time to arrive and be adopted before deciding
		// whether to request the next height. handleStateUpdate persists until
		// it finishes the exchange, so a stalled height means we are caught up.
		progress := false
		waitUntil := time.Now().Add(time.Second)
		for time.Now().Before(waitUntil) {
			if mesh.engine.Height() >= next {
				progress = true
				break
			}
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(20 * time.Millisecond):
			}
		}
		if !progress {
			break
		}
	}
	if mesh.engine.Height() > start {
		return nil
	}
	return fmt.Errorf("catch-up did not advance from height %d", start)
}

// Submit certifies a transition even when the receiving manager is not the
// current leader: the transition is forwarded to the leader and the caller
// waits for the committed snapshot.
func (mesh *CommitteeMesh) Submit(transition model.StateTransition) (model.SignedSnapshot, error) {
	if tracing.Enabled() {
		_, span := otel.Tracer("netp2p").Start(context.Background(), "bft.submit")
		defer span.End()
	}
	// Serialize submissions so concurrent client registrations cannot propose
	// conflicting transitions at the same height.
	mesh.submitMu.Lock()
	defer mesh.submitMu.Unlock()

	// ApplyTransition is deterministic, so a transition that cannot apply is
	// rejected before proposing rather than burning every committee round and
	// surfacing as a generic consensus timeout. Admin and console callers then
	// get the real reason, such as an unknown group reference.
	probe := mesh.engine.CurrentState()
	probe.EngineCommittee = mesh.engine.CommitteeMembers()
	if err := bft.ApplyTransition(&probe, transition); err != nil {
		return model.SignedSnapshot{}, err
	}

	subscriber := make(chan model.SignedSnapshot, 16)
	mesh.mu.Lock()
	mesh.subscribers[subscriber] = struct{}{}
	mesh.mu.Unlock()
	defer func() {
		mesh.mu.Lock()
		delete(mesh.subscribers, subscriber)
		mesh.mu.Unlock()
	}()

	startHeight := mesh.engine.Height()
	transitionHash := bft.TransitionHash(transition)
	totalTimeout := time.After(30 * time.Second)
	params := mesh.engine.CommitteeParams()
	if err := mesh.ensureCommitteeAvailable(); err != nil {
		return model.SignedSnapshot{}, err
	}
	for round := uint64(0); round < uint64(params.Size); round++ {
		height := mesh.engine.Height() + 1
		leader := mesh.engine.Leader(height, round)
		if leader.ID == mesh.engine.LocalID() {
			mesh.proposeLocal(transition, round)
		} else {
			leaderPeer, ok := mesh.peerSnapshot()[leader.ID]
			if !ok {
				continue
			}
			round := round
			if err := mesh.send(leaderPeer, model.CommitteeEnvelope{Type: "forward", Transition: &transition, Round: round}); err != nil {
				continue
			}
		}
		// Followers start their deadline when a proposal arrives. Leave a
		// margin over the engine timeout so the next-round proposal cannot win
		// a race against the last follower's local deadline.
		roundDeadline := time.After(mesh.engine.RoundTimeout() + time.Second)
		rotating := true
		for rotating {
			select {
			case snapshot := <-subscriber:
				if snapshot.Height > startHeight && bytes.Equal(bft.TransitionHash(snapshot.Transition), transitionHash) {
					return snapshot, nil
				}
			case <-roundDeadline:
				rotating = false
			case <-totalTimeout:
				return model.SignedSnapshot{}, fmt.Errorf("timed out waiting for BFT quorum after height %d", startHeight)
			}
		}
	}
	return model.SignedSnapshot{}, fmt.Errorf("all committee rounds exhausted after height %d", startHeight)
}

func (mesh *CommitteeMesh) publish(snapshot model.SignedSnapshot) {
	mesh.mu.Lock()
	subscribers := make([]chan model.SignedSnapshot, 0, len(mesh.subscribers))
	for subscriber := range mesh.subscribers {
		subscribers = append(subscribers, subscriber)
	}
	mesh.mu.Unlock()
	for _, subscriber := range subscribers {
		select {
		case subscriber <- snapshot:
		default:
		}
	}
}

func (mesh *CommitteeMesh) broadcast(message model.CommitteeEnvelope) {
	peers := mesh.peerSnapshot()
	var waitGroup sync.WaitGroup
	for _, peerID := range peers {
		waitGroup.Add(1)
		go func(peerID peer.ID) {
			defer waitGroup.Done()
			if err := mesh.send(peerID, message); err != nil {
				log.Printf("committee send failed: %v", err)
			}
		}(peerID)
	}
	waitGroup.Wait()
}

func (mesh *CommitteeMesh) send(peerID peer.ID, message model.CommitteeEnvelope) error {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	return mesh.node.Send(ctx, peerID, p2p.StateUpdateProtocol, wire.CommitteeEnvelopeToProto(message))
}
