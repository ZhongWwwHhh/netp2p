package manager

import (
	"context"
	"encoding/json"
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
)

type CommitteeMesh struct {
	node        *p2p.Node
	engine      *bft.Engine
	members     []model.CommitteeMember
	peers       map[string]peer.ID
	mu          sync.Mutex
	submitMu    sync.Mutex
	subscribers map[chan model.SignedSnapshot]struct{}
}

type committeeEnvelope struct {
	Type       string                 `json:"type"`
	Proposal   *bft.Proposal          `json:"proposal,omitempty"`
	Vote       *bft.Vote              `json:"vote,omitempty"`
	Snapshot   *model.SignedSnapshot  `json:"snapshot,omitempty"`
	Transition *model.StateTransition `json:"transition,omitempty"`
	Height     *uint64                `json:"height,omitempty"`
	Round      *uint64                `json:"round,omitempty"`
}

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
		subscribers: make(map[chan model.SignedSnapshot]struct{}),
	}
	node.Handle(p2p.StateUpdateProtocol, mesh.handleStateUpdate)
	engine.OnCommit(mesh.publish)
	return mesh, nil
}

// PeerIDs returns the libp2p identities of the other committee members.
func (mesh *CommitteeMesh) PeerIDs() []peer.ID {
	result := make([]peer.ID, 0, len(mesh.peers))
	for _, peerID := range mesh.peers {
		result = append(result, peerID)
	}
	return result
}

func (mesh *CommitteeMesh) connectInfo(memberID string, peerID peer.ID) peer.AddrInfo {
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
	var waitGroup sync.WaitGroup
	errors := make(chan error, len(mesh.peers))
	for memberID, peerID := range mesh.peers {
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
	envelope, err := p2p.DecodeEnvelope(stream)
	if err != nil {
		return
	}
	var message committeeEnvelope
	if err := json.Unmarshal(envelope.Payload, &message); err != nil {
		return
	}
	switch message.Type {
	case "proposal":
		if message.Proposal == nil {
			return
		}
		vote, err := mesh.engine.ProcessProposal(*message.Proposal)
		if err == nil {
			_ = mesh.send(stream.Conn().RemotePeer(), committeeEnvelope{Type: "vote", Vote: &vote})
		}
	case "vote":
		if message.Vote == nil {
			return
		}
		qc, ready, err := mesh.engine.ProcessVote(*message.Vote)
		if err != nil || !ready {
			return
		}
		proposal, ok := mesh.engine.Proposal(qc.Height)
		if !ok {
			return
		}
		snapshot, err := mesh.engine.Commit(proposal, qc)
		if err != nil {
			return
		}
		mesh.broadcast(committeeEnvelope{Type: "snapshot", Snapshot: &snapshot})
	case "snapshot", "sync_response":
		if message.Snapshot == nil {
			return
		}
		mesh.adoptSnapshot(*message.Snapshot)
	case "forward":
		if message.Transition == nil {
			return
		}
		round := uint64(0)
		if message.Round != nil {
			round = *message.Round
		}
		mesh.proposeLocal(*message.Transition, round)
	case "sync_request":
		if message.Height == nil {
			return
		}
		snapshot, ok := mesh.engine.Snapshot(*message.Height)
		if !ok {
			snapshot, ok = mesh.engine.LatestSnapshot()
		}
		if ok {
			_ = mesh.send(stream.Conn().RemotePeer(), committeeEnvelope{Type: "sync_response", Snapshot: &snapshot})
		}
	}
}

// WaitReady blocks until every committee peer accepts a state-update stream.
// Connect only proves the transport is dialable; WaitReady proves the remote
// engine and stream handler are installed, which genesis requires before it can
// collect a quorum.
func (mesh *CommitteeMesh) WaitReady(ctx context.Context) error {
	var waitGroup sync.WaitGroup
	errors := make(chan error, len(mesh.peers))
	for memberID, peerID := range mesh.peers {
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
	proposal, ok := mesh.engine.Proposal(snapshot.Height)
	if !ok {
		return mesh.engine.CatchUp(snapshot)
	}
	_, err := mesh.engine.Commit(proposal, snapshot.QC)
	return err
}

func (mesh *CommitteeMesh) proposeLocal(transition model.StateTransition, round uint64) {
	height := mesh.engine.Height() + 1
	if _, exists := mesh.engine.Proposal(height); exists {
		log.Printf("committee already has a proposal at height %d, skipping", height)
		return
	}
	// Propose records the leader's own vote internally, so a quorum is reached
	// when the outstanding peer votes arrive. Calling ProcessVote on the local
	// vote here would race with the vote handler that commits the height and
	// deletes the proposal.
	proposal, _, err := mesh.engine.Propose(transition, round)
	if err != nil {
		log.Printf("committee propose failed: %v", err)
		return
	}
	mesh.broadcast(committeeEnvelope{Type: "proposal", Proposal: &proposal})
}

// CatchUp asks every committee peer for a snapshot starting from the local
// height, and adopts the first valid response. A restarting manager calls this
// after Connect+WaitReady to reach the certified height before serving.
func (mesh *CommitteeMesh) CatchUp(ctx context.Context) error {
	localHeight := mesh.engine.Height()
	for _, peerID := range mesh.peers {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		height := localHeight
		message := committeeEnvelope{Type: "sync_request", Height: &height}
		if err := mesh.send(peerID, message); err != nil {
			continue
		}
	}
	if mesh.engine.Height() > localHeight {
		return nil
	}
	// Direct sync_request via streams: the handleStateUpdate loop above sends
	// a response back through a new stream. Wait briefly for it to arrive.
	deadline := time.Now().Add(3 * time.Second)
	for mesh.engine.Height() <= localHeight && time.Now().Before(deadline) {
		time.Sleep(100 * time.Millisecond)
	}
	if mesh.engine.Height() > localHeight {
		return nil
	}
	return fmt.Errorf("catch-up did not advance from height %d", localHeight)
}

// Submit certifies a transition even when the receiving manager is not the
// current leader: the transition is forwarded to the leader and the caller
// waits for the committed snapshot.
func (mesh *CommitteeMesh) Submit(transition model.StateTransition) (model.SignedSnapshot, error) {
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
	totalTimeout := time.After(30 * time.Second)
	for round := uint64(0); round < bft.CommitteeSize; round++ {
		height := mesh.engine.Height() + 1
		leader := mesh.engine.Leader(height, round)
		if leader.ID == mesh.engine.LocalID() {
			mesh.proposeLocal(transition, round)
		} else {
			leaderPeer, ok := mesh.peers[leader.ID]
			if !ok {
				continue
			}
			round := round
			if err := mesh.send(leaderPeer, committeeEnvelope{Type: "forward", Transition: &transition, Round: &round}); err != nil {
				continue
			}
		}
		roundDeadline := time.After(2 * time.Second)
		rotating := true
		for rotating {
			select {
			case snapshot := <-subscriber:
				if snapshot.Height > startHeight {
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

func (mesh *CommitteeMesh) broadcast(message committeeEnvelope) {
	var waitGroup sync.WaitGroup
	for _, peerID := range mesh.peers {
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

func (mesh *CommitteeMesh) send(peerID peer.ID, message committeeEnvelope) error {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	return mesh.node.Send(ctx, peerID, p2p.StateUpdateProtocol, message)
}
