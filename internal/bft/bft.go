// Package bft implements the v0 HotStuff-lite manager committee state machine.
package bft

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"sort"
	"sync"

	"github.com/netp2p/netp2p/internal/model"
)

const (
	CommitteeSize            = 4
	FaultLimit               = 1
	QuorumSize               = CommitteeSize - FaultLimit
	TransitionRegisterPeer   = "register_peer"
	TransitionGenesis        = "genesis"
	TransitionUpsertGroup    = "upsert_group"
	TransitionRemoveGroup    = "remove_group"
	TransitionUpsertPolicy   = "upsert_policy"
	TransitionRemovePolicy   = "remove_policy"
	TransitionUpsertRoute    = "upsert_route"
	TransitionRemoveRoute    = "remove_route"
	TransitionUpsertBudget   = "upsert_budget"
	TransitionRemoveBudget   = "remove_budget"
	TransitionUpsertSetupKey = "upsert_setup_key"
	TransitionRemoveSetupKey = "remove_setup_key"
)

var (
	ErrNotLeader     = errors.New("not leader")
	ErrUnknownLeader = errors.New("proposal from non-leader")
	ErrStaleHeight   = errors.New("stale height")
	ErrInvalidQC     = errors.New("invalid quorum certificate")
)

type Proposal struct {
	Height    uint64             `json:"height"`
	Round     uint64             `json:"round"`
	NetworkID string             `json:"networkId"`
	State     model.NetworkState `json:"state"`
	LeaderID  string             `json:"leaderId"`
}

type Vote struct {
	Height    uint64 `json:"height"`
	Round     uint64 `json:"round"`
	NetworkID string `json:"networkId"`
	StateHash []byte `json:"stateHash"`
	VoterID   string `json:"voterId"`
	Signature []byte `json:"signature"`
}

type Engine struct {
	mu         sync.RWMutex
	committee  []model.CommitteeMember
	byID       map[string]model.CommitteeMember
	publicKeys map[string]ed25519.PublicKey
	privateKey ed25519.PrivateKey
	localID    string
	height     uint64
	current    model.NetworkState
	proposals  map[uint64]Proposal
	votes      map[uint64][]Vote
	committed  map[uint64]model.SignedSnapshot
	listeners  []func(model.SignedSnapshot)
}

func SeededPrivateKey(seed int64) ed25519.PrivateKey {
	seedBytes := make([]byte, 8)
	binary.LittleEndian.PutUint64(seedBytes, uint64(seed))
	hash := sha256.Sum256(seedBytes)
	return ed25519.NewKeyFromSeed(hash[:])
}

func SeededPublicKey(seed int64) ed25519.PublicKey {
	privateKey := SeededPrivateKey(seed)
	publicKey, _ := privateKey.Public().(ed25519.PublicKey)
	return publicKey
}

func NewEngine(seedState model.NetworkState, committee []model.CommitteeMember, localID string, privateKey ed25519.PrivateKey) (*Engine, error) {
	if len(committee) != CommitteeSize {
		return nil, fmt.Errorf("committee size must be %d", CommitteeSize)
	}
	if len(privateKey) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("invalid local private key")
	}
	if _, err := netip.ParsePrefix(seedState.OverlayCIDR); err != nil {
		return nil, fmt.Errorf("invalid overlay CIDR")
	}
	engine := &Engine{
		committee:  append([]model.CommitteeMember(nil), committee...),
		byID:       make(map[string]model.CommitteeMember, len(committee)),
		publicKeys: make(map[string]ed25519.PublicKey, len(committee)),
		privateKey: append(ed25519.PrivateKey(nil), privateKey...),
		localID:    localID,
		current:    NormalizeState(seedState),
		proposals:  make(map[uint64]Proposal),
		votes:      make(map[uint64][]Vote),
		committed:  make(map[uint64]model.SignedSnapshot),
	}
	sort.Slice(engine.committee, func(i, j int) bool {
		return engine.committee[i].ID < engine.committee[j].ID
	})
	for index := range engine.committee {
		member := engine.committee[index]
		if member.ID == "" {
			return nil, fmt.Errorf("committee member id is required")
		}
		if len(member.PublicKey) == 0 {
			publicKey := SeededPublicKey(member.KeySeed)
			member.PublicKey = append([]byte(nil), publicKey...)
			engine.committee[index] = member
		}
		engine.byID[member.ID] = member
		engine.publicKeys[member.ID] = ed25519.PublicKey(member.PublicKey)
	}
	if _, ok := engine.byID[localID]; !ok {
		return nil, fmt.Errorf("local manager %q is not in committee", localID)
	}
	return engine, nil
}

func NormalizeState(state model.NetworkState) model.NetworkState {
	normalized := state
	// Start from non-nil empty slices so an empty collection marshals as [] and
	// not null. Clients (including the browser console) decode these as arrays.
	normalized.Peers = append([]model.PeerRecord{}, state.Peers...)
	normalized.Groups = append([]model.Group{}, state.Groups...)
	normalized.Policies = append([]model.Policy{}, state.Policies...)
	normalized.Routes = append([]model.Route{}, state.Routes...)
	normalized.Budgets = append([]model.TrafficBudget{}, state.Budgets...)
	normalized.SetupKeys = append([]model.SetupKey{}, state.SetupKeys...)
	sort.Slice(normalized.Peers, func(i, j int) bool { return normalized.Peers[i].PeerID < normalized.Peers[j].PeerID })
	sort.Slice(normalized.Groups, func(i, j int) bool { return normalized.Groups[i].ID < normalized.Groups[j].ID })
	sort.Slice(normalized.Policies, func(i, j int) bool { return normalized.Policies[i].ID < normalized.Policies[j].ID })
	sort.Slice(normalized.Routes, func(i, j int) bool { return normalized.Routes[i].ID < normalized.Routes[j].ID })
	sort.Slice(normalized.Budgets, func(i, j int) bool { return normalized.Budgets[i].ID < normalized.Budgets[j].ID })
	sort.Slice(normalized.SetupKeys, func(i, j int) bool { return normalized.SetupKeys[i].Key < normalized.SetupKeys[j].Key })
	for index := range normalized.Groups {
		sort.Strings(normalized.Groups[index].UserIDs)
		sort.Strings(normalized.Groups[index].PeerIDs)
	}
	return normalized
}

func canonicalValue(value any) []byte {
	encoded, _ := json.Marshal(value)
	return encoded
}

func StateHash(state model.NetworkState) []byte {
	hash := sha256.Sum256(canonicalValue(NormalizeState(state)))
	return hash[:]
}

func proposalHash(proposal Proposal) []byte {
	proposal.State = NormalizeState(proposal.State)
	hash := sha256.Sum256(canonicalValue(proposal))
	return hash[:]
}

func (engine *Engine) Leader(height, round uint64) model.CommitteeMember {
	return engine.committee[(height+round)%uint64(len(engine.committee))]
}

func (engine *Engine) Height() uint64 {
	engine.mu.RLock()
	defer engine.mu.RUnlock()
	return engine.height
}

func (engine *Engine) LocalID() string {
	return engine.localID
}

func (engine *Engine) CurrentState() model.NetworkState {
	engine.mu.RLock()
	defer engine.mu.RUnlock()
	return cloneState(engine.current)
}

func (engine *Engine) Proposal(height uint64) (Proposal, bool) {
	engine.mu.RLock()
	defer engine.mu.RUnlock()
	proposal, ok := engine.proposals[height]
	return cloneProposal(proposal), ok
}

// CommitteeMembers returns the committee's signing identities in canonical order.
func (engine *Engine) CommitteeMembers() []model.CommitteeMember {
	engine.mu.RLock()
	defer engine.mu.RUnlock()
	return append([]model.CommitteeMember(nil), engine.committee...)
}

// Snapshot returns a committed snapshot by height for decision-log queries.
func (engine *Engine) Snapshot(height uint64) (model.SignedSnapshot, bool) {
	engine.mu.RLock()
	defer engine.mu.RUnlock()
	snapshot, ok := engine.committed[height]
	return snapshot, ok
}

// LatestSnapshot returns the highest committed snapshot, if any.
func (engine *Engine) LatestSnapshot() (model.SignedSnapshot, bool) {
	engine.mu.RLock()
	defer engine.mu.RUnlock()
	if len(engine.committed) == 0 {
		return model.SignedSnapshot{}, false
	}
	snapshot := engine.committed[engine.height]
	snapshot.Committee = append([]model.CommitteeMember(nil), engine.committee...)
	return snapshot, true
}

// CatchUp commits a certified snapshot received from a peer without needing a
// local proposal. It is the only path by which a restarting or lagging manager
// can advance. It accepts height >= current+1 so a broadcast can bridge a gap.
func (engine *Engine) CatchUp(snapshot model.SignedSnapshot) error {
	if err := ValidateSnapshot(snapshot); err != nil {
		return fmt.Errorf("invalid snapshot: %w", err)
	}
	engine.mu.Lock()
	if snapshot.Height <= engine.height {
		engine.mu.Unlock()
		return ErrStaleHeight
	}
	if snapshot.Height > engine.height+1 && len(engine.committed) > 0 {
		engine.mu.Unlock()
		return fmt.Errorf("snapshot height %d leaves a gap from %d", snapshot.Height, engine.height)
	}
	engine.current = NormalizeState(snapshot.State)
	engine.height = snapshot.Height
	engine.committed[snapshot.Height] = snapshot
	delete(engine.proposals, snapshot.Height)
	delete(engine.votes, snapshot.Height)
	listeners := make([]func(model.SignedSnapshot), len(engine.listeners))
	copy(listeners, engine.listeners)
	engine.mu.Unlock()
	for _, listener := range listeners {
		listener(snapshot)
	}
	return nil
}

func cloneState(state model.NetworkState) model.NetworkState {
	// NormalizeState already returns fresh (non-nil) copies of every collection.
	return NormalizeState(state)
}

func cloneProposal(proposal Proposal) Proposal {
	proposal.State = cloneState(proposal.State)
	return proposal
}

func signVote(privateKey ed25519.PrivateKey, vote *Vote) error {
	hash := sha256.Sum256(canonicalValue(map[string]any{
		"height": vote.Height, "round": vote.Round, "networkId": vote.NetworkID,
		"stateHash": vote.StateHash, "voterId": vote.VoterID,
	}))
	vote.Signature = ed25519.Sign(privateKey, hash[:])
	return nil
}

func verifyVote(publicKey ed25519.PublicKey, vote Vote) bool {
	if len(vote.Signature) != ed25519.SignatureSize {
		return false
	}
	hash := sha256.Sum256(canonicalValue(map[string]any{
		"height": vote.Height, "round": vote.Round, "networkId": vote.NetworkID,
		"stateHash": vote.StateHash, "voterId": vote.VoterID,
	}))
	return ed25519.Verify(publicKey, hash[:], vote.Signature)
}

func (engine *Engine) Propose(transition model.StateTransition, round uint64) (Proposal, Vote, error) {
	engine.mu.Lock()
	defer engine.mu.Unlock()
	height := engine.height + 1
	leader := engine.Leader(height, round)
	if leader.ID != engine.localID {
		return Proposal{}, Vote{}, fmt.Errorf("%w: local=%s leader=%s height=%d", ErrNotLeader, engine.localID, leader.ID, height)
	}
	next := cloneState(engine.current)
	if err := ApplyTransition(&next, transition); err != nil {
		return Proposal{}, Vote{}, err
	}
	proposal := Proposal{Height: height, Round: round, NetworkID: next.NetworkID, State: next, LeaderID: leader.ID}
	vote := engine.localVote(proposal)
	engine.proposals[proposal.Height] = proposal
	engine.addVoteLocked(vote)
	return proposal, vote, nil
}

func (engine *Engine) localVote(proposal Proposal) Vote {
	hash := StateHash(proposal.State)
	vote := Vote{Height: proposal.Height, Round: proposal.Round, NetworkID: proposal.NetworkID, StateHash: hash, VoterID: engine.localID}
	if err := signVote(engine.privateKey, &vote); err != nil {
		return vote
	}
	return vote
}

func (engine *Engine) ProcessProposal(proposal Proposal) (Vote, error) {
	engine.mu.Lock()
	defer engine.mu.Unlock()
	if proposal.NetworkID != engine.current.NetworkID {
		return Vote{}, fmt.Errorf("network id mismatch")
	}
	if proposal.Height <= engine.height {
		return Vote{}, ErrStaleHeight
	}
	if proposal.Height != engine.height+1 {
		return Vote{}, fmt.Errorf("unexpected proposal height")
	}
	if proposal.LeaderID != engine.Leader(proposal.Height, proposal.Round).ID {
		return Vote{}, ErrUnknownLeader
	}
	engine.proposals[proposal.Height] = proposal
	vote := engine.localVote(proposal)
	engine.addVoteLocked(vote)
	return vote, nil
}

func (engine *Engine) addVoteLocked(vote Vote) {
	for _, existing := range engine.votes[vote.Height] {
		if existing.VoterID == vote.VoterID {
			return
		}
	}
	engine.votes[vote.Height] = append(engine.votes[vote.Height], vote)
}

func (engine *Engine) ProcessVote(vote Vote) (model.QuorumCertificate, bool, error) {
	engine.mu.Lock()
	defer engine.mu.Unlock()
	publicKey, ok := engine.publicKeys[vote.VoterID]
	if !ok || !verifyVote(publicKey, vote) {
		return model.QuorumCertificate{}, false, fmt.Errorf("invalid vote signature")
	}
	if vote.Height <= engine.height {
		return model.QuorumCertificate{}, false, ErrStaleHeight
	}
	proposal, ok := engine.proposals[vote.Height]
	if !ok || !bytes.Equal(StateHash(proposal.State), vote.StateHash) {
		return model.QuorumCertificate{}, false, fmt.Errorf("vote does not match proposal")
	}
	engine.addVoteLocked(vote)
	if len(engine.votes[vote.Height]) < QuorumSize {
		return model.QuorumCertificate{}, false, nil
	}
	qc := model.QuorumCertificate{Height: vote.Height, Round: vote.Round, StateHash: vote.StateHash}
	count := 0
	for _, member := range engine.committee {
		for _, item := range engine.votes[vote.Height] {
			if item.VoterID == member.ID {
				qc.Signers = append(qc.Signers, member.ID)
				qc.Signatures = append(qc.Signatures, item.Signature)
				count++
				break
			}
		}
		if count == QuorumSize {
			break
		}
	}
	return qc, true, nil
}

func (engine *Engine) Commit(proposal Proposal, qc model.QuorumCertificate) (model.SignedSnapshot, error) {
	engine.mu.Lock()
	if err := func() error {
		if err := engine.verifyQCLocked(qc); err != nil {
			return err
		}
		if qc.Height != proposal.Height || !bytes.Equal(qc.StateHash, StateHash(proposal.State)) {
			return ErrInvalidQC
		}
		if proposal.Height != engine.height+1 {
			return fmt.Errorf("cannot commit non-next height")
		}
		return nil
	}(); err != nil {
		engine.mu.Unlock()
		return model.SignedSnapshot{}, err
	}
	engine.current = NormalizeState(proposal.State)
	engine.height = proposal.Height
	snapshot := model.SignedSnapshot{
		Epoch: proposal.Height, Height: proposal.Height, StateHash: append([]byte(nil), qc.StateHash...),
		State: cloneState(engine.current), Committee: append([]model.CommitteeMember(nil), engine.committee...), QC: qc,
	}
	engine.committed[proposal.Height] = snapshot
	delete(engine.proposals, proposal.Height)
	delete(engine.votes, proposal.Height)
	listeners := make([]func(model.SignedSnapshot), len(engine.listeners))
	copy(listeners, engine.listeners)
	engine.mu.Unlock()
	for _, listener := range listeners {
		listener(snapshot)
	}
	return snapshot, nil
}

func (engine *Engine) verifyQCLocked(qc model.QuorumCertificate) error {
	if len(qc.Signers) < QuorumSize || len(qc.Signatures) != len(qc.Signers) {
		return ErrInvalidQC
	}
	seen := make(map[string]struct{})
	for index, signerID := range qc.Signers {
		publicKey, ok := engine.publicKeys[signerID]
		if !ok {
			return ErrInvalidQC
		}
		if _, duplicate := seen[signerID]; duplicate {
			return ErrInvalidQC
		}
		seen[signerID] = struct{}{}
		vote := Vote{Height: qc.Height, Round: qc.Round, NetworkID: engine.current.NetworkID, StateHash: qc.StateHash, VoterID: signerID, Signature: qc.Signatures[index]}
		if !verifyVote(publicKey, vote) {
			return ErrInvalidQC
		}
	}
	return nil
}

func (engine *Engine) OnCommit(listener func(model.SignedSnapshot)) {
	engine.mu.Lock()
	defer engine.mu.Unlock()
	engine.listeners = append(engine.listeners, listener)
}

func ApplyTransition(state *model.NetworkState, transition model.StateTransition) error {
	if state == nil {
		return fmt.Errorf("nil state")
	}
	switch transition.Type {
	case TransitionGenesis:
		return nil
	case TransitionRegisterPeer:
		for _, peer := range state.Peers {
			if peer.PeerID == transition.Peer.PeerID {
				return fmt.Errorf("peer already registered")
			}
		}
		var setupKey *model.SetupKey
		for index := range state.SetupKeys {
			if state.SetupKeys[index].Key == transition.SetupKey {
				setupKey = &state.SetupKeys[index]
				break
			}
		}
		if setupKey == nil {
			return fmt.Errorf("invalid setup key")
		}
		if transition.Peer.OverlayIP != "" {
			return fmt.Errorf("client may not choose overlay IP")
		}
		address, err := allocateAddress(*state)
		if err != nil {
			return err
		}
		peer := transition.Peer
		peer.OverlayIP = address
		peer.Groups = append([]string(nil), setupKey.Groups...)
		state.Peers = append(state.Peers, peer)
		state.NextIPOffset++
		for _, groupID := range setupKey.Groups {
			found := false
			for index := range state.Groups {
				if state.Groups[index].ID != groupID {
					continue
				}
				state.Groups[index].PeerIDs = append(state.Groups[index].PeerIDs, peer.PeerID)
				found = true
				break
			}
			if !found {
				return fmt.Errorf("setup key references unknown group %q", groupID)
			}
		}
		return nil
	case TransitionUpsertGroup:
		if transition.Group == nil || transition.Group.ID == "" {
			return fmt.Errorf("group record is required")
		}
		for index := range state.Groups {
			if state.Groups[index].ID == transition.Group.ID {
				state.Groups[index] = *transition.Group
				return nil
			}
		}
		state.Groups = append(state.Groups, *transition.Group)
		return nil
	case TransitionRemoveGroup:
		if transition.TargetID == "" {
			return fmt.Errorf("targetId is required")
		}
		for index := range state.Groups {
			if state.Groups[index].ID == transition.TargetID {
				state.Groups = append(state.Groups[:index], state.Groups[index+1:]...)
				return nil
			}
		}
		return fmt.Errorf("group %q not found", transition.TargetID)
	case TransitionUpsertPolicy:
		if transition.Policy == nil || transition.Policy.ID == "" {
			return fmt.Errorf("policy record is required")
		}
		for index := range state.Policies {
			if state.Policies[index].ID == transition.Policy.ID {
				state.Policies[index] = *transition.Policy
				return nil
			}
		}
		state.Policies = append(state.Policies, *transition.Policy)
		return nil
	case TransitionRemovePolicy:
		if transition.TargetID == "" {
			return fmt.Errorf("targetId is required")
		}
		for index := range state.Policies {
			if state.Policies[index].ID == transition.TargetID {
				state.Policies = append(state.Policies[:index], state.Policies[index+1:]...)
				return nil
			}
		}
		return fmt.Errorf("policy %q not found", transition.TargetID)
	case TransitionUpsertRoute:
		if transition.Route == nil || transition.Route.ID == "" {
			return fmt.Errorf("route record is required")
		}
		for index := range state.Routes {
			if state.Routes[index].ID == transition.Route.ID {
				state.Routes[index] = *transition.Route
				return nil
			}
		}
		state.Routes = append(state.Routes, *transition.Route)
		return nil
	case TransitionRemoveRoute:
		if transition.TargetID == "" {
			return fmt.Errorf("targetId is required")
		}
		for index := range state.Routes {
			if state.Routes[index].ID == transition.TargetID {
				state.Routes = append(state.Routes[:index], state.Routes[index+1:]...)
				return nil
			}
		}
		return fmt.Errorf("route %q not found", transition.TargetID)
	case TransitionUpsertBudget:
		if transition.Budget == nil || transition.Budget.ID == "" {
			return fmt.Errorf("budget record is required")
		}
		for index := range state.Budgets {
			if state.Budgets[index].ID == transition.Budget.ID {
				state.Budgets[index] = *transition.Budget
				return nil
			}
		}
		state.Budgets = append(state.Budgets, *transition.Budget)
		return nil
	case TransitionRemoveBudget:
		if transition.TargetID == "" {
			return fmt.Errorf("targetId is required")
		}
		for index := range state.Budgets {
			if state.Budgets[index].ID == transition.TargetID {
				state.Budgets = append(state.Budgets[:index], state.Budgets[index+1:]...)
				return nil
			}
		}
		return fmt.Errorf("budget %q not found", transition.TargetID)
	case TransitionUpsertSetupKey:
		if transition.Record == nil || transition.Record.Key == "" {
			return fmt.Errorf("setup key record is required")
		}
		for index := range state.SetupKeys {
			if state.SetupKeys[index].Key == transition.Record.Key {
				state.SetupKeys[index] = *transition.Record
				return nil
			}
		}
		state.SetupKeys = append(state.SetupKeys, *transition.Record)
		return nil
	case TransitionRemoveSetupKey:
		if transition.TargetID == "" {
			return fmt.Errorf("targetId is required")
		}
		for index := range state.SetupKeys {
			if state.SetupKeys[index].Key == transition.TargetID {
				state.SetupKeys = append(state.SetupKeys[:index], state.SetupKeys[index+1:]...)
				return nil
			}
		}
		return fmt.Errorf("setup key %q not found", transition.TargetID)
	default:
		return fmt.Errorf("unknown transition type %q", transition.Type)
	}
}

func allocateAddress(state model.NetworkState) (string, error) {
	prefix, err := netip.ParsePrefix(state.OverlayCIDR)
	if err != nil {
		return "", err
	}
	offset := uint64(state.NextIPOffset)
	bits := prefix.Bits()
	if prefix.Addr().Is4() {
		hostBits := uint64(32 - bits)
		if bits > 30 || hostBits >= 64 || offset >= (uint64(1)<<hostBits)-1 {
			return "", fmt.Errorf("overlay address space exhausted")
		}
		address := netip.AddrFrom4(prefix.Addr().As4()).As16()
		value := binary.BigEndian.Uint32(address[12:]) + uint32(offset)
		return netip.AddrFrom4([4]byte{byte(value >> 24), byte(value >> 16), byte(value >> 8), byte(value)}).String(), nil
	}
	return "", fmt.Errorf("only IPv4 overlay prefixes are supported")
}

func ValidateSnapshot(snapshot model.SignedSnapshot) error {
	if len(snapshot.Committee) < CommitteeSize {
		return ErrInvalidQC
	}
	publicKeys := make(map[string]ed25519.PublicKey)
	for _, member := range snapshot.Committee {
		if len(member.PublicKey) == 0 {
			publicKeys[member.ID] = SeededPublicKey(member.KeySeed)
		} else {
			publicKeys[member.ID] = ed25519.PublicKey(member.PublicKey)
		}
	}
	if !bytes.Equal(snapshot.StateHash, StateHash(snapshot.State)) {
		return fmt.Errorf("snapshot state hash mismatch")
	}
	qc := snapshot.QC
	if len(qc.Signers) < QuorumSize || len(qc.Signatures) != len(qc.Signers) || qc.Height != snapshot.Height {
		return ErrInvalidQC
	}
	seen := make(map[string]struct{})
	for index, signerID := range qc.Signers {
		publicKey, ok := publicKeys[signerID]
		if !ok {
			return ErrInvalidQC
		}
		if _, duplicate := seen[signerID]; duplicate {
			return ErrInvalidQC
		}
		seen[signerID] = struct{}{}
		vote := Vote{Height: qc.Height, Round: qc.Round, NetworkID: snapshot.State.NetworkID, StateHash: qc.StateHash, VoterID: signerID, Signature: qc.Signatures[index]}
		if !verifyVote(publicKey, vote) {
			return ErrInvalidQC
		}
	}
	return nil
}
