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
	"strings"
	"sync"
	"time"

	"github.com/netp2p/netp2p/internal/model"
)

const (
	CommitteeSize              = 4
	FaultLimit                 = 1
	QuorumSize                 = CommitteeSize - FaultLimit
	TransitionRegisterPeer     = "register_peer"
	TransitionGenesis          = "genesis"
	TransitionUpsertGroup      = "upsert_group"
	TransitionRemoveGroup      = "remove_group"
	TransitionUpsertPolicy     = "upsert_policy"
	TransitionRemovePolicy     = "remove_policy"
	TransitionUpsertRoute      = "upsert_route"
	TransitionRemoveRoute      = "remove_route"
	TransitionUpsertBudget     = "upsert_budget"
	TransitionRemoveBudget     = "remove_budget"
	TransitionUpsertSetupKey   = "upsert_setup_key"
	TransitionRemoveSetupKey   = "remove_setup_key"
	TransitionRevokeSetupKey   = "revoke_setup_key"
	TransitionUpdatePeer       = "update_peer"
	TransitionUpsertNS         = "upsert_nameserver"
	TransitionRemoveNS         = "remove_nameserver"
	TransitionUpsertZone       = "upsert_zone"
	TransitionRemoveZone       = "remove_zone"
	TransitionUpdateDNS        = "update_dns_settings"
	TransitionRegisterUser     = "register_user"
	TransitionUpdateUserGroups = "update_user_groups"
	TransitionUpdateUserRole   = "update_user_role"
	TransitionRemoveUser       = "remove_user"
	TransitionSetUserBlocked   = "set_user_blocked"
	TransitionUpdateSettings   = "update_network_settings"
	TransitionUpdateAssignment = "update_route_assignment"
	TransitionRemoveAssignment = "remove_route_assignment"
)

var (
	ErrNotLeader     = errors.New("not leader")
	ErrUnknownLeader = errors.New("proposal from non-leader")
	ErrStaleHeight   = errors.New("stale height")
	ErrInvalidQC     = errors.New("invalid quorum certificate")
)

type Proposal struct {
	Height     uint64                `json:"height"`
	Round      uint64                `json:"round"`
	NetworkID  string                `json:"networkId"`
	State      model.NetworkState    `json:"state"`
	LeaderID   string                `json:"leaderId"`
	Transition model.StateTransition `json:"transition"`
}

type Vote struct {
	Height         uint64 `json:"height"`
	Round          uint64 `json:"round"`
	NetworkID      string `json:"networkId"`
	StateHash      []byte `json:"stateHash"`
	TransitionHash []byte `json:"transitionHash"`
	VoterID        string `json:"voterId"`
	Signature      []byte `json:"signature"`
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

func findPeerRecord(state model.NetworkState, peerID string) *model.PeerRecord {
	for index := range state.Peers {
		if state.Peers[index].PeerID == peerID {
			return &state.Peers[index]
		}
	}
	return nil
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
	normalized.Users = append([]model.User{}, state.Users...)
	normalized.Groups = append([]model.Group{}, state.Groups...)
	normalized.Policies = append([]model.Policy{}, state.Policies...)
	normalized.Routes = append([]model.Route{}, state.Routes...)
	normalized.Budgets = append([]model.TrafficBudget{}, state.Budgets...)
	normalized.SetupKeys = append([]model.SetupKey{}, state.SetupKeys...)
	normalized.Nameservers = append([]model.Nameserver{}, state.Nameservers...)
	normalized.Zones = append([]model.DNSZone{}, state.Zones...)
	normalized.Assignments = append([]model.RouteAssignment{}, state.Assignments...)
	sort.Slice(normalized.Peers, func(i, j int) bool { return normalized.Peers[i].PeerID < normalized.Peers[j].PeerID })
	sort.Slice(normalized.Users, func(i, j int) bool { return normalized.Users[i].ID < normalized.Users[j].ID })
	sort.Slice(normalized.Groups, func(i, j int) bool { return normalized.Groups[i].ID < normalized.Groups[j].ID })
	sort.Slice(normalized.Policies, func(i, j int) bool { return normalized.Policies[i].ID < normalized.Policies[j].ID })
	sort.Slice(normalized.Routes, func(i, j int) bool { return normalized.Routes[i].ID < normalized.Routes[j].ID })
	sort.Slice(normalized.Budgets, func(i, j int) bool { return normalized.Budgets[i].ID < normalized.Budgets[j].ID })
	sort.Slice(normalized.SetupKeys, func(i, j int) bool { return normalized.SetupKeys[i].ID < normalized.SetupKeys[j].ID })
	sort.Slice(normalized.Nameservers, func(i, j int) bool { return normalized.Nameservers[i].ID < normalized.Nameservers[j].ID })
	sort.Slice(normalized.Zones, func(i, j int) bool { return normalized.Zones[i].ID < normalized.Zones[j].ID })
	sort.Slice(normalized.Assignments, func(i, j int) bool { return normalized.Assignments[i].ID < normalized.Assignments[j].ID })
	for index := range normalized.Groups {
		sort.Strings(normalized.Groups[index].UserIDs)
		sort.Strings(normalized.Groups[index].PeerIDs)
	}
	for index := range normalized.Users {
		sort.Strings(normalized.Users[index].AutoGroups)
	}
	sort.Strings(normalized.Settings.JWTAllowGroups)
	for index := range normalized.Nameservers {
		sort.Strings(normalized.Nameservers[index].Groups)
		sort.Strings(normalized.Nameservers[index].MatchDomains)
		sort.Strings(normalized.Nameservers[index].Servers)
	}
	for index := range normalized.Zones {
		sort.Strings(normalized.Zones[index].Groups)
		sort.Slice(normalized.Zones[index].Records, func(a, b int) bool {
			left, right := normalized.Zones[index].Records[a], normalized.Zones[index].Records[b]
			if left.Name != right.Name {
				return left.Name < right.Name
			}
			if left.Type != right.Type {
				return left.Type < right.Type
			}
			return left.Value < right.Value
		})
	}
	for index := range normalized.Assignments {
		normalized.Assignments[index].Primary = normalized.Assignments[index].Primary.Normalized()
		sort.Strings(normalized.Assignments[index].Primary.ManagerHops)
		normalized.Assignments[index].Fallbacks = append([]model.PathSpec{}, normalized.Assignments[index].Fallbacks...)
		sort.Slice(normalized.Assignments[index].Fallbacks, func(a, b int) bool {
			return normalized.Assignments[index].Fallbacks[a].ID < normalized.Assignments[index].Fallbacks[b].ID
		})
		for pathIndex := range normalized.Assignments[index].Fallbacks {
			normalized.Assignments[index].Fallbacks[pathIndex] = normalized.Assignments[index].Fallbacks[pathIndex].Normalized()
			sort.Strings(normalized.Assignments[index].Fallbacks[pathIndex].ManagerHops)
		}
	}
	sort.Strings(normalized.DNSSettings.Groups)
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

// TransitionHash commits a transition into the signed vote. Because the hash is
// covered by each committee member's signature, the certified snapshot's
// transition cannot be altered by a single manager without breaking the QC.
func TransitionHash(transition model.StateTransition) []byte {
	hash := sha256.Sum256(canonicalValue(transition))
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

// Activity returns committed snapshots in descending height order, newest
// first. Entries at or above `before` are skipped so callers can page. Each
// entry is a certified decision-log record: its transition is covered by the
// QC and can be re-verified with ValidateSnapshot.
func (engine *Engine) Activity(limit int, before uint64) []model.SignedSnapshot {
	engine.mu.RLock()
	defer engine.mu.RUnlock()
	if limit <= 0 {
		limit = 100
	}
	heights := make([]uint64, 0, len(engine.committed))
	for height := range engine.committed {
		if before > 0 && height >= before {
			continue
		}
		heights = append(heights, height)
	}
	sort.Slice(heights, func(i, j int) bool { return heights[i] > heights[j] })
	if len(heights) > limit {
		heights = heights[:limit]
	}
	result := make([]model.SignedSnapshot, 0, len(heights))
	for _, height := range heights {
		snapshot := engine.committed[height]
		snapshot.Committee = append([]model.CommitteeMember(nil), engine.committee...)
		result = append(result, snapshot)
	}
	return result
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
		"stateHash": vote.StateHash, "transitionHash": vote.TransitionHash,
		"voterId": vote.VoterID,
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
		"stateHash": vote.StateHash, "transitionHash": vote.TransitionHash,
		"voterId": vote.VoterID,
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
	next.EngineCommittee = append([]model.CommitteeMember(nil), engine.committee...)
	if err := ApplyTransition(&next, transition); err != nil {
		return Proposal{}, Vote{}, err
	}
	next.EngineCommittee = nil
	proposal := Proposal{Height: height, Round: round, NetworkID: next.NetworkID, State: next, LeaderID: leader.ID, Transition: transition}
	vote := engine.localVote(proposal)
	engine.proposals[proposal.Height] = proposal
	engine.addVoteLocked(vote)
	return proposal, vote, nil
}

func (engine *Engine) localVote(proposal Proposal) Vote {
	hash := StateHash(proposal.State)
	vote := Vote{
		Height: proposal.Height, Round: proposal.Round, NetworkID: proposal.NetworkID,
		StateHash: hash, TransitionHash: TransitionHash(proposal.Transition), VoterID: engine.localID,
	}
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
	// Re-derive the proposed state from the leader's transition so a byzantine
	// leader cannot ship a state that its own decision log does not justify.
	expected := cloneState(engine.current)
	expected.EngineCommittee = append([]model.CommitteeMember(nil), engine.committee...)
	if err := ApplyTransition(&expected, proposal.Transition); err != nil {
		return Vote{}, fmt.Errorf("invalid transition: %w", err)
	}
	expected.EngineCommittee = nil
	if !bytes.Equal(StateHash(expected), StateHash(proposal.State)) {
		return Vote{}, fmt.Errorf("proposal state does not match transition")
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
	if !bytes.Equal(TransitionHash(proposal.Transition), vote.TransitionHash) {
		return model.QuorumCertificate{}, false, fmt.Errorf("vote does not match transition")
	}
	engine.addVoteLocked(vote)
	if len(engine.votes[vote.Height]) < QuorumSize {
		return model.QuorumCertificate{}, false, nil
	}
	qc := model.QuorumCertificate{
		Height: vote.Height, Round: vote.Round,
		StateHash: vote.StateHash, TransitionHash: vote.TransitionHash,
	}
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
		if !bytes.Equal(qc.TransitionHash, TransitionHash(proposal.Transition)) {
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
		Transition: proposal.Transition, LeaderID: proposal.LeaderID,
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
		vote := Vote{
			Height: qc.Height, Round: qc.Round, NetworkID: engine.current.NetworkID,
			StateHash: qc.StateHash, TransitionHash: qc.TransitionHash, VoterID: signerID,
			Signature: qc.Signatures[index],
		}
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
	engineCommittee := state.EngineCommittee
	switch transition.Type {
	case TransitionGenesis:
		return nil
	case TransitionRegisterPeer:
		for _, peer := range state.Peers {
			if peer.PeerID == transition.Peer.PeerID {
				return fmt.Errorf("peer already registered")
			}
		}
		if transition.SetupKey == "" && transition.Peer.UserID == "" {
			return fmt.Errorf("a setup key or an authenticated user is required")
		}
		groups := []string{}
		if transition.SetupKey != "" {
			setupKey := findSetupKeyByToken(*state, transition.SetupKey)
			if setupKey == nil {
				return fmt.Errorf("invalid setup key")
			}
			if !setupKey.SetupKeyValid(time.Now().UTC().Format(time.RFC3339)) {
				return fmt.Errorf("invalid setup key")
			}
			groups = append(groups, setupKey.Groups...)
			setupKey.UsedCount++
			setupKey.LastUsedAt = time.Now().UTC().Format(time.RFC3339)
		}
		if transition.Peer.UserID != "" {
			user := findUser(*state, transition.Peer.UserID)
			if user == nil {
				return fmt.Errorf("unknown user %q", transition.Peer.UserID)
			}
			if user.Blocked {
				return fmt.Errorf("user %q is blocked", user.ID)
			}
			groups = append(groups, user.AutoGroups...)
		}
		if err := requireGroups(state, groups); err != nil {
			return err
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
		peer.Groups = dedupeSorted(groups)
		peer.DNSLabel = allocateDNSLabel(*state, peer.Hostname)
		state.Peers = append(state.Peers, peer)
		state.NextIPOffset++
		addPeerToGroups(state, peer.PeerID, peer.Groups)
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
				if state.Groups[index].Issued == model.GroupIssuedJWT {
					return fmt.Errorf("group %q is managed by JWT synchronization", transition.TargetID)
				}
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
		if transition.Record == nil || transition.Record.ID == "" {
			return fmt.Errorf("setup key record is required")
		}
		if len(transition.Record.Groups) == 0 {
			return fmt.Errorf("setup key must grant at least one group")
		}
		if err := requireGroups(state, transition.Record.Groups); err != nil {
			return err
		}
		for index := range state.SetupKeys {
			if state.SetupKeys[index].ID == transition.Record.ID {
				state.SetupKeys[index] = *transition.Record
				return nil
			}
		}
		state.SetupKeys = append(state.SetupKeys, *transition.Record)
		return nil
	case TransitionRevokeSetupKey:
		if transition.TargetID == "" {
			return fmt.Errorf("targetId is required")
		}
		for index := range state.SetupKeys {
			if state.SetupKeys[index].ID == transition.TargetID {
				state.SetupKeys[index].Revoked = true
				return nil
			}
		}
		return fmt.Errorf("setup key %q not found", transition.TargetID)
	case TransitionRemoveSetupKey:
		if transition.TargetID == "" {
			return fmt.Errorf("targetId is required")
		}
		for index := range state.SetupKeys {
			if state.SetupKeys[index].ID == transition.TargetID {
				state.SetupKeys = append(state.SetupKeys[:index], state.SetupKeys[index+1:]...)
				return nil
			}
		}
		return fmt.Errorf("setup key %q not found", transition.TargetID)
	case TransitionUpdatePeer:
		if transition.Peer.PeerID == "" {
			return fmt.Errorf("peer id is required")
		}
		for index := range state.Peers {
			if state.Peers[index].PeerID != transition.Peer.PeerID {
				continue
			}
			// Only metadata and reachability may change here; overlay IP and
			// group membership stay under manager control.
			if transition.Peer.OverlayIP != "" {
				return fmt.Errorf("client may not choose overlay IP")
			}
			state.Peers[index].Hostname = transition.Peer.Hostname
			state.Peers[index].OS = transition.Peer.OS
			state.Peers[index].ClientVersion = transition.Peer.ClientVersion
			if transition.Peer.UserID != "" {
				if findUser(*state, transition.Peer.UserID) == nil {
					return fmt.Errorf("unknown user %q", transition.Peer.UserID)
				}
				state.Peers[index].UserID = transition.Peer.UserID
			}
			if transition.Peer.LastLogin != "" {
				state.Peers[index].LastLogin = transition.Peer.LastLogin
			}
			if state.Peers[index].DNSLabel == "" {
				state.Peers[index].DNSLabel = allocateDNSLabel(*state, transition.Peer.Hostname)
			}
			if len(transition.Peer.Addresses) > 0 {
				state.Peers[index].Addresses = append([]string(nil), transition.Peer.Addresses...)
			}
			return nil
		}
		return fmt.Errorf("peer %q not registered", transition.Peer.PeerID)
	case TransitionUpsertNS:
		if transition.Nameserver == nil || transition.Nameserver.ID == "" {
			return fmt.Errorf("nameserver record is required")
		}
		if err := requireGroups(state, transition.Nameserver.Groups); err != nil {
			return err
		}
		for index := range state.Nameservers {
			if state.Nameservers[index].ID == transition.Nameserver.ID {
				state.Nameservers[index] = *transition.Nameserver
				return nil
			}
		}
		state.Nameservers = append(state.Nameservers, *transition.Nameserver)
		return nil
	case TransitionRemoveNS:
		if transition.TargetID == "" {
			return fmt.Errorf("targetId is required")
		}
		for index := range state.Nameservers {
			if state.Nameservers[index].ID == transition.TargetID {
				state.Nameservers = append(state.Nameservers[:index], state.Nameservers[index+1:]...)
				return nil
			}
		}
		return fmt.Errorf("nameserver %q not found", transition.TargetID)
	case TransitionUpsertZone:
		if transition.Zone == nil || transition.Zone.ID == "" {
			return fmt.Errorf("zone record is required")
		}
		if transition.Zone.Domain == "" {
			return fmt.Errorf("zone domain is required")
		}
		if err := requireGroups(state, transition.Zone.Groups); err != nil {
			return err
		}
		for index := range state.Zones {
			if state.Zones[index].ID == transition.Zone.ID {
				state.Zones[index] = *transition.Zone
				return nil
			}
		}
		state.Zones = append(state.Zones, *transition.Zone)
		return nil
	case TransitionRemoveZone:
		if transition.TargetID == "" {
			return fmt.Errorf("targetId is required")
		}
		for index := range state.Zones {
			if state.Zones[index].ID == transition.TargetID {
				state.Zones = append(state.Zones[:index], state.Zones[index+1:]...)
				return nil
			}
		}
		return fmt.Errorf("zone %q not found", transition.TargetID)
	case TransitionUpdateDNS:
		if transition.DNSSettings == nil {
			return fmt.Errorf("dns settings record is required")
		}
		if err := requireGroups(state, transition.DNSSettings.Groups); err != nil {
			return err
		}
		state.DNSSettings = *transition.DNSSettings
		return nil
	case TransitionRegisterUser:
		if transition.User == nil || transition.User.ID == "" {
			return fmt.Errorf("user record is required")
		}
		if findUser(*state, transition.User.ID) != nil {
			return fmt.Errorf("user %q already registered", transition.User.ID)
		}
		user := *transition.User
		if user.Role == "" {
			user.Role = model.RoleUser
		}
		if !model.ValidRole(user.Role) {
			return fmt.Errorf("unknown role %q", user.Role)
		}
		if err := requireGroups(state, user.AutoGroups); err != nil {
			return err
		}
		user.AutoGroups = dedupeSorted(user.AutoGroups)
		state.Users = append(state.Users, user)
		addUserToGroups(state, user.ID, user.AutoGroups)
		applyUserGroupsToPeers(state, user)
		return nil
	case TransitionUpdateUserGroups:
		user := findUser(*state, transitionUserID(transition))
		if user == nil {
			return fmt.Errorf("user %q not found", transitionUserID(transition))
		}
		if transition.User != nil {
			if err := requireGroups(state, transition.User.AutoGroups); err != nil {
				return err
			}
			previous := append([]string(nil), user.AutoGroups...)
			user.AutoGroups = dedupeSorted(transition.User.AutoGroups)
			removeUserFromGroups(state, user.ID, previous, user.AutoGroups)
			addUserToGroups(state, user.ID, user.AutoGroups)
			applyUserGroupsToPeers(state, *user)
			if transition.User.LastLogin != "" {
				user.LastLogin = transition.User.LastLogin
			}
		}
		if transition.User != nil && transition.User.Blocked {
			user.Blocked = true
		}
		return nil
	case TransitionUpdateUserRole:
		user := findUser(*state, transitionUserID(transition))
		if user == nil {
			return fmt.Errorf("user %q not found", transitionUserID(transition))
		}
		if transition.User == nil || transition.User.Role == "" {
			return fmt.Errorf("role is required")
		}
		if !model.ValidRole(transition.User.Role) {
			return fmt.Errorf("unknown role %q", transition.User.Role)
		}
		if user.Role == model.RoleOwner && transition.User.Role != model.RoleOwner {
			if countOwners(*state) <= 1 {
				return fmt.Errorf("cannot demote the last owner")
			}
		}
		user.Role = transition.User.Role
		return nil
	case TransitionSetUserBlocked:
		user := findUser(*state, transitionUserID(transition))
		if user == nil {
			return fmt.Errorf("user %q not found", transitionUserID(transition))
		}
		blocked := false
		if transition.User != nil {
			blocked = transition.User.Blocked
		}
		if blocked && user.Role == model.RoleOwner && countOwners(*state) <= 1 {
			return fmt.Errorf("cannot block the last owner")
		}
		user.Blocked = blocked
		return nil
	case TransitionRemoveUser:
		target := transitionUserID(transition)
		user := findUser(*state, target)
		if user == nil {
			return fmt.Errorf("user %q not found", target)
		}
		if user.Role == model.RoleOwner && countOwners(*state) <= 1 {
			return fmt.Errorf("cannot remove the last owner")
		}
		removeUserFromGroups(state, user.ID, user.AutoGroups, nil)
		state.Users = removeUser(state.Users, target)
		removePeersOfUser(state, target)
		return nil
	case TransitionUpdateSettings:
		if transition.Settings == nil {
			return fmt.Errorf("network settings record is required")
		}
		if transition.Settings.LoginExpirationDays < 0 {
			return fmt.Errorf("loginExpirationDays cannot be negative")
		}
		state.Settings = *transition.Settings
		return nil
	case TransitionUpdateAssignment:
		if transition.Assignment == nil || transition.Assignment.ID == "" {
			return fmt.Errorf("route assignment is required")
		}
		assignment := *transition.Assignment
		if assignment.NetworkID == "" {
			assignment.NetworkID = state.NetworkID
		}
		if assignment.NetworkID != state.NetworkID {
			return fmt.Errorf("assignment belongs to another network")
		}
		if assignment.SourcePeerID == "" || assignment.DestinationPeerID == "" {
			return fmt.Errorf("assignment source and destination are required")
		}
		if assignment.SourcePeerID == assignment.DestinationPeerID {
			return fmt.Errorf("assignment source and destination must differ")
		}
		if findPeerRecord(*state, assignment.SourcePeerID) == nil || findPeerRecord(*state, assignment.DestinationPeerID) == nil {
			return fmt.Errorf("assignment references unknown peer")
		}
		assignment.Primary = assignment.Primary.Normalized()
		assignment.Fallbacks = append([]model.PathSpec{}, assignment.Fallbacks...)
		if assignment.Primary.Kind == model.PathKindViaManager || assignment.Primary.Kind == model.PathKindMultiHop {
			if err := validateManagerPath(engineCommittee, assignment.Primary); err != nil {
				return err
			}
		}
		for index := range assignment.Fallbacks {
			assignment.Fallbacks[index] = assignment.Fallbacks[index].Normalized()
			switch assignment.Fallbacks[index].Kind {
			case model.PathKindViaManager, model.PathKindMultiHop:
				if err := validateManagerPath(engineCommittee, assignment.Fallbacks[index]); err != nil {
					return err
				}
			case model.PathKindDirect:
			default:
				return fmt.Errorf("unknown path kind %q", assignment.Fallbacks[index].Kind)
			}
		}
		if assignment.UpdatedAt.IsZero() {
			assignment.UpdatedAt = time.Now().UTC()
		}
		for index := range state.Assignments {
			if state.Assignments[index].ID != assignment.ID {
				continue
			}
			state.Assignments[index] = assignment
			return nil
		}
		state.Assignments = append(state.Assignments, assignment)
		return nil
	case TransitionRemoveAssignment:
		if transition.TargetID == "" {
			return fmt.Errorf("targetId is required")
		}
		for index := range state.Assignments {
			if state.Assignments[index].ID == transition.TargetID {
				state.Assignments = append(state.Assignments[:index], state.Assignments[index+1:]...)
				return nil
			}
		}
		return fmt.Errorf("assignment %q not found", transition.TargetID)
	default:
		return fmt.Errorf("unknown transition type %q", transition.Type)
	}
}

func requireGroups(state *model.NetworkState, groups []string) error {
	for _, groupID := range groups {
		found := false
		for index := range state.Groups {
			if state.Groups[index].ID == groupID {
				found = true
				break
			}
		}
		if !found {
			return fmt.Errorf("unknown group %q", groupID)
		}
	}
	return nil
}

func validateManagerPath(committee []model.CommitteeMember, path model.PathSpec) error {
	if len(path.ManagerHops) == 0 {
		return fmt.Errorf("via-manager path requires at least one manager hop")
	}
	for _, hop := range path.ManagerHops {
		forwarding := false
		for _, member := range committee {
			// Hops are libp2p PeerIDs. Certified state carries the committee
			// PeerIDs, so the forwarding check is on the same identity the
			// data plane dials.
			if member.PeerID == hop && member.ForwardingEnabled {
				forwarding = true
				break
			}
		}
		if !forwarding {
			return fmt.Errorf("manager with peer id %q is not a forwarding committee member", hop)
		}
	}
	return nil
}

func findSetupKeyByToken(state model.NetworkState, token string) *model.SetupKey {
	for index := range state.SetupKeys {
		if bytes.Equal(state.SetupKeys[index].TokenHash, model.SetupKeyHash(token)) {
			return &state.SetupKeys[index]
		}
	}
	return nil
}

func findUser(state model.NetworkState, id string) *model.User {
	if id == "" {
		return nil
	}
	for index := range state.Users {
		if state.Users[index].ID == id {
			return &state.Users[index]
		}
	}
	return nil
}

func transitionUserID(transition model.StateTransition) string {
	if transition.User != nil && transition.User.ID != "" {
		return transition.User.ID
	}
	return transition.TargetID
}

func countOwners(state model.NetworkState) int {
	count := 0
	for _, user := range state.Users {
		if user.Role == model.RoleOwner {
			count++
		}
	}
	return count
}

// dedupeSorted returns the distinct values in sorted order. Sorting keeps the
// derived peer groups identical on every committee member.
func dedupeSorted(values []string) []string {
	if len(values) == 0 {
		return []string{}
	}
	seen := make(map[string]struct{}, len(values))
	result := make([]string, 0, len(values))
	for _, value := range values {
		if value == "" {
			continue
		}
		if _, exists := seen[value]; exists {
			continue
		}
		seen[value] = struct{}{}
		result = append(result, value)
	}
	sort.Strings(result)
	return result
}

// addPeerToGroups records peer membership in Group.PeerIDs, which is what the
// policy compiler reads, then re-derives the peer's group list from it.
func addPeerToGroups(state *model.NetworkState, peerID string, groupIDs []string) {
	for _, groupID := range groupIDs {
		for index := range state.Groups {
			if state.Groups[index].ID != groupID {
				continue
			}
			state.Groups[index].PeerIDs = dedupeSorted(append(state.Groups[index].PeerIDs, peerID))
			break
		}
	}
	syncPeerGroups(state, peerID)
}

// addUserToGroups records user membership in Group.UserIDs so policy can expand
// user groups even before any device registers.
func addUserToGroups(state *model.NetworkState, userID string, groupIDs []string) {
	for _, groupID := range groupIDs {
		for index := range state.Groups {
			if state.Groups[index].ID != groupID {
				continue
			}
			state.Groups[index].UserIDs = dedupeSorted(append(state.Groups[index].UserIDs, userID))
			break
		}
	}
}

// removeUserFromGroups drops the user from the groups they left. Peers are only
// removed from JWT-issued groups: setup-key and API groups are not derived from
// the user's IdP membership and must survive a group sync.
func removeUserFromGroups(state *model.NetworkState, userID string, previous, next []string) {
	keep := make(map[string]struct{}, len(next))
	for _, groupID := range next {
		keep[groupID] = struct{}{}
	}
	for _, groupID := range previous {
		if _, still := keep[groupID]; still {
			continue
		}
		for index := range state.Groups {
			group := &state.Groups[index]
			if group.ID != groupID {
				continue
			}
			group.UserIDs = removeValue(group.UserIDs, userID)
			if group.Issued == model.GroupIssuedJWT {
				for _, peerID := range peersOfUser(*state, userID) {
					group.PeerIDs = removeValue(group.PeerIDs, peerID)
					syncPeerGroups(state, peerID)
				}
			}
			break
		}
	}
}

// applyUserGroupsToPeers propagates a user's group set to their devices.
func applyUserGroupsToPeers(state *model.NetworkState, user model.User) {
	peerIDs := peersOfUser(*state, user.ID)
	for _, peerID := range peerIDs {
		addPeerToGroups(state, peerID, user.AutoGroups)
	}
}

// syncPeerGroups re-derives PeerRecord.Groups from group membership so the two
// representations cannot drift.
func syncPeerGroups(state *model.NetworkState, peerID string) {
	groups := []string{}
	for _, group := range state.Groups {
		for _, member := range group.PeerIDs {
			if member == peerID {
				groups = append(groups, group.ID)
				break
			}
		}
	}
	for index := range state.Peers {
		if state.Peers[index].PeerID == peerID {
			state.Peers[index].Groups = dedupeSorted(groups)
			return
		}
	}
}

func peersOfUser(state model.NetworkState, userID string) []string {
	result := make([]string, 0, 2)
	for _, peer := range state.Peers {
		if peer.UserID == userID {
			result = append(result, peer.PeerID)
		}
	}
	return result
}

func removePeersOfUser(state *model.NetworkState, userID string) {
	filtered := state.Peers[:0]
	for _, peer := range state.Peers {
		if peer.UserID == userID {
			continue
		}
		filtered = append(filtered, peer)
	}
	state.Peers = filtered
}

func removeUser(users []model.User, id string) []model.User {
	filtered := users[:0]
	for _, user := range users {
		if user.ID == id {
			continue
		}
		filtered = append(filtered, user)
	}
	return filtered
}

func removeValue(values []string, target string) []string {
	filtered := values[:0]
	for _, value := range values {
		if value == target {
			continue
		}
		filtered = append(filtered, value)
	}
	return filtered
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

// allocateDNSLabel derives a unique DNS label for a peer from its hostname,
// falling back to a peer-id prefix when the hostname carries nothing usable.
// Determinism matters: every committee member must derive the same label.
func allocateDNSLabel(state model.NetworkState, hostname string) string {
	label := sanitizeDNSLabel(hostname)
	if label == "" {
		return ""
	}
	used := make(map[string]struct{}, len(state.Peers))
	for _, peer := range state.Peers {
		if peer.DNSLabel != "" {
			used[peer.DNSLabel] = struct{}{}
		}
	}
	if _, taken := used[label]; !taken {
		return label
	}
	for suffix := 2; ; suffix++ {
		candidate := fmt.Sprintf("%s-%d", label, suffix)
		if _, taken := used[candidate]; !taken {
			return candidate
		}
	}
}

// sanitizeDNSLabel keeps only characters valid in a DNS label.
func sanitizeDNSLabel(hostname string) string {
	trimmed := strings.ToLower(strings.TrimSpace(hostname))
	if index := strings.Index(trimmed, "."); index >= 0 {
		trimmed = trimmed[:index]
	}
	var builder strings.Builder
	for _, char := range trimmed {
		switch {
		case char >= 'a' && char <= 'z', char >= '0' && char <= '9', char == '-':
			builder.WriteRune(char)
		case char == '_' || char == ' ':
			builder.WriteRune('-')
		}
	}
	label := strings.Trim(builder.String(), "-")
	if len(label) > 63 {
		label = label[:63]
	}
	return label
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
	// The transition committed in the snapshot must match the one the
	// committee signed, otherwise the decision log could be rewritten.
	if !bytes.Equal(qc.TransitionHash, TransitionHash(snapshot.Transition)) {
		return fmt.Errorf("snapshot transition hash mismatch")
	}
	// The leader that produced this height is determined by the committee order.
	if snapshot.LeaderID == "" || snapshot.LeaderID != leaderIDFor(snapshot.Committee, snapshot.Height, qc.Round) {
		return fmt.Errorf("snapshot leader mismatch")
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
		vote := Vote{
			Height: qc.Height, Round: qc.Round, NetworkID: snapshot.State.NetworkID,
			StateHash: qc.StateHash, TransitionHash: qc.TransitionHash, VoterID: signerID,
			Signature: qc.Signatures[index],
		}
		if !verifyVote(publicKey, vote) {
			return ErrInvalidQC
		}
	}
	return nil
}

// leaderIDFor mirrors Engine.Leader for a committee snapshot, so a client can
// check a certified snapshot's leader without holding committee state.
func leaderIDFor(committee []model.CommitteeMember, height, round uint64) string {
	if len(committee) == 0 {
		return ""
	}
	ordered := append([]model.CommitteeMember(nil), committee...)
	sort.Slice(ordered, func(i, j int) bool { return ordered[i].ID < ordered[j].ID })
	return ordered[(height+round)%uint64(len(ordered))].ID
}
