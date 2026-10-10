// Package bft implements the v0 HotStuff-lite manager committee state machine.
package bft

import (
	"bytes"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
	"github.com/netp2p/netp2p/internal/crypto/bls"
	"github.com/netp2p/netp2p/internal/model"
	"github.com/netp2p/netp2p/internal/wire"
	"github.com/netp2p/netp2p/internal/wire/pb"
	"google.golang.org/protobuf/proto"
)

const (
	CommitteeSize              = model.DefaultCommitteeSize
	FaultLimit                 = model.DefaultFaultLimit
	QuorumSize                 = model.DefaultQuorumSize
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
	TransitionUpdateCommittee  = "update_committee"
	TransitionRotateCommittee  = "rotate_committee_keys"
	TransitionUpdateBudgetUse  = "update_budget_usage"
)

var (
	ErrNotLeader     = errors.New("not leader")
	ErrUnknownLeader = errors.New("proposal from non-leader")
	ErrStaleHeight   = errors.New("stale height")
	ErrInvalidQC     = errors.New("invalid quorum certificate")
)

// Proposal, Vote and CommitteeEnvelope live in the model package so the wire
// conversion layer can reference them without importing bft. The aliases keep
// the historical bft.Proposal / bft.Vote spellings working.
type (
	Proposal          = model.Proposal
	Vote              = model.Vote
	CommitteeEnvelope = model.CommitteeEnvelope
	CommitteeParams   = model.CommitteeParams
)

type Engine struct {
	mu        sync.RWMutex
	committee []model.CommitteeMember
	byID      map[string]model.CommitteeMember
	blsKeys   *bls.KeySet
	blsIndex  map[string]int
	// dkgLoader returns locally held DKG shares by committee epoch. When set, a
	// rotation that carries an external group public key adopts that material
	// instead of the deterministic seed derivation.
	dkgLoader       func(epoch uint64) (*bls.KeySet, bool)
	committeeConfig model.CommitteeConfig
	params          model.CommitteeParams
	privateKey      ed25519.PrivateKey
	localID         string
	height          uint64
	current         model.NetworkState
	currentRound    uint64
	roundDeadline   time.Time
	roundTimeout    time.Duration
	proposals       map[proposalKey]Proposal
	votes           map[proposalKey][]Vote
	committed       map[uint64]model.SignedSnapshot
	listeners       []func(model.SignedSnapshot)
}

type proposalKey struct {
	Height uint64
	Round  uint64
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
	params, err := model.CommitteeParamsFromConfig(seedState.CommitteeConfig)
	if err != nil {
		return nil, fmt.Errorf("invalid seed committee params: %w", err)
	}
	return NewEngineWithParams(seedState, committee, localID, privateKey, params)
}

func NewEngineWithParams(seedState model.NetworkState, committee []model.CommitteeMember, localID string, privateKey ed25519.PrivateKey, params model.CommitteeParams) (*Engine, error) {
	if err := params.Validate(); err != nil {
		return nil, fmt.Errorf("invalid committee params: %w", err)
	}
	if len(committee) != params.Size {
		return nil, fmt.Errorf("committee size must be %d", params.Size)
	}
	if len(privateKey) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("invalid local private key")
	}
	if _, err := netip.ParsePrefix(seedState.OverlayCIDR); err != nil {
		return nil, fmt.Errorf("invalid overlay CIDR")
	}
	engine := &Engine{
		committee:    append([]model.CommitteeMember(nil), committee...),
		byID:         make(map[string]model.CommitteeMember, len(committee)),
		privateKey:   append(ed25519.PrivateKey(nil), privateKey...),
		localID:      localID,
		current:      NormalizeState(seedState),
		currentRound: 0,
		roundTimeout: 2 * time.Second,
		proposals:    make(map[proposalKey]Proposal),
		votes:        make(map[proposalKey][]Vote),
		committed:    make(map[uint64]model.SignedSnapshot),
		params:       params,
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
	}
	if _, ok := engine.byID[localID]; !ok {
		return nil, fmt.Errorf("local manager %q is not in committee", localID)
	}
	config, keys, index, err := deriveCommitteeKeys(engine.committee, seedState.NetworkID, seedState.CommitteeConfig.CommitteeEpoch, params.QuorumSize)
	if err != nil {
		return nil, err
	}
	engine.committeeConfig = config
	engine.blsKeys = keys
	engine.blsIndex = index
	for position := range engine.committee {
		engine.committee[position].BLSPublicKey = keys.PublicKeyShare(index[engine.committee[position].ID])
		engine.byID[engine.committee[position].ID] = engine.committee[position]
	}
	engine.current.CommitteeConfig = engine.committeeConfig
	engine.startRoundLocked(0)
	return engine, nil
}

// NewEngineWithKeySet installs an externally generated committee key set, such
// as the result of a Pedersen DKG ceremony. Unlike NewEngineWithParams, it
// never derives committee keys from a seed or network identity.
func NewEngineWithKeySet(
	seedState model.NetworkState,
	committee []model.CommitteeMember,
	localID string,
	privateKey ed25519.PrivateKey,
	params model.CommitteeParams,
	keys *bls.KeySet,
	epoch uint64,
) (*Engine, error) {
	if err := params.Validate(); err != nil {
		return nil, fmt.Errorf("invalid committee params: %w", err)
	}
	if len(committee) != params.Size {
		return nil, fmt.Errorf("committee size must be %d", params.Size)
	}
	if len(privateKey) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("invalid local private key")
	}
	if _, err := netip.ParsePrefix(seedState.OverlayCIDR); err != nil {
		return nil, fmt.Errorf("invalid overlay CIDR")
	}
	if keys == nil {
		return nil, fmt.Errorf("committee key set is required")
	}
	if keys.Threshold != params.QuorumSize || keys.Size != params.Size {
		return nil, fmt.Errorf("committee key set is %d-of-%d, want %d-of-%d",
			keys.Threshold, keys.Size, params.QuorumSize, params.Size)
	}
	if len(keys.GroupPublicKey) != bls.PublicKeySize {
		return nil, fmt.Errorf("committee group public key must be %d bytes", bls.PublicKeySize)
	}

	engine := &Engine{
		committee:    append([]model.CommitteeMember(nil), committee...),
		byID:         make(map[string]model.CommitteeMember, len(committee)),
		blsKeys:      keys,
		blsIndex:     make(map[string]int, len(committee)),
		privateKey:   append(ed25519.PrivateKey(nil), privateKey...),
		localID:      localID,
		current:      NormalizeState(seedState),
		currentRound: 0,
		roundTimeout: 2 * time.Second,
		proposals:    make(map[proposalKey]Proposal),
		votes:        make(map[proposalKey][]Vote),
		committed:    make(map[uint64]model.SignedSnapshot),
		params:       params,
	}
	sort.Slice(engine.committee, func(i, j int) bool {
		return engine.committee[i].ID < engine.committee[j].ID
	})
	for index := range engine.committee {
		member := engine.committee[index]
		if member.ID == "" {
			return nil, fmt.Errorf("committee member id is required")
		}
		if member.KeySeed != 0 {
			return nil, fmt.Errorf("committee member %q carries deterministic keySeed", member.ID)
		}
		if len(member.PublicKey) == 0 {
			return nil, fmt.Errorf("committee member %q needs an identity public key", member.ID)
		}
		if len(keys.PublicKeyShare(index)) == 0 {
			return nil, fmt.Errorf("committee member %q has no DKG public share", member.ID)
		}
		engine.committee[index].BLSPublicKey = append([]byte(nil), keys.PublicKeyShare(index)...)
		engine.blsIndex[member.ID] = index
		engine.byID[member.ID] = engine.committee[index]
	}
	if _, ok := engine.byID[localID]; !ok {
		return nil, fmt.Errorf("local manager %q is not in committee", localID)
	}
	engine.committeeConfig = params.CommitteeConfig(epoch, keys.GroupPublicKey)
	engine.current.CommitteeConfig = engine.committeeConfig
	engine.startRoundLocked(0)
	return engine, nil
}

func (engine *Engine) CommitteeParams() model.CommitteeParams {
	engine.mu.RLock()
	defer engine.mu.RUnlock()
	return engine.params
}

// SetRoundTimeout configures the view-change deadline. It is primarily useful
// for tests and future deployment runtime configuration.
func (engine *Engine) SetRoundTimeout(timeout time.Duration) error {
	if timeout <= 0 {
		return fmt.Errorf("round timeout must be positive")
	}
	engine.mu.Lock()
	defer engine.mu.Unlock()
	engine.roundTimeout = timeout
	return nil
}

// RoundTimeout exposes the view-change interval so callers that drive rounds
// can wait longer than every engine's local deadline.
func (engine *Engine) RoundTimeout() time.Duration {
	engine.mu.RLock()
	defer engine.mu.RUnlock()
	return engine.roundTimeout
}

// CurrentRound reports the local consensus view. It is carried in committee
// probes so a restarted manager can adopt the highest view known to a quorum.
func (engine *Engine) CurrentRound() uint64 {
	engine.mu.RLock()
	defer engine.mu.RUnlock()
	return engine.currentRound
}

// AlignRound advances a lagging local view to a round reported by a committee
// quorum. Only advancing is safe: never undo a view in which a proposal may
// already have collected votes.
func (engine *Engine) AlignRound(round uint64) {
	engine.mu.Lock()
	defer engine.mu.Unlock()
	if round <= engine.currentRound {
		return
	}
	engine.clearUncommittedHeightLocked(engine.height + 1)
	engine.startRoundLocked(round)
}

// deriveCommitteeKeys builds the deterministic (t-of-n) BLS sharing for a
// committee sorted by member ID. Each member's share is evaluated at a stable
// point derived from its ID, so replacing a member does not invalidate the
// others' shares or change the group public key.
func deriveCommitteeKeys(committee []model.CommitteeMember, networkID string, epoch uint64, threshold int) (model.CommitteeConfig, *bls.KeySet, map[string]int, error) {
	sorted := append([]model.CommitteeMember(nil), committee...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].ID < sorted[j].ID })
	points := make([]fr.Element, len(sorted))
	for position, member := range sorted {
		points[position] = bls.PointForIdentity(member.ID)
	}
	keys, err := bls.DeriveKeySet(committeeSeed(networkID, epoch), threshold, points)
	if err != nil {
		return model.CommitteeConfig{}, nil, nil, err
	}
	index := make(map[string]int, len(sorted))
	for position, member := range sorted {
		index[member.ID] = position
	}
	config := model.CommitteeConfig{
		Threshold:      uint32(threshold),
		Size:           uint32(len(sorted)),
		GroupPublicKey: append([]byte(nil), keys.GroupPublicKey...),
		CommitteeEpoch: epoch,
	}
	return config, keys, index, nil
}

// committeeSeed derives the BLS master seed from the network identity and the
// committee epoch. v0 keeps this deterministic so any node can rebuild the
// group key without a DKG; a later stage replaces it with a real ceremony.
func committeeSeed(networkID string, epoch uint64) []byte {
	digest := sha256.New()
	digest.Write([]byte("netp2p-bls-committee-v1"))
	var epochBytes [8]byte
	binary.BigEndian.PutUint64(epochBytes[:], epoch)
	digest.Write([]byte(networkID))
	digest.Write([]byte{0})
	digest.Write(epochBytes[:])
	return digest.Sum(nil)
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
	for index := range normalized.Peers {
		normalized.Peers[index].Posture = dedupeSorted(normalized.Peers[index].Posture)
	}
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

func StateHash(state model.NetworkState) []byte {
	message := wire.NetworkStateToProto(NormalizeState(state))
	hash := sha256.Sum256(mustDeterministicMarshal(message))
	return hash[:]
}

// TransitionHash commits a transition into the signed vote. Because the hash is
// covered by each committee member's signature, the certified snapshot's
// transition cannot be altered by a single manager without breaking the QC.
func TransitionHash(transition model.StateTransition) []byte {
	message := wire.StateTransitionToProto(transition)
	hash := sha256.Sum256(mustDeterministicMarshal(message))
	return hash[:]
}

// ClientViewHash hashes the client-visible projection of a proposal. The
// committee signs this value alongside the full state hash, so clients can
// verify redacted snapshots without receiving manager-only secrets.
func ClientViewHash(state model.NetworkState, transition model.StateTransition) []byte {
	client := model.ClientSnapshot(model.SignedSnapshot{State: NormalizeState(state), Transition: transition})
	message := &pb.ClientView{
		State:      wire.NetworkStateToProto(client.State),
		Transition: wire.StateTransitionToProto(client.Transition),
	}
	hash := sha256.Sum256(mustDeterministicMarshal(message))
	return hash[:]
}

// mustDeterministicMarshal encodes a protobuf message with field ordering
// fixed so that identical logical values always hash identically. The wire
// schema avoids map fields precisely so this stays deterministic.
func mustDeterministicMarshal(message proto.Message) []byte {
	encoded, err := proto.MarshalOptions{Deterministic: true}.Marshal(message)
	if err != nil {
		panic(fmt.Sprintf("bft: deterministic marshal failed: %v", err))
	}
	return encoded
}

// voteMessage is the common payload every committee member signs. It excludes
// VoterID so that threshold partial signatures can be aggregated into a single
// group signature.
func voteMessage(vote Vote) []byte {
	message := &pb.Vote{
		Height:         vote.Height,
		Round:          vote.Round,
		NetworkId:      vote.NetworkID,
		StateHash:      vote.StateHash,
		TransitionHash: vote.TransitionHash,
		ClientViewHash: vote.ClientViewHash,
		CommitteeEpoch: vote.CommitteeEpoch,
	}
	return mustDeterministicMarshal(message)
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

// CommitteeEpoch returns the epoch the engine is currently signing under.
func (engine *Engine) CommitteeEpoch() uint64 {
	engine.mu.RLock()
	defer engine.mu.RUnlock()
	return engine.committeeConfig.CommitteeEpoch
}

func (engine *Engine) CurrentState() model.NetworkState {
	engine.mu.RLock()
	defer engine.mu.RUnlock()
	return cloneState(engine.current)
}

func (engine *Engine) Proposal(height uint64) (Proposal, bool) {
	engine.mu.RLock()
	defer engine.mu.RUnlock()
	key := proposalKey{Height: height, Round: engine.currentRound}
	proposal, ok := engine.proposals[key]
	return cloneProposal(proposal), ok
}

// CurrentProposal returns the proposal for the active view. Keeping the
// historical height-only lookup makes mesh catch-up code simple while still
// preventing an old round from masking the current leader's proposal.
func (engine *Engine) CurrentProposal() (Proposal, bool) {
	engine.mu.RLock()
	defer engine.mu.RUnlock()
	key := proposalKey{Height: engine.height + 1, Round: engine.currentRound}
	proposal, ok := engine.proposals[key]
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

// BudgetUsageHistory returns every committed budget settlement in commit order,
// so callers can rebuild per-period usage from the decision log rather than
// trusting a single mutable counter.
func (engine *Engine) BudgetUsageHistory() []model.BudgetUsage {
	engine.mu.RLock()
	defer engine.mu.RUnlock()
	heights := make([]uint64, 0, len(engine.committed))
	for height := range engine.committed {
		heights = append(heights, height)
	}
	sort.Slice(heights, func(i, j int) bool { return heights[i] < heights[j] })
	result := make([]model.BudgetUsage, 0, len(heights))
	for _, height := range heights {
		snapshot := engine.committed[height]
		if snapshot.Transition.Type == TransitionUpdateBudgetUse && snapshot.Transition.BudgetUsage != nil {
			result = append(result, *snapshot.Transition.BudgetUsage)
		}
	}
	return result
}

func proposalFingerprint(proposal Proposal) [3][]byte {
	return [3][]byte{
		StateHash(proposal.State),
		TransitionHash(proposal.Transition),
		ClientViewHash(proposal.State, proposal.Transition),
	}
}

func sameProposal(left, right Proposal) bool {
	leftFingerprint := proposalFingerprint(left)
	rightFingerprint := proposalFingerprint(right)
	for index := range leftFingerprint {
		if !bytes.Equal(leftFingerprint[index], rightFingerprint[index]) {
			return false
		}
	}
	return left.NetworkID == right.NetworkID && left.LeaderID == right.LeaderID
}

func (engine *Engine) clearUncommittedHeightLocked(height uint64) {
	for key := range engine.proposals {
		if key.Height == height {
			delete(engine.proposals, key)
		}
	}
	for key := range engine.votes {
		if key.Height == height {
			delete(engine.votes, key)
		}
	}
}

func (engine *Engine) startRoundLocked(round uint64) {
	engine.currentRound = round
	engine.roundDeadline = time.Now().Add(engine.roundTimeout)
}

func (engine *Engine) expireRoundLocked(height uint64) {
	if height != engine.height+1 || engine.roundDeadline.IsZero() || time.Now().Before(engine.roundDeadline) {
		return
	}
	// Rotating the view on deadline prevents a proposal that never reached
	// quorum from monopolizing the next height. Certified catch-up remains the
	// authority if managers temporarily settle on different local views.
	engine.clearUncommittedHeightLocked(height)
	engine.currentRound++
	engine.roundDeadline = time.Now().Add(engine.roundTimeout)
}

func (engine *Engine) acceptRoundLocked(round uint64) error {
	switch {
	case round < engine.currentRound:
		return fmt.Errorf("stale proposal round %d, current round %d", round, engine.currentRound)
	case round > engine.currentRound+1:
		return fmt.Errorf("proposal round %d skips ahead of current round %d", round, engine.currentRound)
	case round == engine.currentRound+1:
		// A next-round proposal is admissible only after the active view has
		// timed out. Clearing both maps is essential: retaining the old
		// height-only proposal was the liveness bug observed in production.
		if engine.roundDeadline.IsZero() {
			return fmt.Errorf("cannot advance to round %d without an active round-%d proposal", round, engine.currentRound)
		}
		if time.Now().Before(engine.roundDeadline) {
			return fmt.Errorf("proposal round %d arrived before round %d deadline", round, engine.currentRound)
		}
		engine.clearUncommittedHeightLocked(engine.height + 1)
	}
	return nil
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
	engine.currentRound = 0
	engine.startRoundLocked(0)
	engine.committed[snapshot.Height] = snapshot
	engine.clearUncommittedHeightLocked(snapshot.Height)
	// A snapshot may carry a committee change (membership or key rotation); adopt
	// it so this manager can vote at the new epoch.
	if err := engine.adoptCommitteeLocked(snapshot.Transition); err != nil {
		engine.mu.Unlock()
		return err
	}
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

// signVoteShare produces this manager's BLS partial signature over the common
// vote message. The signature is not individually verifiable as a group
// signature; quorum-size partials are aggregated into the QC's group signature.
func (engine *Engine) signVoteShare(vote *Vote) error {
	index, ok := engine.blsIndex[engine.localID]
	if !ok {
		return fmt.Errorf("local manager is not in the BLS committee")
	}
	signature, err := engine.blsKeys.SignShare(index, voteMessage(*vote))
	if err != nil {
		return err
	}
	vote.Signature = signature
	return nil
}

func (engine *Engine) Propose(transition model.StateTransition, round uint64) (Proposal, Vote, error) {
	engine.mu.Lock()
	defer engine.mu.Unlock()
	height := engine.height + 1
	engine.expireRoundLocked(height)
	if err := engine.acceptRoundLocked(round); err != nil {
		return Proposal{}, Vote{}, err
	}
	leader := engine.Leader(height, round)
	if leader.ID != engine.localID {
		return Proposal{}, Vote{}, fmt.Errorf("%w: local=%s leader=%s height=%d", ErrNotLeader, engine.localID, leader.ID, height)
	}
	key := proposalKey{Height: height, Round: round}
	if existing, ok := engine.proposals[key]; ok {
		candidate := existing
		candidate.Transition = transition
		if !sameProposal(existing, candidate) {
			return Proposal{}, Vote{}, fmt.Errorf("conflicting proposal at height %d round %d", height, round)
		}
		for _, vote := range engine.votes[key] {
			if vote.VoterID == engine.localID {
				return existing, vote, nil
			}
		}
		return existing, engine.localVote(existing), nil
	}
	next := cloneState(engine.current)
	next.EngineCommittee = append([]model.CommitteeMember(nil), engine.committee...)
	if err := ApplyTransition(&next, transition); err != nil {
		return Proposal{}, Vote{}, err
	}
	next.EngineCommittee = nil
	proposal := Proposal{Height: height, Round: round, NetworkID: next.NetworkID, State: next, LeaderID: leader.ID, Transition: transition}
	vote := engine.localVote(proposal)
	engine.startRoundLocked(round)
	engine.proposals[key] = proposal
	engine.addVoteLocked(vote)
	return proposal, vote, nil
}

func (engine *Engine) localVote(proposal Proposal) Vote {
	hash := StateHash(proposal.State)
	vote := Vote{
		Height: proposal.Height, Round: proposal.Round, NetworkID: proposal.NetworkID,
		StateHash: hash, TransitionHash: TransitionHash(proposal.Transition), ClientViewHash: ClientViewHash(proposal.State, proposal.Transition),
		VoterID:        engine.localID,
		CommitteeEpoch: engine.committeeConfig.CommitteeEpoch,
	}
	if err := engine.signVoteShare(&vote); err != nil {
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
	engine.expireRoundLocked(proposal.Height)
	if err := engine.acceptRoundLocked(proposal.Round); err != nil {
		return Vote{}, err
	}
	if proposal.LeaderID != engine.Leader(proposal.Height, proposal.Round).ID {
		return Vote{}, ErrUnknownLeader
	}
	key := proposalKey{Height: proposal.Height, Round: proposal.Round}
	if existing, ok := engine.proposals[key]; ok {
		if !sameProposal(existing, proposal) {
			return Vote{}, fmt.Errorf("conflicting proposal at height %d round %d", proposal.Height, proposal.Round)
		}
		for _, vote := range engine.votes[key] {
			if vote.VoterID == engine.localID {
				return vote, nil
			}
		}
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
	engine.startRoundLocked(proposal.Round)
	engine.proposals[key] = proposal
	vote := engine.localVote(proposal)
	engine.addVoteLocked(vote)
	return vote, nil
}

func (engine *Engine) addVoteLocked(vote Vote) {
	key := proposalKey{Height: vote.Height, Round: vote.Round}
	for _, existing := range engine.votes[key] {
		if existing.VoterID == vote.VoterID {
			return
		}
	}
	engine.votes[key] = append(engine.votes[key], vote)
}

func (engine *Engine) ProcessVote(vote Vote) (model.QuorumCertificate, bool, error) {
	engine.mu.Lock()
	defer engine.mu.Unlock()
	shareIndex, ok := engine.blsIndex[vote.VoterID]
	if !ok || !bls.Verify(engine.blsKeys.PublicKeyShare(shareIndex), voteMessage(vote), vote.Signature) {
		return model.QuorumCertificate{}, false, fmt.Errorf("invalid vote signature")
	}
	if vote.CommitteeEpoch != engine.committeeConfig.CommitteeEpoch {
		return model.QuorumCertificate{}, false, fmt.Errorf("vote committee epoch mismatch")
	}
	if vote.Height <= engine.height {
		return model.QuorumCertificate{}, false, ErrStaleHeight
	}
	engine.expireRoundLocked(vote.Height)
	key := proposalKey{Height: vote.Height, Round: vote.Round}
	proposal, ok := engine.proposals[key]
	if !ok || !bytes.Equal(StateHash(proposal.State), vote.StateHash) {
		return model.QuorumCertificate{}, false, fmt.Errorf("vote does not match proposal")
	}
	if vote.Round != proposal.Round || vote.Round != engine.currentRound {
		return model.QuorumCertificate{}, false, fmt.Errorf("vote round %d does not match current proposal round %d", vote.Round, proposal.Round)
	}
	if !bytes.Equal(TransitionHash(proposal.Transition), vote.TransitionHash) {
		return model.QuorumCertificate{}, false, fmt.Errorf("vote does not match transition")
	}
	if !bytes.Equal(ClientViewHash(proposal.State, proposal.Transition), vote.ClientViewHash) {
		return model.QuorumCertificate{}, false, fmt.Errorf("vote does not match client view")
	}
	engine.addVoteLocked(vote)
	if len(engine.votes[key]) < engine.params.QuorumSize {
		return model.QuorumCertificate{}, false, nil
	}
	partials := make(map[int][]byte, len(engine.votes[key]))
	bitmap := make([]byte, (len(engine.committee)+7)/8)
	for _, item := range engine.votes[key] {
		index, ok := engine.blsIndex[item.VoterID]
		if !ok {
			continue
		}
		partials[index] = item.Signature
		bitmap[index/8] |= 1 << uint(index%8)
	}
	if len(partials) < engine.params.QuorumSize {
		return model.QuorumCertificate{}, false, nil
	}
	aggregate, err := engine.blsKeys.Aggregate(partials)
	if err != nil {
		return model.QuorumCertificate{}, false, err
	}
	qc := model.QuorumCertificate{
		Height: vote.Height, Round: vote.Round,
		StateHash: vote.StateHash, TransitionHash: vote.TransitionHash, ClientViewHash: vote.ClientViewHash,
		AggregateSignature: aggregate, SignerBitmap: bitmap,
		CommitteeEpoch: engine.committeeConfig.CommitteeEpoch,
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
		if qc.Round != proposal.Round {
			return ErrInvalidQC
		}
		if !bytes.Equal(qc.TransitionHash, TransitionHash(proposal.Transition)) {
			return ErrInvalidQC
		}
		if !bytes.Equal(qc.ClientViewHash, ClientViewHash(proposal.State, proposal.Transition)) {
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
	engine.currentRound = 0
	engine.startRoundLocked(0)
	// The certificate was produced under the committee and key configuration
	// that were active before this transition applies, so record those on the
	// snapshot and only then adopt the new configuration for later heights.
	signedCommittee := append([]model.CommitteeMember(nil), engine.committee...)
	signedConfig := engine.committeeConfig
	snapshot := model.SignedSnapshot{
		Epoch: proposal.Height, Height: proposal.Height, StateHash: append([]byte(nil), qc.StateHash...),
		State: cloneState(engine.current), Committee: signedCommittee, QC: qc,
		Transition: proposal.Transition, LeaderID: proposal.LeaderID, CommitteeConfig: signedConfig,
	}
	if err := engine.adoptCommitteeLocked(proposal.Transition); err != nil {
		engine.mu.Unlock()
		return model.SignedSnapshot{}, err
	}
	engine.committed[proposal.Height] = snapshot
	engine.clearUncommittedHeightLocked(proposal.Height)
	listeners := make([]func(model.SignedSnapshot), len(engine.listeners))
	copy(listeners, engine.listeners)
	engine.mu.Unlock()
	for _, listener := range listeners {
		listener(snapshot)
	}
	return snapshot, nil
}

// adoptCommitteeLocked applies a membership or key-rotation transition to the
// engine so subsequent heights use the new committee and epoch.
func (engine *Engine) adoptCommitteeLocked(transition model.StateTransition) error {
	if transition.Type != TransitionUpdateCommittee && transition.Type != TransitionRotateCommittee {
		return nil
	}
	committee := append([]model.CommitteeMember(nil), engine.committee...)
	epoch := engine.committeeConfig.CommitteeEpoch
	switch transition.Type {
	case TransitionUpdateCommittee:
		if len(transition.Committee) > 0 {
			committee = append([]model.CommitteeMember(nil), transition.Committee...)
		}
	case TransitionRotateCommittee:
		epoch++
	}
	sort.Slice(committee, func(i, j int) bool { return committee[i].ID < committee[j].ID })
	config, keys, index, err := engine.committeeMaterialLocked(committee, epoch, transition)
	if err != nil {
		return err
	}
	byID := make(map[string]model.CommitteeMember, len(committee))
	for position := range committee {
		committee[position].BLSPublicKey = keys.PublicKeyShare(index[committee[position].ID])
		byID[committee[position].ID] = committee[position]
	}
	engine.committee = committee
	engine.byID = byID
	engine.blsKeys = keys
	engine.blsIndex = index
	engine.committeeConfig = config
	engine.current.CommitteeConfig = config
	return nil
}

// committeeMaterialLocked resolves the key material for a committee change.
// When a rotation carries a DKG-produced group public key, the locally held
// share for that epoch is adopted; otherwise the deterministic seed sharing is
// used so genesis and non-DKG deployments keep working unchanged.
func (engine *Engine) committeeMaterialLocked(committee []model.CommitteeMember, epoch uint64, transition model.StateTransition) (model.CommitteeConfig, *bls.KeySet, map[string]int, error) {
	if transition.Type == TransitionRotateCommittee && transition.CommitteeConfig != nil {
		groupKey := transition.CommitteeConfig.GroupPublicKey
		if len(groupKey) == bls.PublicKeySize && bls.ValidG2Point(groupKey) {
			if engine.dkgLoader != nil {
				if keys, ok := engine.dkgLoader(epoch); ok && bytes.Equal(keys.GroupPublicKey, groupKey) {
					config := model.CommitteeConfig{
						Threshold:      uint32(engine.params.QuorumSize),
						Size:           uint32(engine.params.Size),
						GroupPublicKey: append([]byte(nil), groupKey...), CommitteeEpoch: epoch,
					}
					return config, keys, committeeIndex(committee), nil
				}
			}
			return model.CommitteeConfig{}, nil, nil, fmt.Errorf("rotate_committee_keys carried a DKG group key but no local share is available for epoch %d", epoch)
		}
	}
	return deriveCommitteeKeys(committee, engine.current.NetworkID, epoch, engine.params.QuorumSize)
}

// committeeIndex maps member IDs to their position in the sorted committee.
func committeeIndex(committee []model.CommitteeMember) map[string]int {
	index := make(map[string]int, len(committee))
	for position, member := range committee {
		index[member.ID] = position
	}
	return index
}

// SetDKGLoader installs a source of locally held DKG shares keyed by committee
// epoch. If the engine is already operating under a DKG-derived configuration,
// it immediately switches to the matching local share.
func (engine *Engine) SetDKGLoader(loader func(epoch uint64) (*bls.KeySet, bool)) {
	engine.mu.Lock()
	engine.dkgLoader = loader
	needsLoad := loader != nil && len(engine.committeeConfig.GroupPublicKey) == bls.PublicKeySize
	epoch := engine.committeeConfig.CommitteeEpoch
	groupKey := append([]byte(nil), engine.committeeConfig.GroupPublicKey...)
	committee := append([]model.CommitteeMember(nil), engine.committee...)
	engine.mu.Unlock()
	if !needsLoad {
		return
	}
	// Call the loader without the engine write lock; loaders may inspect public
	// engine state and persisted shares during startup.
	keys, ok := loader(epoch)
	if !ok || !bytes.Equal(keys.GroupPublicKey, groupKey) {
		return
	}
	engine.mu.Lock()
	defer engine.mu.Unlock()
	index := committeeIndex(committee)
	engine.blsKeys = keys
	engine.blsIndex = index
	for position := range committee {
		committee[position].BLSPublicKey = keys.PublicKeyShare(index[committee[position].ID])
		engine.byID[committee[position].ID] = committee[position]
	}
	engine.committee = committee
}

func (engine *Engine) verifyQCLocked(qc model.QuorumCertificate) error {
	if qc.CommitteeEpoch != engine.committeeConfig.CommitteeEpoch {
		return ErrInvalidQC
	}
	signers, err := countSigners(qc.SignerBitmap, len(engine.committee))
	if err != nil {
		return ErrInvalidQC
	}
	if signers < engine.params.QuorumSize {
		return ErrInvalidQC
	}
	vote := Vote{
		Height: qc.Height, Round: qc.Round, NetworkID: engine.current.NetworkID,
		StateHash: qc.StateHash, TransitionHash: qc.TransitionHash, ClientViewHash: qc.ClientViewHash,
		CommitteeEpoch: qc.CommitteeEpoch,
	}
	if !bls.Verify(engine.committeeConfig.GroupPublicKey, voteMessage(vote), qc.AggregateSignature) {
		return ErrInvalidQC
	}
	return nil
}

func countSigners(bitmap []byte, committeeSize int) (int, error) {
	if committeeSize < 1 {
		return 0, fmt.Errorf("committee size must be positive")
	}
	expectedBytes := (committeeSize + 7) / 8
	if len(bitmap) != expectedBytes {
		return 0, fmt.Errorf("signer bitmap has %d bytes, want %d", len(bitmap), expectedBytes)
	}
	count := 0
	for bit := 0; bit < committeeSize; bit++ {
		if bitmap[bit/8]&(1<<uint(bit%8)) != 0 {
			count++
		}
	}
	for bit := committeeSize; bit < len(bitmap)*8; bit++ {
		if bitmap[bit/8]&(1<<uint(bit%8)) != 0 {
			return 0, fmt.Errorf("signer bit %d is outside the committee", bit)
		}
	}
	return count, nil
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
		posture, err := sanitizePosture(transition.Peer.Posture)
		if err != nil {
			return err
		}
		address, err := allocateAddress(*state)
		if err != nil {
			return err
		}
		peer := transition.Peer
		peer.OverlayIP = address
		peer.IsExitNode = false
		peer.Posture = posture
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
		if err := validateRoute(*state, *transition.Route); err != nil {
			return err
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
		if len(transition.Record.TokenHash) == 0 {
			return fmt.Errorf("setup key requires a token verifier")
		}
		if transition.Record.Token != "" {
			transition.Record.Token = ""
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
			// Metadata fields are optional in a partial update (for example an
			// admin action that only toggles the exit-node flag); only apply
			// the ones the caller actually supplied.
			if transition.Peer.Hostname != "" {
				state.Peers[index].Hostname = transition.Peer.Hostname
			}
			if transition.Peer.OS != "" {
				state.Peers[index].OS = transition.Peer.OS
			}
			if transition.Peer.ClientVersion != "" {
				state.Peers[index].ClientVersion = transition.Peer.ClientVersion
			}
			if transition.Peer.UserID != "" {
				if findUser(*state, transition.Peer.UserID) == nil {
					return fmt.Errorf("unknown user %q", transition.Peer.UserID)
				}
				state.Peers[index].UserID = transition.Peer.UserID
			}
			if transition.Peer.LastLogin != "" {
				state.Peers[index].LastLogin = transition.Peer.LastLogin
			}
			// Posture is nullable: a nil slice leaves the certified labels
			// untouched so a routine metadata refresh cannot clear them, while
			// an explicit (even empty) list replaces them.
			if transition.Peer.Posture != nil {
				posture, err := sanitizePosture(transition.Peer.Posture)
				if err != nil {
					return err
				}
				state.Peers[index].Posture = posture
			}
			state.Peers[index].IsExitNode = transition.Peer.IsExitNode
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
		if assignment.MaxHops <= 0 {
			assignment.MaxHops = len(assignment.Primary.ManagerHops)
		}
		if len(assignment.Primary.ManagerHops) > assignment.MaxHops {
			return fmt.Errorf("primary path exceeds the assignment hop limit")
		}
		if assignment.Primary.Kind == model.PathKindViaManager || assignment.Primary.Kind == model.PathKindMultiHop {
			if err := validateManagerPath(engineCommittee, assignment.Primary); err != nil {
				return err
			}
		}
		for index := range assignment.Fallbacks {
			assignment.Fallbacks[index] = assignment.Fallbacks[index].Normalized()
			if len(assignment.Fallbacks[index].ManagerHops) > assignment.MaxHops {
				return fmt.Errorf("fallback path exceeds the assignment hop limit")
			}
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
	case TransitionUpdateCommittee:
		return applyUpdateCommittee(state, transition)
	case TransitionRotateCommittee:
		return applyRotateCommitteeKeys(state, transition)
	case TransitionUpdateBudgetUse:
		return applyBudgetUsage(state, transition)
	default:
		return fmt.Errorf("unknown transition type %q", transition.Type)
	}
}

// applyBudgetUsage settles aggregated client usage into certified state. The
// transition carries absolute counters so every voter derives an identical
// result; the daily/monthly reset is decided by the proposing manager.
func applyBudgetUsage(state *model.NetworkState, transition model.StateTransition) error {
	usage := transition.BudgetUsage
	if usage == nil || usage.BudgetID == "" {
		return fmt.Errorf("budget usage is required")
	}
	for index := range state.Budgets {
		if state.Budgets[index].ID != usage.BudgetID {
			continue
		}
		state.Budgets[index].UsedDailyBytes = usage.DailyBytes
		state.Budgets[index].UsedMonthlyBytes = usage.MonthlyBytes
		if usage.PeriodDay != "" {
			if parsed, err := time.Parse("2006-01-02", usage.PeriodDay); err == nil {
				state.Budgets[index].UpdatedAt = parsed.UTC()
			}
		}
		return nil
	}
	return fmt.Errorf("budget %q not found", usage.BudgetID)
}

func committeeParamsForState(state model.NetworkState) (model.CommitteeParams, error) {
	return model.CommitteeParamsFromConfig(state.CommitteeConfig)
}

// applyUpdateCommittee validates and stages a committee member change. The
// effective committee is carried on the runtime-only EngineCommittee field and
// adopted by the engine at commit time.
func applyUpdateCommittee(state *model.NetworkState, transition model.StateTransition) error {
	next := transition.Committee
	params, err := committeeParamsForState(*state)
	if err != nil {
		return fmt.Errorf("invalid committee params: %w", err)
	}
	if len(next) != params.Size {
		return fmt.Errorf("committee size must remain %d", params.Size)
	}
	if len(state.EngineCommittee) != params.Size {
		return fmt.Errorf("committee context is required to replace members")
	}
	seen := make(map[string]struct{}, len(next))
	for _, member := range next {
		if member.ID == "" {
			return fmt.Errorf("committee member id is required")
		}
		if member.PeerID == "" {
			return fmt.Errorf("committee member %q is missing a peer id", member.ID)
		}
		if member.Address == "" {
			return fmt.Errorf("committee member %q is missing an address", member.ID)
		}
		if _, duplicate := seen[member.ID]; duplicate {
			return fmt.Errorf("duplicate committee member %q", member.ID)
		}
		seen[member.ID] = struct{}{}
	}
	forwarding := 0
	for _, member := range next {
		if member.ForwardingEnabled {
			forwarding++
		}
	}
	if forwarding == 0 {
		return fmt.Errorf("committee must keep at least one forwarding member")
	}
	// The seed committee parameters bound how many members may change at once.
	replaced := 0
	current := make(map[string]struct{}, len(state.EngineCommittee))
	for _, member := range state.EngineCommittee {
		current[member.ID] = struct{}{}
	}
	for _, member := range next {
		if _, known := current[member.ID]; !known {
			replaced++
		}
	}
	if replaced > params.FaultLimit {
		return fmt.Errorf("at most %d committee members may be replaced at once", params.FaultLimit)
	}
	state.EngineCommittee = append([]model.CommitteeMember(nil), next...)
	return nil
}

// applyRotateCommitteeKeys bumps the committee epoch. It adopts a DKG-produced
// group public key when the transition carries one, otherwise it deterministically
// regenerates every share and the group public key from the committee seed.
func applyRotateCommitteeKeys(state *model.NetworkState, transition model.StateTransition) error {
	params, err := committeeParamsForState(*state)
	if err != nil {
		return fmt.Errorf("invalid committee params: %w", err)
	}
	if len(state.EngineCommittee) != params.Size {
		return fmt.Errorf("committee context is required to rotate keys")
	}
	epoch := state.CommitteeConfig.CommitteeEpoch + 1
	if transition.CommitteeConfig != nil && len(transition.CommitteeConfig.GroupPublicKey) > 0 {
		if !bls.ValidG2Point(transition.CommitteeConfig.GroupPublicKey) {
			return fmt.Errorf("rotate_committee_keys group public key is not a valid G2 point")
		}
		state.CommitteeConfig = params.CommitteeConfig(epoch, transition.CommitteeConfig.GroupPublicKey)
		return nil
	}
	config, _, _, err := deriveCommitteeKeys(state.EngineCommittee, state.NetworkID, epoch, params.QuorumSize)
	if err != nil {
		return err
	}
	state.CommitteeConfig = config
	return nil
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

func validateRoute(state model.NetworkState, route model.Route) error {
	if route.Destination == "" {
		return fmt.Errorf("route destination is required")
	}
	prefix, err := netip.ParsePrefix(route.Destination)
	if err != nil {
		return fmt.Errorf("route destination %q is not an IPv4 CIDR: %w", route.Destination, err)
	}
	if prefix.Addr().Is4() == false {
		return fmt.Errorf("route destination %q must be IPv4", route.Destination)
	}
	if prefix.Bits() < 0 || prefix.Bits() > 32 {
		return fmt.Errorf("route destination %q has an invalid prefix length", route.Destination)
	}
	if route.RoutingGroup == "" {
		return fmt.Errorf("route routing group is required")
	}
	if err := requireGroups(&state, append([]string{route.RoutingGroup}, route.DistributionGroup...)); err != nil {
		return err
	}
	hasExitNode := false
	for _, peer := range state.Peers {
		if !peer.IsExitNode || !groupContainsPeer(state.Groups, route.RoutingGroup, peer.PeerID) {
			continue
		}
		hasExitNode = true
		break
	}
	if !hasExitNode {
		return fmt.Errorf("routing group %q has no exit-node peer", route.RoutingGroup)
	}
	if route.Metric < 0 {
		return fmt.Errorf("route metric cannot be negative")
	}
	if route.MaxHops < 0 {
		return fmt.Errorf("route max hops cannot be negative")
	}
	for _, pathType := range route.AllowedPathTypes {
		switch pathType {
		case "direct", "via_manager", "multi-hop":
		default:
			return fmt.Errorf("route allowed path type %q is unknown", pathType)
		}
	}
	switch route.FlowClass {
	case "", "latency", "throughput", "reliability", "cost":
	default:
		return fmt.Errorf("route flow class %q is unknown", route.FlowClass)
	}
	return nil
}

func groupContainsPeer(groups []model.Group, groupID, peerID string) bool {
	for _, group := range groups {
		if group.ID != groupID {
			continue
		}
		for _, member := range group.PeerIDs {
			if member == peerID {
				return true
			}
		}
	}
	return false
}

func validateManagerPath(committee []model.CommitteeMember, path model.PathSpec) error {
	if len(path.ManagerHops) == 0 {
		return fmt.Errorf("via-manager path requires at least one manager hop")
	}
	seen := make(map[string]struct{}, len(path.ManagerHops))
	for _, hop := range path.ManagerHops {
		if _, duplicate := seen[hop]; duplicate {
			return fmt.Errorf("manager hop %q repeats", hop)
		}
		seen[hop] = struct{}{}
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
	hash := model.SetupKeyHash(token)
	for index := range state.SetupKeys {
		// Constant-time comparison so token lookups do not leak hash prefixes.
		if hmac.Equal(state.SetupKeys[index].TokenHash, hash) {
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
// maxPostureLabels bounds the declared posture so a peer cannot bloat certified
// state with an unbounded label list.
const maxPostureLabels = 32

// sanitizePosture trims, rejects empties, dedupes and sorts declared posture
// labels. It returns an error for blank or oversized input so a malformed
// registration is rejected rather than silently truncated.
func sanitizePosture(values []string) ([]string, error) {
	if len(values) > maxPostureLabels {
		return nil, fmt.Errorf("posture has %d labels, maximum is %d", len(values), maxPostureLabels)
	}
	if len(values) == 0 {
		return []string{}, nil
	}
	seen := make(map[string]struct{}, len(values))
	result := make([]string, 0, len(values))
	for _, value := range values {
		label := strings.TrimSpace(value)
		if label == "" {
			return nil, fmt.Errorf("posture labels must not be empty")
		}
		if _, exists := seen[label]; exists {
			continue
		}
		seen[label] = struct{}{}
		result = append(result, label)
	}
	sort.Strings(result)
	return result, nil
}

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
	config := snapshot.CommitteeConfig
	params, err := model.CommitteeParamsFromConfig(config)
	if err != nil {
		return ErrInvalidQC
	}
	if len(snapshot.Committee) != params.Size {
		return ErrInvalidQC
	}
	if !config.Equal(snapshot.State.CommitteeConfig) {
		return ErrInvalidQC
	}
	if len(config.GroupPublicKey) == 0 || !bls.ValidG2Point(config.GroupPublicKey) {
		return ErrInvalidQC
	}
	if config.Threshold != uint32(params.QuorumSize) {
		return ErrInvalidQC
	}
	if !bytes.Equal(snapshot.StateHash, StateHash(snapshot.State)) {
		return fmt.Errorf("snapshot state hash mismatch")
	}
	qc := snapshot.QC
	if len(qc.ClientViewHash) == 0 || !bytes.Equal(qc.ClientViewHash, ClientViewHash(snapshot.State, snapshot.Transition)) {
		return ErrInvalidQC
	}
	if qc.Height != snapshot.Height {
		return ErrInvalidQC
	}
	if !bytes.Equal(qc.StateHash, snapshot.StateHash) {
		return ErrInvalidQC
	}
	if qc.CommitteeEpoch != config.CommitteeEpoch {
		return fmt.Errorf("snapshot committee epoch mismatch")
	}
	signers, err := countSigners(qc.SignerBitmap, params.Size)
	if err != nil {
		return ErrInvalidQC
	}
	if signers < params.QuorumSize {
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
	vote := Vote{
		Height: qc.Height, Round: qc.Round, NetworkID: snapshot.State.NetworkID,
		StateHash: qc.StateHash, TransitionHash: qc.TransitionHash, ClientViewHash: qc.ClientViewHash,
		CommitteeEpoch: qc.CommitteeEpoch,
	}
	if !bls.Verify(config.GroupPublicKey, voteMessage(vote), qc.AggregateSignature) {
		return ErrInvalidQC
	}
	return nil
}

// ValidateClientSnapshot validates a manager-redacted snapshot. Managers still
// validate the full state hash, while clients verify the committee-signed hash
// of the client-visible projection.
func ValidateClientSnapshot(snapshot model.SignedSnapshot) error {
	config := snapshot.CommitteeConfig
	params, err := model.CommitteeParamsFromConfig(config)
	if err != nil {
		return ErrInvalidQC
	}
	if len(snapshot.Committee) != params.Size {
		return ErrInvalidQC
	}
	if !config.Equal(snapshot.State.CommitteeConfig) {
		return ErrInvalidQC
	}
	if len(config.GroupPublicKey) == 0 || !bls.ValidG2Point(config.GroupPublicKey) {
		return ErrInvalidQC
	}
	if config.Threshold != uint32(params.QuorumSize) {
		return ErrInvalidQC
	}
	qc := snapshot.QC
	if len(qc.ClientViewHash) == 0 || !bytes.Equal(qc.ClientViewHash, ClientViewHash(snapshot.State, snapshot.Transition)) {
		return ErrInvalidQC
	}
	if qc.Height != snapshot.Height {
		return ErrInvalidQC
	}
	if len(snapshot.StateHash) == 0 || !bytes.Equal(qc.StateHash, snapshot.StateHash) {
		return ErrInvalidQC
	}
	if qc.CommitteeEpoch != config.CommitteeEpoch {
		return fmt.Errorf("snapshot committee epoch mismatch")
	}
	signers, err := countSigners(qc.SignerBitmap, params.Size)
	if err != nil {
		return ErrInvalidQC
	}
	if signers < params.QuorumSize {
		return ErrInvalidQC
	}
	if snapshot.LeaderID == "" || snapshot.LeaderID != leaderIDFor(snapshot.Committee, snapshot.Height, qc.Round) {
		return fmt.Errorf("snapshot leader mismatch")
	}
	vote := Vote{
		Height: qc.Height, Round: qc.Round, NetworkID: snapshot.State.NetworkID,
		StateHash: qc.StateHash, TransitionHash: qc.TransitionHash, ClientViewHash: qc.ClientViewHash,
		CommitteeEpoch: qc.CommitteeEpoch,
	}
	if !bls.Verify(config.GroupPublicKey, voteMessage(vote), qc.AggregateSignature) {
		return ErrInvalidQC
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
