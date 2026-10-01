// Package dkg runs a Pedersen distributed key generation ceremony between the
// committee managers. The ceremony is opt-in: genesis keys stay deterministic
// from the seed, and only a rotation can switch the committee to a
// DKG-derived group key. Each member persists its own share locally; nothing
// secret is ever certified.
package dkg

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"

	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/netp2p/netp2p/internal/crypto/bls"
	"github.com/netp2p/netp2p/internal/p2p"
)

// ErrCeremony is returned for protocol-level ceremony failures.
var ErrCeremony = errors.New("dkg: ceremony failed")

// Member identifies one committee participant. Members are sorted by ID before
// the ceremony so every node derives the same evaluation points.
type Member struct {
	ID     string
	PeerID peer.ID
}

// Config describes a ceremony.
type Config struct {
	CeremonyID string
	Threshold  int
	Members    []Member
	LocalID    string
}

// Ceremony holds the local state for one DKG run. Create it, register Handle on
// the node, then call Run on every member.
type Ceremony struct {
	node       *p2p.Node
	config     Config
	points     []fr.Element
	localIndex int

	mu    sync.Mutex
	state *bls.DKGState

	groupKeys map[int][]byte
	saved     bool
}

// New builds a ceremony. The members are sorted by ID to fix the evaluation
// point order.
func New(node *p2p.Node, config Config) (*Ceremony, error) {
	if node == nil {
		return nil, fmt.Errorf("%w: node is required", ErrCeremony)
	}
	if len(config.Members) == 0 || config.Threshold < 1 || config.Threshold > len(config.Members) {
		return nil, fmt.Errorf("%w: invalid threshold parameters", ErrCeremony)
	}
	members := append([]Member(nil), config.Members...)
	sort.Slice(members, func(i, j int) bool { return members[i].ID < members[j].ID })
	config.Members = members
	points := make([]fr.Element, len(members))
	localIndex := -1
	for index, member := range members {
		points[index] = bls.PointForIdentity(member.ID)
		if member.ID == config.LocalID {
			localIndex = index
		}
	}
	if localIndex < 0 {
		return nil, fmt.Errorf("%w: local member %q is not in the committee", ErrCeremony, config.LocalID)
	}
	state, err := bls.NewDKGState(config.Threshold, len(members), localIndex, points, nil)
	if err != nil {
		return nil, err
	}
	return &Ceremony{
		node: node, config: config, points: points, localIndex: localIndex,
		state: state, groupKeys: make(map[int][]byte),
	}, nil
}

type wireMessage struct {
	Kind           string   `json:"kind"`
	Ceremony       string   `json:"ceremony"`
	From           string   `json:"from"`
	Commitments    [][]byte `json:"commitments,omitempty"`
	Share          []byte   `json:"share,omitempty"`
	GroupPublicKey []byte   `json:"groupPublicKey,omitempty"`
	Ready          bool     `json:"ready,omitempty"`
}

// Handle serves an inbound ceremony exchange.
func (ceremony *Ceremony) Handle(stream network.Stream) {
	defer stream.Close()
	envelope, err := p2p.DecodeEnvelope(stream)
	if err != nil {
		return
	}
	var message wireMessage
	if err := json.Unmarshal(envelope.Payload, &message); err != nil {
		return
	}
	if message.Ceremony != ceremony.config.CeremonyID {
		return
	}
	dealer, ok := ceremony.indexByPeer(stream.Conn().RemotePeer())
	if !ok || ceremony.config.Members[dealer].ID != message.From {
		return
	}
	response, err := ceremony.respond(dealer, message)
	if err != nil {
		return
	}
	payload, err := json.Marshal(response)
	if err != nil {
		return
	}
	_ = p2p.EncodeEnvelope(stream, p2p.DKGProtocol, payload)
}

func (ceremony *Ceremony) respond(dealer int, message wireMessage) (wireMessage, error) {
	ceremony.mu.Lock()
	defer ceremony.mu.Unlock()
	switch message.Kind {
	case "commit":
		if len(message.Commitments) != ceremony.config.Threshold {
			return wireMessage{}, fmt.Errorf("%w: wrong commitment count", ErrCeremony)
		}
		if err := ceremony.state.AddCommitments(dealer, message.Commitments); err != nil {
			return wireMessage{}, err
		}
		return ceremony.response("commit", ceremony.state.Commitments(), nil), nil
	case "share":
		share, err := bls.ShareFromBytes(message.Share)
		if err != nil {
			return wireMessage{}, err
		}
		if err := ceremony.state.AddShare(dealer, share); err != nil {
			return wireMessage{}, err
		}
		ourShare, err := ceremony.state.ShareFor(dealer)
		if err != nil {
			return wireMessage{}, err
		}
		return ceremony.response("share", nil, bls.ShareBytes(ourShare)), nil
	case "finalize":
		if len(message.GroupPublicKey) > 0 {
			ceremony.groupKeys[dealer] = append([]byte(nil), message.GroupPublicKey...)
		}
		return ceremony.response("finalize", nil, nil), nil
	case "ready":
		response := ceremony.response("ready", nil, nil)
		response.Ready = ceremony.saved
		return response, nil
	default:
		return wireMessage{}, fmt.Errorf("%w: unknown message kind %q", ErrCeremony, message.Kind)
	}
}

func (ceremony *Ceremony) response(kind string, commitments [][]byte, share []byte) wireMessage {
	return wireMessage{Kind: kind, Ceremony: ceremony.config.CeremonyID, From: ceremony.config.LocalID, Commitments: commitments, Share: share}
}

// Run performs the ceremony and returns the local result. It is safe to call
// once; it must be called on every member (each member also serves the others
// through Handle).
func (ceremony *Ceremony) Run(ctx context.Context) (*bls.DKGResult, error) {
	ceremony.mu.Lock()
	if err := ceremony.state.AddCommitments(ceremony.localIndex, ceremony.state.Commitments()); err != nil {
		ceremony.mu.Unlock()
		return nil, err
	}
	ownShare, err := ceremony.state.ShareFor(ceremony.localIndex)
	if err != nil {
		ceremony.mu.Unlock()
		return nil, err
	}
	if err := ceremony.state.AddShare(ceremony.localIndex, ownShare); err != nil {
		ceremony.mu.Unlock()
		return nil, err
	}
	ceremony.mu.Unlock()

	// Round one: exchange commitments with every other member.
	for index, member := range ceremony.config.Members {
		if index == ceremony.localIndex {
			continue
		}
		ceremony.mu.Lock()
		commitments := ceremony.state.Commitments()
		ceremony.mu.Unlock()
		response, err := ceremony.exchange(ctx, member.PeerID, wireMessage{
			Kind: "commit", Ceremony: ceremony.config.CeremonyID, From: ceremony.config.LocalID, Commitments: commitments,
		})
		if err != nil {
			return nil, fmt.Errorf("%w: commit exchange with %s: %v", ErrCeremony, member.ID, err)
		}
		if len(response.Commitments) != ceremony.config.Threshold {
			return nil, fmt.Errorf("%w: member %s returned %d commitments", ErrCeremony, member.ID, len(response.Commitments))
		}
		ceremony.mu.Lock()
		err = ceremony.state.AddCommitments(index, response.Commitments)
		ceremony.mu.Unlock()
		if err != nil {
			return nil, err
		}
	}

	// Round two: exchange shares.
	for index, member := range ceremony.config.Members {
		if index == ceremony.localIndex {
			continue
		}
		ceremony.mu.Lock()
		share, err := ceremony.state.ShareFor(index)
		ceremony.mu.Unlock()
		if err != nil {
			return nil, err
		}
		response, err := ceremony.exchange(ctx, member.PeerID, wireMessage{
			Kind: "share", Ceremony: ceremony.config.CeremonyID, From: ceremony.config.LocalID, Share: bls.ShareBytes(share),
		})
		if err != nil {
			return nil, fmt.Errorf("%w: share exchange with %s: %v", ErrCeremony, member.ID, err)
		}
		theirShare, err := bls.ShareFromBytes(response.Share)
		if err != nil {
			return nil, err
		}
		ceremony.mu.Lock()
		err = ceremony.state.AddShare(index, theirShare)
		ceremony.mu.Unlock()
		if err != nil {
			return nil, err
		}
	}

	ceremony.mu.Lock()
	result, err := ceremony.state.Finalize()
	ceremony.mu.Unlock()
	if err != nil {
		return nil, err
	}

	// Round three: broadcast the group key and verify everyone agrees.
	for index, member := range ceremony.config.Members {
		if index == ceremony.localIndex {
			continue
		}
		response, err := ceremony.exchange(ctx, member.PeerID, wireMessage{
			Kind: "finalize", Ceremony: ceremony.config.CeremonyID, From: ceremony.config.LocalID, GroupPublicKey: result.GroupPublicKey,
		})
		if err != nil {
			return nil, fmt.Errorf("%w: finalize exchange with %s: %v", ErrCeremony, member.ID, err)
		}
		if len(response.GroupPublicKey) > 0 && !bytes.Equal(response.GroupPublicKey, result.GroupPublicKey) {
			return nil, fmt.Errorf("%w: member %s computed a different group key", ErrCeremony, member.ID)
		}
	}
	return result, nil
}

func (ceremony *Ceremony) exchange(ctx context.Context, peerID peer.ID, request wireMessage) (wireMessage, error) {
	exchangeContext, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	stream, err := ceremony.node.Host.NewStream(exchangeContext, peerID, p2p.DKGProtocol)
	if err != nil {
		return wireMessage{}, err
	}
	defer stream.Close()
	payload, err := json.Marshal(request)
	if err != nil {
		return wireMessage{}, err
	}
	if err := p2p.EncodeEnvelope(stream, p2p.DKGProtocol, payload); err != nil {
		return wireMessage{}, err
	}
	if closeWriter, ok := stream.(interface{ CloseWrite() error }); ok {
		_ = closeWriter.CloseWrite()
	}
	envelope, err := p2p.DecodeEnvelope(stream)
	if err != nil {
		return wireMessage{}, err
	}
	var response wireMessage
	if err := json.Unmarshal(envelope.Payload, &response); err != nil {
		return wireMessage{}, err
	}
	if response.Kind != request.Kind {
		return wireMessage{}, fmt.Errorf("%w: unexpected response kind %q", ErrCeremony, response.Kind)
	}
	return response, nil
}

// MarkSaved records that this member has persisted its share, which unblocks
// the readiness barrier.
func (ceremony *Ceremony) MarkSaved() {
	ceremony.mu.Lock()
	ceremony.saved = true
	ceremony.mu.Unlock()
}

// WaitAll blocks until every other member reports that it has saved its share
// for the epoch. It is the barrier that keeps a leader from committing a
// rotation before the whole committee can sign under the new keys.
func (ceremony *Ceremony) WaitAll(ctx context.Context) error {
	deadline := time.Now().Add(30 * time.Second)
	for {
		pending := 0
		for index, member := range ceremony.config.Members {
			if index == ceremony.localIndex {
				continue
			}
			response, err := ceremony.exchange(ctx, member.PeerID, wireMessage{
				Kind: "ready", Ceremony: ceremony.config.CeremonyID, From: ceremony.config.LocalID,
			})
			if err != nil || !response.Ready {
				pending++
			}
		}
		if pending == 0 {
			return nil
		}
		if time.Now().After(deadline) || ctx.Err() != nil {
			return fmt.Errorf("%w: %d members were not ready to persist their share", ErrCeremony, pending)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(500 * time.Millisecond):
		}
	}
}

func (ceremony *Ceremony) indexByPeer(peerID peer.ID) (int, bool) {
	for index, member := range ceremony.config.Members {
		if member.PeerID == peerID {
			return index, true
		}
	}
	return 0, false
}

// ShareFile is the on-disk representation of a member's DKG share. Only public
// material and the member's own secret share are stored.
type ShareFile struct {
	Version        int      `json:"version"`
	MemberID       string   `json:"memberID"`
	Epoch          uint64   `json:"epoch"`
	Threshold      int      `json:"threshold"`
	Size           int      `json:"size"`
	GroupPublicKey []byte   `json:"groupPublicKey"`
	Share          []byte   `json:"share"`
	SharePublics   [][]byte `json:"sharePublics"`
}

// SharePath is the conventional file name for a member's share at an epoch.
func SharePath(dir string, epoch uint64) string {
	return filepath.Join(dir, fmt.Sprintf("dkg-share-%d.json", epoch))
}

// SaveShare atomically writes a member's share for an epoch.
func SaveShare(dir string, epoch uint64, memberID string, threshold, size int, result *bls.DKGResult) error {
	if result == nil {
		return fmt.Errorf("%w: nil result", ErrCeremony)
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	file := ShareFile{
		Version: 1, MemberID: memberID, Epoch: epoch,
		Threshold: threshold, Size: size,
		GroupPublicKey: result.GroupPublicKey, Share: bls.ShareBytes(result.Share),
		SharePublics: result.SharePublics,
	}
	payload, err := json.Marshal(file)
	if err != nil {
		return err
	}
	path := SharePath(dir, epoch)
	temporary := path + ".tmp"
	if err := os.WriteFile(temporary, payload, 0o600); err != nil {
		return err
	}
	return os.Rename(temporary, path)
}

// LoadShare rebuilds a KeySet from a member's persisted share for an epoch. The
// memberIDs are the certified committee members; they fix the evaluation points.
func LoadShare(dir string, epoch uint64, memberID string, memberIDs []string, threshold int) (*bls.KeySet, bool) {
	payload, err := os.ReadFile(SharePath(dir, epoch))
	if err != nil {
		return nil, false
	}
	var file ShareFile
	if err := json.Unmarshal(payload, &file); err != nil {
		return nil, false
	}
	if file.MemberID != memberID || len(file.SharePublics) != len(memberIDs) {
		return nil, false
	}
	sorted := append([]string(nil), memberIDs...)
	sort.Strings(sorted)
	points := make([]fr.Element, len(sorted))
	localIndex := -1
	for index, id := range sorted {
		points[index] = bls.PointForIdentity(id)
		if id == memberID {
			localIndex = index
		}
	}
	if localIndex < 0 {
		return nil, false
	}
	share, err := bls.ShareFromBytes(file.Share)
	if err != nil {
		return nil, false
	}
	thresholdValue := file.Threshold
	if thresholdValue <= 0 {
		thresholdValue = threshold
	}
	if thresholdValue < 1 || thresholdValue > len(sorted) {
		return nil, false
	}
	keySet, err := bls.NewKeySetFromShares(thresholdValue, len(sorted), points, localIndex, share, file.SharePublics, file.GroupPublicKey)
	if err != nil {
		return nil, false
	}
	return keySet, true
}

// CeremonyID derives a stable identifier so members agree on the run.
func CeremonyID(networkID string, epoch uint64, memberIDs []string) string {
	digest := sha256.New()
	digest.Write([]byte("netp2p-dkg-ceremony-v1"))
	digest.Write([]byte{0})
	digest.Write([]byte(networkID))
	digest.Write([]byte{0})
	var epochBytes [8]byte
	for index := 7; index >= 0; index-- {
		epochBytes[index] = byte(epoch)
		epoch >>= 8
	}
	digest.Write(epochBytes[:])
	ordered := append([]string(nil), memberIDs...)
	sort.Strings(ordered)
	for _, id := range ordered {
		digest.Write([]byte{0})
		digest.Write([]byte(id))
	}
	return fmt.Sprintf("%x", digest.Sum(nil))
}
