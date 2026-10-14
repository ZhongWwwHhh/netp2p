package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sort"
	"time"

	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/netp2p/netp2p/internal/bft"
	"github.com/netp2p/netp2p/internal/config"
	"github.com/netp2p/netp2p/internal/crypto/bls"
	"github.com/netp2p/netp2p/internal/dkg"
	"github.com/netp2p/netp2p/internal/manager"
	"github.com/netp2p/netp2p/internal/model"
	"github.com/netp2p/netp2p/internal/p2p"
	"github.com/netp2p/netp2p/internal/version"
)

type committeeResizeWatcher struct {
	node          *p2p.Node
	engine        *bft.Engine
	mesh          *manager.CommitteeMesh
	localID       string
	dataDir       string
	networkID     string
	ceremony      *dkg.Ceremony
	ceremonyID    string
	ceremonyEpoch uint64
	failedEpoch   uint64
}

func runCommitteeResizeWatcher(ctx context.Context, watcher committeeResizeWatcher) {
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
		watcher.runOnce(ctx)
	}
}

func (watcher *committeeResizeWatcher) runOnce(ctx context.Context) {
	state := watcher.engine.CurrentState()
	target, changed := watcher.targetCommittee(state)
	if !changed {
		return
	}
	if len(state.PendingCommitteeShrink) > 0 && !committeeContainsManager(target, watcher.localID) {
		return
	}
	params, err := model.CommitteeParamsForSize(len(target))
	if err != nil {
		log.Printf("committee resize target invalid: %v", err)
		return
	}
	if !committeeQuorumAvailable(watcher.node, watcher.mesh, watcher.engine.CommitteeParams()) {
		return
	}
	if err := watcher.connectCandidates(target); err != nil {
		log.Printf("committee resize connect incomplete: %v", err)
		return
	}
	epoch := watcher.engine.CommitteeEpoch() + 1
	keys, err := watcher.ensureCommitteeShare(ctx, target, params, epoch)
	if err != nil {
		log.Printf("committee resize DKG incomplete: %v", err)
		return
	}
	// Submit forwards to the current leader. During a shrink that leader can
	// be a manager being removed, so retained managers must not self-select.
	config := params.CommitteeConfig(epoch, keys.GroupPublicKey)
	transition := model.StateTransition{
		Type:            bft.TransitionActivateCommittee,
		Committee:       target,
		CommitteeConfig: &config,
		Actor:           &model.Actor{ID: "system:committee-resize", Role: "system"},
	}
	if _, err := watcher.mesh.Submit(transition); err != nil {
		log.Printf("submit committee activation: %v", err)
	}
}

func (watcher *committeeResizeWatcher) targetCommittee(state model.NetworkState) ([]model.CommitteeMember, bool) {
	current := watcher.engine.CommitteeMembers()
	target, changed := targetCommitteeFromState(state, current)
	return target, changed
}

func targetCommitteeFromState(state model.NetworkState, current []model.CommitteeMember) ([]model.CommitteeMember, bool) {
	if len(state.PendingCommitteeShrink) > 0 {
		return append([]model.CommitteeMember(nil), state.PendingCommitteeShrink...), true
	}
	target := append([]model.CommitteeMember(nil), current...)
	known := make(map[string]struct{}, len(current))
	for _, member := range target {
		known[member.ID] = struct{}{}
	}
	changed := false
	for _, request := range state.ManagerJoins {
		if request.Status != model.ManagerJoinApproved {
			continue
		}
		if _, exists := known[request.ManagerID]; exists {
			continue
		}
		target = append(target, managerJoinCommitteeMember(request))
		known[request.ManagerID] = struct{}{}
		changed = true
	}
	sort.Slice(target, func(i, j int) bool { return target[i].ID < target[j].ID })
	return target, changed
}

func managerJoinCommitteeMember(request model.ManagerJoinRequest) model.CommitteeMember {
	return model.CommitteeMember{
		ID: request.ManagerID, PeerID: request.PeerID, Address: request.Address,
		PublicKey: append([]byte(nil), request.PublicKey...), ListenAddr: request.ListenAddr,
		ForwardingEnabled: true,
	}
}

func activatedNetworkManifest(base config.NetworkManifest, activation model.SignedSnapshot) (config.NetworkManifest, error) {
	committee, committeeConfig, ok := activatedCommittee(activation)
	if !ok {
		return config.NetworkManifest{}, fmt.Errorf("activation snapshot is missing its certified committee")
	}
	params, err := model.CommitteeParamsFromConfig(committeeConfig)
	if err != nil {
		return config.NetworkManifest{}, fmt.Errorf("activated committee params: %w", err)
	}
	if len(committee) != params.Size || !activation.State.CommitteeConfig.Equal(committeeConfig) {
		return config.NetworkManifest{}, fmt.Errorf("activation snapshot has inconsistent committee state")
	}
	manifest := base
	manifest.NetworkID = activation.State.NetworkID
	manifest.OverlayCIDR = activation.State.OverlayCIDR
	manifest.ProtocolVersion = version.ProtocolVersion
	manifest.ManagerJoinTokenHash = append([]byte(nil), activation.State.ManagerJoinTokenHash...)
	manifest.CommitteeParams = params
	manifest.Managers = append([]model.CommitteeMember(nil), committee...)
	manifest.Groups = activation.State.Groups
	manifest.Policies = activation.State.Policies
	manifest.Routes = activation.State.Routes
	manifest.Budgets = activation.State.Budgets
	manifest.Nameservers = activation.State.Nameservers
	manifest.Zones = activation.State.Zones
	manifest.DNSSettings = activation.State.DNSSettings
	manifest.Settings = activation.State.Settings
	manifest.NextIPOffset = activation.State.NextIPOffset
	if err := manifest.Validate(); err != nil {
		return config.NetworkManifest{}, fmt.Errorf("validate activated manifest: %w", err)
	}
	return manifest, nil
}

func writeNetworkManifestAtomic(path string, manifest config.NetworkManifest) error {
	encoded, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return err
	}
	encoded = append(encoded, '\n')
	temporary, err := os.CreateTemp(filepath.Dir(path), ".network-*.json")
	if err != nil {
		return err
	}
	temporaryPath := temporary.Name()
	defer os.Remove(temporaryPath)
	if err := temporary.Chmod(0o600); err != nil {
		_ = temporary.Close()
		return err
	}
	if _, err := temporary.Write(encoded); err != nil {
		_ = temporary.Close()
		return err
	}
	if err := temporary.Sync(); err != nil {
		_ = temporary.Close()
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	return os.Rename(temporaryPath, path)
}

func (watcher committeeResizeWatcher) connectCandidates(target []model.CommitteeMember) error {
	current := watcher.engine.CommitteeMembers()
	known := make(map[string]struct{}, len(current))
	for _, member := range current {
		known[member.ID] = struct{}{}
	}
	var lastErr error
	for _, member := range target {
		if _, exists := known[member.ID]; exists {
			continue
		}
		info, err := peer.AddrInfoFromString(member.Address + "/p2p/" + member.PeerID)
		if err != nil {
			lastErr = fmt.Errorf("invalid candidate address for %s: %w", member.ID, err)
			continue
		}
		connectContext, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		err = watcher.node.Host.Connect(connectContext, *info)
		cancel()
		if err != nil {
			lastErr = fmt.Errorf("connect candidate %s: %w", member.ID, err)
			continue
		}
	}
	return lastErr
}

type dkgProbeMessage struct {
	Kind     string `json:"kind"`
	Ceremony string `json:"ceremony"`
	From     string `json:"from"`
	Ready    bool   `json:"ready,omitempty"`
}

func probeDKGCeremony(ctx context.Context, node *p2p.Node, peerID peer.ID, ceremonyID, localID string) error {
	probeContext, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	stream, err := node.Host.NewStream(probeContext, peerID, p2p.DKGProtocol)
	if err != nil {
		return err
	}
	defer stream.Close()
	payload, err := json.Marshal(dkgProbeMessage{
		Kind: "ready", Ceremony: ceremonyID, From: localID,
	})
	if err != nil {
		return err
	}
	if err := p2p.EncodeEnvelope(stream, p2p.DKGProtocol, payload); err != nil {
		return err
	}
	if closeWriter, ok := stream.(interface{ CloseWrite() error }); ok {
		_ = closeWriter.CloseWrite()
	}
	envelope, err := p2p.DecodeEnvelope(stream)
	if err != nil {
		return err
	}
	var response dkgProbeMessage
	if err := json.Unmarshal(envelope.Payload, &response); err != nil {
		return err
	}
	if response.Kind != "ready" || response.Ceremony != ceremonyID || response.From == "" {
		return fmt.Errorf("unexpected DKG readiness response")
	}
	return nil
}

func waitForCommitteeDKG(
	ctx context.Context, node *p2p.Node, members []model.CommitteeMember, ceremonyID, localManagerID string,
) error {
	localPeerID := node.Host.ID().String()
	deadline := time.Now().Add(30 * time.Second)
	var lastErr error

	for {
		remaining := 0
		for _, member := range members {
			if member.PeerID == localPeerID {
				continue
			}
			memberID, err := peer.Decode(member.PeerID)
			if err != nil {
				return fmt.Errorf("invalid committee peer ID for %s: %w", member.ID, err)
			}
			remaining++
			if err := probeDKGCeremony(ctx, node, memberID, ceremonyID, localManagerID); err != nil {
				lastErr = fmt.Errorf("manager %s DKG protocol not ready: %w", member.ID, err)
				continue
			}
			remaining--
		}
		if remaining == 0 {
			return nil
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if time.Now().After(deadline) {
			if lastErr == nil {
				lastErr = fmt.Errorf("%d managers were not DKG-ready", remaining)
			}
			return lastErr
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(250 * time.Millisecond):
		}
	}
}

func (watcher *committeeResizeWatcher) ensureCommitteeShare(
	ctx context.Context, target []model.CommitteeMember, params model.CommitteeParams, epoch uint64,
) (*bls.KeySet, error) {
	ids := make([]string, 0, len(target))
	for _, member := range target {
		ids = append(ids, member.ID)
	}
	ceremonyID := dkg.CeremonyID(watcher.networkID, epoch, ids)
	if watcher.failedEpoch == epoch {
		return nil, fmt.Errorf("committee resize DKG already failed for epoch %d", epoch)
	}
	if keys, ok := dkg.LoadShare(watcher.dataDir, epoch, watcher.localID, ids, params.QuorumSize); ok {
		if watcher.ceremony == nil || watcher.ceremonyEpoch != epoch || watcher.ceremonyID != ceremonyID {
			ceremony, err := newDKGCeremonyForCommittee(
				watcher.node, target, watcher.networkID, epoch, params.QuorumSize, watcher.localID,
			)
			if err != nil {
				return nil, err
			}
			watcher.node.Handle(p2p.DKGProtocol, ceremony.Handle)
			watcher.ceremony = ceremony
			watcher.ceremonyID = ceremonyID
			watcher.ceremonyEpoch = epoch
		}
		watcher.ceremony.MarkSaved()
		if err := watcher.ceremony.WaitAll(ctx); err != nil {
			watcher.failedEpoch = epoch
			return nil, fmt.Errorf("confirm persisted committee share: %w", err)
		}
		return keys, nil
	}
	if watcher.ceremony == nil || watcher.ceremonyEpoch != epoch || watcher.ceremonyID != ceremonyID {
		ceremony, err := newDKGCeremonyForCommittee(
			watcher.node, target, watcher.networkID, epoch, params.QuorumSize, watcher.localID,
		)
		if err != nil {
			return nil, err
		}
		watcher.node.Handle(p2p.DKGProtocol, ceremony.Handle)
		watcher.ceremony = ceremony
		watcher.ceremonyID = ceremonyID
		watcher.ceremonyEpoch = epoch
	}
	if err := waitForCommitteeDKG(ctx, watcher.node, target, ceremonyID, watcher.localID); err != nil {
		return nil, fmt.Errorf("committee resize DKG readiness: %w", err)
	}
	result, err := watcher.ceremony.Run(ctx)
	if err != nil {
		watcher.failedEpoch = epoch
		return nil, fmt.Errorf("committee resize ceremony: %w", err)
	}
	if err := dkg.SaveShare(watcher.dataDir, epoch, watcher.localID, params.QuorumSize, params.Size, result); err != nil {
		watcher.failedEpoch = epoch
		return nil, fmt.Errorf("persist committee resize share: %w", err)
	}
	watcher.ceremony.MarkSaved()
	if err := watcher.ceremony.WaitAll(ctx); err != nil {
		watcher.failedEpoch = epoch
		return nil, fmt.Errorf("committee resize readiness: %w", err)
	}
	return keySetFromDKG(target, watcher.localID, params, result)
}
