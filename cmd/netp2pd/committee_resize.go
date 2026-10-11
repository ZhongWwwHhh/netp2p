package main

import (
	"context"
	"fmt"
	"log"
	"sort"
	"time"

	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/netp2p/netp2p/internal/bft"
	"github.com/netp2p/netp2p/internal/crypto/bls"
	"github.com/netp2p/netp2p/internal/dkg"
	"github.com/netp2p/netp2p/internal/manager"
	"github.com/netp2p/netp2p/internal/model"
	"github.com/netp2p/netp2p/internal/p2p"
)

type committeeResizeWatcher struct {
	node      *p2p.Node
	engine    *bft.Engine
	mesh      *manager.CommitteeMesh
	localID   string
	dataDir   string
	networkID string
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

func (watcher committeeResizeWatcher) runOnce(ctx context.Context) {
	state := watcher.engine.CurrentState()
	target, changed := watcher.targetCommittee(state)
	if !changed {
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
	if watcher.engine.Leader(watcher.engine.Height()+1, 0).ID != watcher.localID {
		return
	}
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

func (watcher committeeResizeWatcher) targetCommittee(state model.NetworkState) ([]model.CommitteeMember, bool) {
	current := watcher.engine.CommitteeMembers()
	target, changed := targetCommitteeFromState(state, current)
	return target, changed
}

func targetCommitteeFromState(state model.NetworkState, current []model.CommitteeMember) ([]model.CommitteeMember, bool) {
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
		}
	}
	return lastErr
}

func (watcher committeeResizeWatcher) ensureCommitteeShare(
	ctx context.Context, target []model.CommitteeMember, params model.CommitteeParams, epoch uint64,
) (*bls.KeySet, error) {
	ids := make([]string, 0, len(target))
	for _, member := range target {
		ids = append(ids, member.ID)
	}
	if keys, ok := dkg.LoadShare(watcher.dataDir, epoch, watcher.localID, ids, params.QuorumSize); ok {
		ceremony, err := newDKGCeremonyForCommittee(
			watcher.node, target, watcher.networkID, epoch, params.QuorumSize, watcher.localID,
		)
		if err != nil {
			return nil, err
		}
		watcher.node.Handle(p2p.DKGProtocol, ceremony.Handle)
		ceremony.MarkSaved()
		if err := ceremony.WaitAll(ctx); err != nil {
			return nil, fmt.Errorf("confirm persisted committee share: %w", err)
		}
		return keys, nil
	}
	ceremony, err := newDKGCeremonyForCommittee(
		watcher.node, target, watcher.networkID, epoch, params.QuorumSize, watcher.localID,
	)
	if err != nil {
		return nil, err
	}
	watcher.node.Handle(p2p.DKGProtocol, ceremony.Handle)
	result, err := ceremony.Run(ctx)
	if err != nil {
		return nil, fmt.Errorf("committee resize ceremony: %w", err)
	}
	if err := dkg.SaveShare(watcher.dataDir, epoch, watcher.localID, params.QuorumSize, params.Size, result); err != nil {
		return nil, fmt.Errorf("persist committee resize share: %w", err)
	}
	ceremony.MarkSaved()
	if err := ceremony.WaitAll(ctx); err != nil {
		return nil, fmt.Errorf("committee resize readiness: %w", err)
	}
	return keySetFromDKG(target, watcher.localID, params, result)
}
