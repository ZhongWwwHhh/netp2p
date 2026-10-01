package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/netp2p/netp2p/internal/bft"
	"github.com/netp2p/netp2p/internal/manager"
	"github.com/netp2p/netp2p/internal/model"
	"github.com/netp2p/netp2p/internal/p2p"
)

func runAdmin(ctx context.Context, managerAddr, token, action, file, target string) error {
	info, err := peer.AddrInfoFromString(managerAddr)
	if err != nil {
		return fmt.Errorf("invalid manager address: %w", err)
	}
	node, err := p2p.New(ctx, p2p.Config{Listen: []string{"/ip4/127.0.0.1/udp/0/quic-v1"}})
	if err != nil {
		return err
	}
	defer node.Close()
	connectCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if err := node.Host.Connect(connectCtx, *info); err != nil {
		return fmt.Errorf("connect manager: %w", err)
	}
	transition, err := buildTransition(action, file, target)
	if err != nil {
		return err
	}
	adminCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	snapshot, err := manager.SubmitAdmin(adminCtx, node, info.ID, token, transition)
	if err != nil {
		return err
	}
	encoded, _ := json.MarshalIndent(map[string]any{
		"height":    snapshot.Height,
		"action":    action,
		"stateHash": fmt.Sprintf("%x", snapshot.StateHash),
	}, "", "  ")
	fmt.Println(string(encoded))
	return nil
}

func buildTransition(action, file, target string) (model.StateTransition, error) {
	transition := model.StateTransition{}
	switch action {
	case "upsert-group":
		transition.Type = bft.TransitionUpsertGroup
		var group model.Group
		if err := loadRecord(file, &group); err != nil {
			return transition, err
		}
		transition.Group = &group
	case "remove-group":
		transition.Type = bft.TransitionRemoveGroup
		transition.TargetID = target
	case "upsert-policy":
		transition.Type = bft.TransitionUpsertPolicy
		var policy model.Policy
		if err := loadRecord(file, &policy); err != nil {
			return transition, err
		}
		transition.Policy = &policy
	case "remove-policy":
		transition.Type = bft.TransitionRemovePolicy
		transition.TargetID = target
	case "update-peer":
		transition.Type = bft.TransitionUpdatePeer
		var peer model.PeerRecord
		if err := loadRecord(file, &peer); err != nil {
			return transition, err
		}
		transition.Peer = peer
	case "upsert-route":
		transition.Type = bft.TransitionUpsertRoute
		var route model.Route
		if err := loadRecord(file, &route); err != nil {
			return transition, err
		}
		transition.Route = &route
	case "remove-route":
		transition.Type = bft.TransitionRemoveRoute
		transition.TargetID = target
	case "upsert-budget":
		transition.Type = bft.TransitionUpsertBudget
		var budget model.TrafficBudget
		if err := loadRecord(file, &budget); err != nil {
			return transition, err
		}
		transition.Budget = &budget
	case "remove-budget":
		transition.Type = bft.TransitionRemoveBudget
		transition.TargetID = target
	case "upsert-setup-key":
		transition.Type = bft.TransitionUpsertSetupKey
		var record model.SetupKey
		if err := loadRecord(file, &record); err != nil {
			return transition, err
		}
		transition.Record = &record
	case "remove-setup-key":
		transition.Type = bft.TransitionRemoveSetupKey
		transition.TargetID = target
	case "upsert-nameserver":
		transition.Type = bft.TransitionUpsertNS
		var nameserver model.Nameserver
		if err := loadRecord(file, &nameserver); err != nil {
			return transition, err
		}
		transition.Nameserver = &nameserver
	case "remove-nameserver":
		transition.Type = bft.TransitionRemoveNS
		transition.TargetID = target
	case "upsert-zone":
		transition.Type = bft.TransitionUpsertZone
		var zone model.DNSZone
		if err := loadRecord(file, &zone); err != nil {
			return transition, err
		}
		transition.Zone = &zone
	case "remove-zone":
		transition.Type = bft.TransitionRemoveZone
		transition.TargetID = target
	case "update-dns-settings":
		transition.Type = bft.TransitionUpdateDNS
		var settings model.DNSSettings
		if err := loadRecord(file, &settings); err != nil {
			return transition, err
		}
		transition.DNSSettings = &settings
	case "update-settings":
		transition.Type = bft.TransitionUpdateSettings
		var settings model.NetworkSettings
		if err := loadRecord(file, &settings); err != nil {
			return transition, err
		}
		transition.Settings = &settings
	case "update-committee":
		transition.Type = bft.TransitionUpdateCommittee
		var committee []model.CommitteeMember
		if err := loadRecord(file, &committee); err != nil {
			return transition, err
		}
		transition.Committee = committee
	case "rotate-committee-keys":
		transition.Type = bft.TransitionRotateCommittee
	default:
		return transition, fmt.Errorf("unknown action %q", action)
	}
	if action != "rotate-committee-keys" && transition.TargetID == "" && file == "" {
		return transition, fmt.Errorf("--file or --target is required for action %q", action)
	}
	return transition, nil
}

func loadRecord(path string, value any) error {
	if path == "" {
		return fmt.Errorf("--file is required for this action")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("read record file: %w", err)
	}
	return json.Unmarshal(data, value)
}
