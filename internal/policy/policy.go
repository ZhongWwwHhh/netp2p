// Package policy compiles group-based access rules into peer NetworkMaps.
package policy

import (
	"fmt"
	"sort"
	"strings"

	"github.com/netp2p/netp2p/internal/model"
)

// State is the certified configuration subset needed by the policy compiler.
type State struct {
	NetworkID string
	Groups    []model.Group
	Policies  []model.Policy
	Routes    []model.Route
	Budgets   []model.TrafficBudget
}

// NetworkMap is the minimal peer-local view of a certified state.
type NetworkMap struct {
	NetworkID    string                     `json:"networkId"`
	PeerID       string                     `json:"peerId"`
	Epoch        uint64                     `json:"epoch"`
	AllowedPeers map[string][]model.Service `json:"allowedPeers"`
	Routes       []model.Route              `json:"routes"`
	Budgets      []model.TrafficBudget      `json:"budgets"`
}

func indexGroups(groups []model.Group) map[string]map[string]struct{} {
	indexed := make(map[string]map[string]struct{})
	for _, group := range groups {
		members := make(map[string]struct{})
		for _, id := range group.UserIDs {
			members[id] = struct{}{}
		}
		for _, id := range group.PeerIDs {
			members[id] = struct{}{}
		}
		indexed[group.ID] = members
	}
	return indexed
}

func members(index map[string]map[string]struct{}, groupIDs []string) map[string]struct{} {
	result := make(map[string]struct{})
	for _, groupID := range groupIDs {
		for id := range index[groupID] {
			result[id] = struct{}{}
		}
	}
	return result
}

func contains(values map[string]struct{}, target string) bool {
	_, ok := values[target]
	return ok
}

func serviceAllows(services []model.Service, protocol string, port uint16) bool {
	if len(services) == 0 {
		return true
	}
	for _, service := range services {
		if !strings.EqualFold(service.Protocol, protocol) {
			continue
		}
		if port >= service.StartPort && port <= service.EndPort {
			return true
		}
	}
	return false
}

// Compile builds the NetworkMap for peerID. Deny has precedence over allow.
// The current v0 model treats user and peer IDs as one membership namespace;
// SSO-derived user groups must therefore be materialized into peer groups by manager.
func Compile(state State, peerID string, epoch uint64) NetworkMap {
	groupIndex := indexGroups(state.Groups)
	networkMap := NetworkMap{
		NetworkID:    state.NetworkID,
		PeerID:       peerID,
		Epoch:        epoch,
		AllowedPeers: make(map[string][]model.Service),
	}

	type allowedService struct {
		peerID   string
		services []model.Service
	}
	allowed := make(map[string]allowedService)
	denied := make(map[string]struct{})

	for _, policy := range state.Policies {
		source := members(groupIndex, policy.SourceGroups)
		if _, ok := source[peerID]; !ok {
			continue
		}
		destinations := members(groupIndex, policy.DestinationGroups)
		for destination := range destinations {
			if destination == peerID {
				continue
			}
			if policy.Effect == model.EffectDeny {
				denied[destination] = struct{}{}
				continue
			}
			current := allowed[destination]
			current.peerID = destination
			current.services = append(current.services, policy.Services...)
			allowed[destination] = current
		}
	}

	for destination := range allowed {
		if _, denied := denied[destination]; denied {
			continue
		}
		networkMap.AllowedPeers[destination] = allowed[destination].services
	}
	for _, route := range state.Routes {
		if len(route.DistributionGroup) == 0 {
			networkMap.Routes = append(networkMap.Routes, route)
			continue
		}
		if _, ok := members(groupIndex, route.DistributionGroup)[peerID]; ok {
			networkMap.Routes = append(networkMap.Routes, route)
		}
	}
	for _, budget := range state.Budgets {
		if budget.SubjectID == peerID || (budget.SubjectType == "group" && contains(members(groupIndex, []string{budget.SubjectID}), peerID)) {
			networkMap.Budgets = append(networkMap.Budgets, budget)
		}
	}
	sort.Slice(networkMap.Routes, func(i, j int) bool {
		return networkMap.Routes[i].ID < networkMap.Routes[j].ID
	})
	return networkMap
}

// Authorize checks one service access. It reuses Compile semantics for now.
func Authorize(state State, sourcePeer, destinationPeer, protocol string, port uint16) (bool, error) {
	if sourcePeer == "" || destinationPeer == "" || sourcePeer == destinationPeer {
		return false, fmt.Errorf("invalid source/destination peer")
	}
	groupIndex := indexGroups(state.Groups)
	denied := false
	allowed := false
	for _, item := range state.Policies {
		sources := members(groupIndex, item.SourceGroups)
		if _, ok := sources[sourcePeer]; !ok {
			continue
		}
		if _, ok := members(groupIndex, item.DestinationGroups)[destinationPeer]; !ok {
			continue
		}
		matchesService := len(item.Services) == 0 || serviceAllows(item.Services, protocol, port)
		if !matchesService {
			continue
		}
		switch item.Effect {
		case model.EffectDeny:
			denied = true
		case model.EffectAllow:
			allowed = true
		}
	}
	if denied {
		return false, nil
	}
	return allowed, nil
}
