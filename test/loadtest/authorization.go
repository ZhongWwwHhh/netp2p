package loadtest

import (
	"errors"
	"fmt"
	"strings"

	"github.com/netp2p/netp2p/internal/model"
)

var (
	ErrInvalidEnvelope     = errors.New("invalid forwarding envelope")
	ErrUnauthorizedPeer    = errors.New("peer is not a member of the routing domain")
	ErrUnauthorizedPath    = errors.New("path family is not certified for the routing domain")
	ErrPolicyDenied        = errors.New("policy denies the flow")
	ErrInvalidPathInstance = errors.New("path instance is not certified")
)

type authorizationRule struct {
	Denied    bool
	Paths     map[string]struct{}
	Instances map[string]struct{}
	Services  []model.Service
}

type AuthorizationIndex struct {
	peerGroups       map[string]map[string]struct{}
	groupManagers    map[string]string
	destinationScope map[string]map[string]struct{}
	domainRules      map[RoutingDomainKey]*authorizationRule
	pathFamilies     map[string]PathFamily
}

type AuthorizationFixture struct {
	Peers         []model.PeerRecord
	Groups        []model.Group
	Policies      []model.Policy
	Families      []PathFamily
	GroupManagers map[string]string
}

func CompileAuthorization(fixture AuthorizationFixture) (*AuthorizationIndex, error) {
	index := &AuthorizationIndex{
		peerGroups:       make(map[string]map[string]struct{}),
		groupManagers:    make(map[string]string),
		destinationScope: make(map[string]map[string]struct{}),
		domainRules:      make(map[RoutingDomainKey]*authorizationRule),
		pathFamilies:     make(map[string]PathFamily),
	}
	for _, family := range fixture.Families {
		if _, exists := index.pathFamilies[family.ID]; exists {
			return nil, fmt.Errorf("duplicate path family %s", family.ID)
		}
		index.pathFamilies[family.ID] = family
	}
	for groupID, managerID := range fixture.GroupManagers {
		index.groupManagers[groupID] = managerID
	}
	for _, peer := range fixture.Peers {
		if index.peerGroups[peer.PeerID] == nil {
			index.peerGroups[peer.PeerID] = make(map[string]struct{}, len(peer.Groups))
			index.destinationScope[peer.PeerID] = make(map[string]struct{}, len(peer.Groups))
		}
		for _, groupID := range peer.Groups {
			index.peerGroups[peer.PeerID][groupID] = struct{}{}
			index.destinationScope[peer.PeerID][groupID] = struct{}{}
		}
	}

	groupManagers := make(map[string]map[string]struct{})
	for _, groups := range index.peerGroups {
		for groupID := range groups {
			managerID := index.groupManagers[groupID]
			if managerID == "" {
				continue
			}
			if groupManagers[groupID] == nil {
				groupManagers[groupID] = make(map[string]struct{})
			}
			groupManagers[groupID][managerID] = struct{}{}
		}
	}
	for _, policy := range fixture.Policies {
		classes := AllFlowClasses
		if policy.FlowClass != "" {
			classes = []FlowClass{FlowClass(policy.FlowClass)}
		}
		for _, family := range fixture.Families {
			for _, sourceGroup := range policy.SourceGroups {
				if !containsString(family.SourceGroups, sourceGroup) {
					continue
				}
				for _, destinationScope := range policy.DestinationGroups {
					if !containsString(family.DestinationScopes, destinationScope) {
						continue
					}
					for managerID := range groupManagers[sourceGroup] {
						for _, class := range classes {
							if !containsFlowClass(family.FlowClasses, class) {
								continue
							}
							key := RoutingDomainKey{
								SourceManagerID:  managerID,
								SourceGroupID:    sourceGroup,
								DestinationScope: destinationScope,
								FlowClass:        class,
							}
							rule := index.domainRules[key]
							if rule == nil {
								rule = &authorizationRule{
									Paths:     make(map[string]struct{}),
									Instances: make(map[string]struct{}),
								}
								index.domainRules[key] = rule
							}
							if policy.Effect == model.EffectDeny {
								rule.Denied = true
								continue
							}
							rule.Paths[family.ID] = struct{}{}
							for _, instance := range PathInstanceIDs(family) {
								rule.Instances[instance] = struct{}{}
							}
							rule.Services = append(rule.Services, policy.Services...)
						}
					}
				}
			}
		}
	}
	return index, nil
}

func PathInstanceIDs(family PathFamily) []string {
	if len(family.ManagerHops) == 0 {
		return []string{family.ID + ":direct"}
	}
	return []string{family.ID + ":" + strings.Join(family.ManagerHops, ">")}
}

func containsString(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}

func containsFlowClass(values []FlowClass, target FlowClass) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}

func serviceAllows(services []model.Service, protocol string, port uint16) bool {
	if len(services) == 0 {
		return true
	}
	for _, service := range services {
		if service.Protocol != "" && !strings.EqualFold(service.Protocol, "all") && !strings.EqualFold(service.Protocol, protocol) {
			continue
		}
		if service.StartPort == 0 && service.EndPort == 0 {
			return true
		}
		if port >= service.StartPort && port <= service.EndPort {
			return true
		}
	}
	return false
}

func protocolName(value uint8) string {
	switch value {
	case 1:
		return "icmp"
	case 6:
		return "tcp"
	case 17:
		return "udp"
	default:
		return fmt.Sprintf("protocol-%d", value)
	}
}

func (index *AuthorizationIndex) AuthorizeEnvelope(envelope ForwardingEnvelope) error {
	if envelope.SourcePeerID == "" || envelope.DestinationPeerID == "" || envelope.TTL == 0 || len(envelope.Payload) == 0 {
		return ErrInvalidEnvelope
	}
	if !ValidFlowClass(envelope.FlowClass) || envelope.Domain.FlowClass != envelope.FlowClass {
		return ErrInvalidEnvelope
	}
	if _, exists := index.pathFamilies[envelope.PathFamilyID]; !exists {
		return ErrUnauthorizedPath
	}
	if index.groupManagers[envelope.Domain.SourceGroupID] != envelope.Domain.SourceManagerID {
		return ErrUnauthorizedPeer
	}
	if _, exists := index.peerGroups[envelope.SourcePeerID][envelope.Domain.SourceGroupID]; !exists {
		return ErrUnauthorizedPeer
	}
	if _, exists := index.destinationScope[envelope.DestinationPeerID][envelope.Domain.DestinationScope]; !exists {
		return ErrUnauthorizedPeer
	}
	rule := index.domainRules[envelope.Domain]
	if rule == nil || rule.Denied {
		return ErrPolicyDenied
	}
	if _, exists := rule.Paths[envelope.PathFamilyID]; !exists {
		return ErrUnauthorizedPath
	}
	if _, exists := rule.Instances[envelope.PathInstanceID]; !exists {
		return ErrInvalidPathInstance
	}
	if !serviceAllows(rule.Services, protocolName(envelope.Protocol), envelope.DestinationPort) {
		return ErrPolicyDenied
	}
	return nil
}

func (index *AuthorizationIndex) DomainCount() int {
	return len(index.domainRules)
}
