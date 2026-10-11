package client

import (
	"net/netip"
	"strings"

	"github.com/netp2p/netp2p/internal/model"
	"github.com/netp2p/netp2p/internal/packet"
)

// flowClassFor resolves the runtime class for one outbound packet. Certified
// route and policy annotations win, then the network default; only an unset
// default falls through to a conservative protocol/port heuristic.
func (client *Client) flowClassFor(destination model.PeerRecord, ipPacket packet.IPv4Packet) FlowClass {
	protocol, port := describePacket(ipPacket)
	client.mu.RLock()
	state := client.snapshot.State
	self := client.self
	client.mu.RUnlock()

	explicit := explicitRouteFlowClass(state, self, ipPacket.Destination())
	if explicit == "" {
		explicit = explicitPolicyFlowClass(state, self, destination, protocol, port)
	}
	return classifyFlow(protocol, port, explicit, state.Settings.DefaultFlowClass)
}

func explicitRouteFlowClass(state model.NetworkState, self model.PeerRecord, destination []byte) string {
	addr, ok := netip.AddrFromSlice(destination)
	if !ok {
		return ""
	}
	addr = addr.Unmap()
	for _, route := range visibleRoutes(state, self) {
		if route.FlowClass == "" {
			continue
		}
		prefix, err := netip.ParsePrefix(route.Destination)
		if err == nil && prefix.Contains(addr) {
			return route.FlowClass
		}
	}
	return ""
}

func explicitPolicyFlowClass(state model.NetworkState, self model.PeerRecord, destination model.PeerRecord, protocol string, port uint16) string {
	best := ""
	bestPriority := 0
	for _, item := range state.Policies {
		if item.Effect != model.EffectAllow || item.FlowClass == "" {
			continue
		}
		if !peerInAnyGroup(state.Groups, item.SourceGroups, self.PeerID) ||
			!peerInAnyGroup(state.Groups, item.DestinationGroups, destination.PeerID) ||
			!flowServiceAllows(item.Services, protocol, port) ||
			!postureAllows(item.Posture, self.Posture) {
			continue
		}
		if best == "" || item.Priority > bestPriority {
			best = item.FlowClass
			bestPriority = item.Priority
		}
	}
	return best
}

func peerInAnyGroup(groups []model.Group, groupIDs []string, peerID string) bool {
	for _, groupID := range groupIDs {
		if idInGroup(groups, groupID, peerID) {
			return true
		}
	}
	return false
}

func idInGroup(groups []model.Group, groupID, id string) bool {
	for _, group := range groups {
		if group.ID != groupID {
			continue
		}
		for _, member := range group.PeerIDs {
			if member == id {
				return true
			}
		}
		for _, member := range group.UserIDs {
			if member == id {
				return true
			}
		}
	}
	return false
}

func flowServiceAllows(services []model.Service, protocol string, port uint16) bool {
	if len(services) == 0 {
		return true
	}
	for _, service := range services {
		name := strings.TrimSpace(service.Protocol)
		if name != "" && !strings.EqualFold(name, "all") && !strings.EqualFold(name, protocol) {
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

func postureAllows(required, advertised []string) bool {
	available := make(map[string]struct{}, len(advertised))
	for _, label := range advertised {
		available[label] = struct{}{}
	}
	for _, label := range required {
		if _, exists := available[label]; !exists {
			return false
		}
	}
	return true
}
