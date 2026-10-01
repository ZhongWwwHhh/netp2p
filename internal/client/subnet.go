package client

import (
	"net"
	"net/netip"
	"sort"

	"github.com/netp2p/netp2p/internal/exitnode"
	"github.com/netp2p/netp2p/internal/model"
)

// subnetGateway resolves the certified gateway peer for a destination address,
// using only certified Routes visible to this client. The second return value
// is false when no route covers the destination.
func (client *Client) subnetGateway(destination net.IP) (model.PeerRecord, bool) {
	addr, ok := netip.AddrFromSlice(destination)
	if !ok {
		return model.PeerRecord{}, false
	}
	addr = addr.Unmap()

	client.mu.RLock()
	state := client.snapshot.State
	self := client.self
	enabled := state.Settings.ExitNodeEnabled
	client.mu.RUnlock()
	if !enabled {
		return model.PeerRecord{}, false
	}

	candidates := visibleRoutes(state, self)
	// Deterministic order: lower metric first, then route id.
	sort.SliceStable(candidates, func(i, j int) bool {
		if candidates[i].Metric != candidates[j].Metric {
			return candidates[i].Metric < candidates[j].Metric
		}
		return candidates[i].ID < candidates[j].ID
	})
	for _, route := range candidates {
		prefix, err := netip.ParsePrefix(route.Destination)
		if err != nil || !prefix.Contains(addr) {
			continue
		}
		if gateway, ok := client.routeGateway(state, route); ok {
			return gateway, true
		}
	}
	return model.PeerRecord{}, false
}

// visibleRoutes returns the certified routes this peer is allowed to use.
func visibleRoutes(state model.NetworkState, self model.PeerRecord) []model.Route {
	groupMembers := membership(state.Groups, self.PeerID)
	result := make([]model.Route, 0, len(state.Routes))
	for _, route := range state.Routes {
		if len(route.DistributionGroup) == 0 {
			result = append(result, route)
			continue
		}
		for _, groupID := range route.DistributionGroup {
			if groupMembers[groupID] {
				result = append(result, route)
				break
			}
		}
	}
	return result
}

// routeGateway picks the exit-node peer that will carry a route. Selection is
// deterministic (lowest PeerID) so every client agrees without relying on
// untrusted client-reported link quality.
func (client *Client) routeGateway(state model.NetworkState, route model.Route) (model.PeerRecord, bool) {
	selfID := client.localPeerID()
	members := make([]model.PeerRecord, 0)
	for _, peer := range state.Peers {
		if peer.PeerID == selfID || !peer.IsExitNode {
			continue
		}
		if peerInGroup(state.Groups, route.RoutingGroup, peer.PeerID) {
			members = append(members, peer)
		}
	}
	if len(members) == 0 {
		return model.PeerRecord{}, false
	}
	sort.SliceStable(members, func(i, j int) bool {
		return members[i].PeerID < members[j].PeerID
	})
	return members[0], true
}

// exitRoutes returns the routes this peer must forward for, i.e. routes whose
// routing group contains this exit node.
func (client *Client) exitRoutes() []exitnode.Route {
	client.mu.RLock()
	state := client.snapshot.State
	self := client.self.PeerID
	client.mu.RUnlock()
	if !state.Settings.ExitNodeEnabled || !client.isExitNode(state) {
		return nil
	}
	result := make([]exitnode.Route, 0)
	for _, route := range state.Routes {
		if peerInGroup(state.Groups, route.RoutingGroup, self) {
			result = append(result, exitnode.Route{
				ID: route.ID, Destination: route.Destination, Masquerade: route.Masquerade,
			})
		}
	}
	return result
}

func (client *Client) isExitNode(state model.NetworkState) bool {
	selfID := client.localPeerID()
	for _, peer := range state.Peers {
		if peer.PeerID == selfID {
			return peer.IsExitNode
		}
	}
	return false
}

// localPeerID returns the certified self peer id, falling back to the libp2p
// host identity for a client that has not logged in yet.
func (client *Client) localPeerID() string {
	client.mu.RLock()
	self := client.self.PeerID
	client.mu.RUnlock()
	if self != "" {
		return self
	}
	if client.node == nil || client.node.Host == nil {
		return ""
	}
	return client.node.Host.ID().String()
}

// networkCIDRs lists the certified subnet/exit CIDRs this peer routes into the
// overlay, for kernel route installation.
func (client *Client) networkCIDRs() []string {
	client.mu.RLock()
	state := client.snapshot.State
	self := client.self
	client.mu.RUnlock()
	if !state.Settings.ExitNodeEnabled {
		return nil
	}
	seen := make(map[string]struct{})
	result := make([]string, 0)
	for _, route := range visibleRoutes(state, self) {
		if _, exists := seen[route.Destination]; exists {
			continue
		}
		if _, err := netip.ParsePrefix(route.Destination); err != nil {
			continue
		}
		seen[route.Destination] = struct{}{}
		result = append(result, route.Destination)
	}
	sort.Strings(result)
	return result
}

// exitNodeForPacket reports whether this node should forward the packet to the
// local network stack as a certified subnet/exit gateway.
func (client *Client) exitNodeForPacket(source model.PeerRecord, destination net.IP) bool {
	addr, ok := netip.AddrFromSlice(destination)
	if !ok {
		return false
	}
	addr = addr.Unmap()
	client.mu.RLock()
	state := client.snapshot.State
	self := client.self.PeerID
	client.mu.RUnlock()
	if !state.Settings.ExitNodeEnabled || !client.isExitNode(state) {
		return false
	}
	for _, route := range state.Routes {
		if !peerInGroup(state.Groups, route.RoutingGroup, self) {
			continue
		}
		// The source must be allowed to use the route.
		if !sourceAllowed(state, route, source.PeerID) {
			continue
		}
		prefix, err := netip.ParsePrefix(route.Destination)
		if err != nil || !prefix.Contains(addr) {
			continue
		}
		// Traffic destined to an overlay peer is delivered normally, not
		// forwarded.
		return true
	}
	return false
}

// gatewayCoversRemote reports whether source is a certified gateway for a route
// that contains remoteIP. It is used to accept the return leg of a masqueraded
// flow, where the packet's source is a foreign address spoken for by the
// gateway rather than the gateway's own overlay IP.
func (client *Client) gatewayCoversRemote(source model.PeerRecord, remoteIP net.IP) bool {
	if !source.IsExitNode {
		return false
	}
	addr, ok := netip.AddrFromSlice(remoteIP)
	if !ok {
		return false
	}
	addr = addr.Unmap()
	client.mu.RLock()
	state := client.snapshot.State
	self := client.self
	client.mu.RUnlock()
	if !state.Settings.ExitNodeEnabled {
		return false
	}
	for _, route := range visibleRoutes(state, self) {
		if !peerInGroup(state.Groups, route.RoutingGroup, source.PeerID) {
			continue
		}
		prefix, err := netip.ParsePrefix(route.Destination)
		if err != nil {
			continue
		}
		if prefix.Contains(addr) {
			return true
		}
	}
	return false
}

func sourceAllowed(state model.NetworkState, route model.Route, peerID string) bool {
	if len(route.DistributionGroup) == 0 {
		return true
	}
	for _, groupID := range route.DistributionGroup {
		if peerInGroup(state.Groups, groupID, peerID) {
			return true
		}
	}
	return false
}

func membership(groups []model.Group, peerID string) map[string]bool {
	result := make(map[string]bool, len(groups))
	for _, group := range groups {
		for _, member := range group.PeerIDs {
			if member == peerID {
				result[group.ID] = true
				break
			}
		}
	}
	return result
}

func peerInGroup(groups []model.Group, groupID, peerID string) bool {
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
