package client

import (
	"errors"
	"fmt"
	"net/netip"

	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/netp2p/netp2p/internal/forward"
	"github.com/netp2p/netp2p/internal/model"
	"github.com/netp2p/netp2p/internal/packet"
	"github.com/netp2p/netp2p/internal/path"
)

func (client *Client) scaleEligible(destination model.PeerRecord) bool {
	client.mu.RLock()
	defer client.mu.RUnlock()
	state := client.snapshot.State
	if !state.Settings.ViaManagerEnabled || state.Settings.DirectPathEnabled || len(state.RoutingDomains) == 0 {
		return false
	}
	for _, assignment := range state.Assignments {
		if assignment.SourcePeerID == client.self.PeerID && assignment.DestinationPeerID == destination.PeerID {
			return false
		}
	}
	return true
}

func (client *Client) sendScale(
	destination model.PeerRecord, raw []byte, flowClass FlowClass, returnTraffic bool,
) (peer.ID, PathSelectionStatus, error) {
	client.mu.RLock()
	snapshot := client.snapshot
	self := client.self
	managers := append([]peer.AddrInfo(nil), client.managers...)
	active := client.manager.ID
	client.mu.RUnlock()

	manager, managerID, ok := forwardingManagerForSnapshot(snapshot, managers, active, self.PeerID)
	if !ok {
		return "", PathSelectionStatus{}, fmt.Errorf("no forwarding manager is available for global routing")
	}
	domain, ok := scaleRoutingDomain(snapshot.State, self, destination, raw, flowClass, managerID, returnTraffic)
	if !ok {
		return "", PathSelectionStatus{}, fmt.Errorf("no certified global routing domain for %s", destination.PeerID)
	}
	flowHash, ok := packet.FlowHash(raw)
	if !ok {
		return "", PathSelectionStatus{}, fmt.Errorf("global routing payload is not an IPv4 or IPv6 packet")
	}
	envelope := forward.ScaleEnvelope{
		Header: forward.ScaleHeader{
			SourcePeerID: self.PeerID, DestinationPeerID: destination.PeerID,
			RoutingDomainID: domain.ID, FlowClass: string(flowClass),
			FlowHash: flowHash, Sequence: client.scaleSequence.Add(1), TTL: forward.DefaultTTL,
		},
		Payload: append([]byte(nil), raw...),
	}
	wire, err := forward.EncodeScaleEnvelope(envelope)
	if err != nil {
		return "", PathSelectionStatus{}, err
	}
	if err := client.sendScaleWire(manager, wire); err != nil {
		return "", PathSelectionStatus{}, err
	}
	return manager, PathSelectionStatus{
		State: PathSelectionCertified, PathID: "global-scale", Kind: model.PathKindViaManager,
		ManagerPeerID: manager.String(), RoutingDomainID: domain.ID,
		Certified: true, OK: true, FlowClass: flowClass,
	}, nil
}

// sendScaleWire writes one certified scale envelope on a fresh stream. The
// persistent frame transport is fire-and-forget; a stale remote stream can
// accept a write after the reader has closed, which would make sendScale report
// success while the manager never admits the packet.
func (client *Client) sendScaleWire(manager peer.ID, wire []byte) error {
	client.mu.RLock()
	frames := client.frames
	client.mu.RUnlock()
	if frames == nil {
		return errors.New("frame transport is not started")
	}
	return frames.SendScale(manager, wire)
}

func forwardingManagerForSnapshot(
	snapshot model.SignedSnapshot, managers []peer.AddrInfo, active peer.ID, selectionKey string,
) (peer.ID, string, bool) {
	committee := make(map[string]model.CommitteeMember, len(snapshot.Committee))
	for _, member := range snapshot.Committee {
		if member.ForwardingEnabled && member.PeerID != "" {
			committee[member.PeerID] = member
		}
	}
	if active != "" {
		if member, ok := committee[active.String()]; ok {
			return active, member.ID, true
		}
	}
	if manager, _, ok := selectManagerByRendezvous(managers, selectionKey); ok {
		if member, ok := committee[manager.ID.String()]; ok {
			return manager.ID, member.ID, true
		}
	}
	return "", "", false
}

func selectManagerByRendezvous(managers []peer.AddrInfo, selectionKey string) (peer.AddrInfo, int, bool) {
	if len(managers) == 0 || selectionKey == "" {
		return peer.AddrInfo{}, -1, false
	}
	weights := make([]path.PathWeight, 0, len(managers))
	for _, manager := range managers {
		weights = append(weights, path.PathWeight{PathID: manager.ID.String(), Weight: 1})
	}
	selected, ok := path.WeightedRendezvous(weights, []byte(selectionKey))
	if !ok {
		return peer.AddrInfo{}, -1, false
	}
	for index, manager := range managers {
		if manager.ID.String() == selected {
			return manager, index, true
		}
	}
	return peer.AddrInfo{}, -1, false
}

func scaleRoutingDomain(
	state model.NetworkState, self, destination model.PeerRecord, raw []byte, flowClass FlowClass, managerID string,
	returnTraffic bool,
) (model.RoutingDomainAuthorization, bool) {
	flow, ok := packet.ParseIPFlow(raw)
	if !ok {
		return model.RoutingDomainAuthorization{}, false
	}
	for _, domain := range state.RoutingDomains {
		if domain.Key.SourceManagerID != managerID || domain.Key.FlowClass != string(flowClass) || len(domain.PathFamilyIDs) == 0 {
			continue
		}
		if returnTraffic {
			if !peerInAnyGroup(state.Groups, []string{domain.Key.SourceGroupID}, self.PeerID) ||
				!scaleReturnEndpointMatches(state, domain, self, destination, flow) {
				continue
			}
		} else if !peerInAnyGroup(state.Groups, []string{domain.Key.SourceGroupID}, self.PeerID) ||
			!scaleDomainDestinationMatches(state, domain, destination, flow) {
			continue
		}
		return domain, true
	}
	return model.RoutingDomainAuthorization{}, false
}

func scaleReturnEndpointMatches(
	state model.NetworkState, domain model.RoutingDomainAuthorization, self, destination model.PeerRecord, flow packet.IPFlow,
) bool {
	kind, id, _ := model.ParseDestinationScope(domain.Key.DestinationScope)
	switch kind {
	case model.DestinationScopeGroup:
		if !peerInAnyGroup(state.Groups, []string{id}, destination.PeerID) {
			return false
		}
	case model.DestinationScopePeer:
		if destination.PeerID != id {
			return false
		}
	case model.DestinationScopeRoute:
		return false
	default:
		return false
	}
	selfIP, selfErr := netip.ParseAddr(self.OverlayIP)
	destinationIP, destinationErr := netip.ParseAddr(destination.OverlayIP)
	return selfErr == nil && destinationErr == nil &&
		selfIP.Unmap() == flow.Source && destinationIP.Unmap() == flow.Destination
}

func scaleDomainDestinationMatches(
	state model.NetworkState, domain model.RoutingDomainAuthorization, destination model.PeerRecord, flow packet.IPFlow,
) bool {
	kind, id, _ := model.ParseDestinationScope(domain.Key.DestinationScope)
	switch kind {
	case model.DestinationScopeGroup:
		return peerInAnyGroup(state.Groups, []string{id}, destination.PeerID)
	case model.DestinationScopePeer:
		return destination.PeerID == id
	case model.DestinationScopeRoute:
		route, ok := routeByID(state, id)
		if !ok || !destination.IsExitNode {
			return false
		}
		prefix, err := netip.ParsePrefix(route.Destination)
		return err == nil && prefix.Contains(flow.Destination) &&
			peerInAnyGroup(state.Groups, []string{route.RoutingGroup}, destination.PeerID)
	default:
		return false
	}
}

func routeByID(state model.NetworkState, routeID string) (model.Route, bool) {
	for _, route := range state.Routes {
		if route.ID == routeID {
			return route, true
		}
	}
	return model.Route{}, false
}

func (client *Client) handleScaleEnvelope(remote peer.ID, wire []byte) error {
	envelope, err := forward.DecodeScaleEnvelope(wire)
	if err != nil {
		recordDataPlaneDrop()
		debugDrop("scale envelope: %v", err)
		return fmt.Errorf("decode scale envelope: %w", err)
	}
	client.mu.RLock()
	selfID := client.self.PeerID
	snapshot := client.snapshot
	client.mu.RUnlock()
	if envelope.Header.DestinationPeerID != selfID {
		recordDataPlaneDrop()
		debugDrop("scale envelope destination %q is not local", envelope.Header.DestinationPeerID)
		return fmt.Errorf("scale envelope destination %q is not local", envelope.Header.DestinationPeerID)
	}
	if !committeeContainsPeer(snapshot, remote.String()) {
		recordDataPlaneDrop()
		debugDrop("scale envelope sender %q is not a committee manager", remote.String())
		return fmt.Errorf("scale envelope sender %q is not a committee manager", remote.String())
	}
	flowHash, ok := packet.FlowHash(envelope.Payload)
	if !ok || flowHash != envelope.Header.FlowHash {
		recordDataPlaneDrop()
		debugDrop("scale envelope flow hash mismatch")
		return errors.New("scale envelope flow hash mismatch")
	}
	source, err := peer.Decode(envelope.Header.SourcePeerID)
	if err != nil {
		recordDataPlaneDrop()
		debugDrop("scale envelope source: %v", err)
		return fmt.Errorf("decode scale envelope source: %w", err)
	}
	return client.handleFrameWithAdmission(source, envelope.Payload, false)
}

func committeeContainsPeer(snapshot model.SignedSnapshot, peerID string) bool {
	for _, member := range snapshot.Committee {
		if member.PeerID == peerID {
			return true
		}
	}
	return false
}
