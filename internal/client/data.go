package client

import (
	"fmt"
	"net"

	"github.com/netp2p/netp2p/internal/model"
	"github.com/netp2p/netp2p/internal/policy"
)

func (client *Client) peerByIP(destination net.IP) (model.PeerRecord, error) {
	client.mu.RLock()
	defer client.mu.RUnlock()
	for _, candidate := range client.snapshot.State.Peers {
		if candidate.OverlayIP == destination.String() {
			return candidate, nil
		}
	}
	return model.PeerRecord{}, fmt.Errorf("no peer for overlay IP %s", destination)
}

func (client *Client) selfOverlayIP() string {
	client.mu.RLock()
	defer client.mu.RUnlock()
	return client.self.OverlayIP
}

func (client *Client) authorize(destination model.PeerRecord, protocol string, port uint16) (bool, error) {
	client.mu.RLock()
	state := policy.State{
		NetworkID: client.snapshot.State.NetworkID,
		Groups:    client.snapshot.State.Groups,
		Policies:  client.snapshot.State.Policies,
	}
	self := client.self.PeerID
	client.mu.RUnlock()
	return policy.Authorize(state, self, destination.PeerID, protocol, port)
}

// authorizeInbound checks whether sourcePeer is allowed to reach this client.
func (client *Client) authorizeInbound(sourcePeer model.PeerRecord, protocol string, port uint16) (bool, error) {
	client.mu.RLock()
	state := policy.State{
		NetworkID: client.snapshot.State.NetworkID,
		Groups:    client.snapshot.State.Groups,
		Policies:  client.snapshot.State.Policies,
	}
	self := client.self.PeerID
	client.mu.RUnlock()
	return policy.Authorize(state, sourcePeer.PeerID, self, protocol, port)
}
