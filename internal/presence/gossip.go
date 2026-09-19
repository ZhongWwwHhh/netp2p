package presence

import (
	"context"
	"encoding/json"
	"time"

	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	ma "github.com/multiformats/go-multiaddr"
	"github.com/netp2p/netp2p/internal/p2p"
)

const gossipInterval = 5 * time.Second

type gossipMessage struct {
	Observations []Observation `json:"observations"`
}

// Gossiper observes libp2p connection activity into a Table and periodically
// exchanges that table with the other committee members.
type Gossiper struct {
	node     *p2p.Node
	table    *Table
	observer string
	peers    []peer.ID

	notifiee network.Notifiee
}

func NewGossiper(node *p2p.Node, table *Table, observer string, peers []peer.ID) *Gossiper {
	gossiper := &Gossiper{node: node, table: table, observer: observer, peers: peers}
	gossiper.notifiee = &connectionNotifiee{table: table, observer: observer}
	node.Host.Network().Notify(gossiper.notifiee)
	node.Handle(p2p.PresenceProtocol, gossiper.handle)
	return gossiper
}

// Run exchanges presence with committee peers until ctx is cancelled.
func (gossiper *Gossiper) Run(ctx context.Context) {
	ticker := time.NewTicker(gossipInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			gossiper.node.Host.Network().StopNotify(gossiper.notifiee)
			return
		case <-ticker.C:
			gossiper.refreshLocal()
			gossiper.exchange(ctx)
		}
	}
}

// refreshLocal re-stamps peers that are currently connected. Without this a
// long-lived connection would look stale once StaleAfter elapsed, because the
// notifiee only fires on connect/disconnect.
func (gossiper *Gossiper) refreshLocal() {
	network := gossiper.node.Host.Network()
	for _, peerID := range network.Peers() {
		connection := network.ConnsToPeer(peerID)
		if len(connection) == 0 {
			continue
		}
		gossiper.table.Observe(peerID.String(), connection[0].RemoteMultiaddr().String(), gossiper.observer)
	}
}

func (gossiper *Gossiper) exchange(ctx context.Context) {
	message := gossipMessage{Observations: gossiper.table.Snapshot()}
	for _, peerID := range gossiper.peers {
		if err := gossiper.node.Send(ctx, peerID, p2p.PresenceProtocol, message); err != nil {
			// A down committee member is expected; its observations simply go
			// stale until it returns.
			continue
		}
	}
}

func (gossiper *Gossiper) handle(stream network.Stream) {
	defer stream.Close()
	envelope, err := p2p.DecodeEnvelope(stream)
	if err != nil {
		return
	}
	var message gossipMessage
	if err := json.Unmarshal(envelope.Payload, &message); err != nil {
		return
	}
	gossiper.table.Merge(message.Observations)
}

// connectionNotifiee turns libp2p connection lifecycle events into presence
// observations, so online status does not depend on any client heartbeat.
type connectionNotifiee struct {
	table    *Table
	observer string
}

func (notifiee *connectionNotifiee) Connected(_ network.Network, connection network.Conn) {
	notifiee.table.Observe(connection.RemotePeer().String(), connection.RemoteMultiaddr().String(), notifiee.observer)
}

func (notifiee *connectionNotifiee) Disconnected(_ network.Network, connection network.Conn) {
	notifiee.table.Disconnect(connection.RemotePeer().String(), connection.RemoteMultiaddr().String(), notifiee.observer)
}

func (notifiee *connectionNotifiee) Listen(network.Network, ma.Multiaddr)      {}
func (notifiee *connectionNotifiee) ListenClose(network.Network, ma.Multiaddr) {}
