package client

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/core/peerstore"
	"github.com/multiformats/go-multiaddr"
	"github.com/netp2p/netp2p/internal/conntrack"
	"github.com/netp2p/netp2p/internal/forward"
	"github.com/netp2p/netp2p/internal/model"
	"github.com/netp2p/netp2p/internal/p2p"
	"github.com/netp2p/netp2p/internal/packet"
	"github.com/netp2p/netp2p/internal/transport"
)

const (
	maxOverlayPacket           = 65535
	outboundQueueDepth         = 1024
	peerAddressRefreshInterval = 30 * time.Second
)

// DataPlaneStats are process-wide client data-plane counters. A client process
// owns one data-plane instance; keeping them outside Client avoids widening the
// public constructor surface for diagnostics.
type DataPlaneStats struct {
	OutboundQueueDepth int64
	OutboundDrops      uint64
}

var dataPlaneStats struct {
	outboundQueueDepth atomic.Int64
	outboundDrops      atomic.Uint64
}

func (client *Client) DataPlaneStats() DataPlaneStats {
	return DataPlaneStats{
		OutboundQueueDepth: dataPlaneStats.outboundQueueDepth.Load(),
		OutboundDrops:      dataPlaneStats.outboundDrops.Load(),
	}
}

func recordDataPlaneDrop() {
	dataPlaneStats.outboundDrops.Add(1)
}

func (client *Client) ServePackets(ctx context.Context) error {
	frames := transport.NewWithEnvelope(ctx, client.node.Host, p2p.FrameProtocol, client.handleFrame, client.handleEnvelope)
	defer frames.Close()
	client.mu.Lock()
	client.frames = frames
	client.mu.Unlock()

	queue := make(chan []byte, outboundQueueDepth)
	workerDone := make(chan struct{})
	refreshCtx, stopRefresh := context.WithCancel(ctx)
	defer stopRefresh()
	go func() {
		defer close(workerDone)
		for raw := range queue {
			dataPlaneStats.outboundQueueDepth.Add(-1)
			client.forwardLocalPacket(ctx, raw)
		}
	}()
	defer func() {
		close(queue)
		<-workerDone
	}()
	go client.refreshPeerAddressesLoop(refreshCtx)
	client.refreshPeerAddresses()

	for {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		raw, err := client.sink.ReadPacket()
		if err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			if isPermanentPacketReadError(err) {
				return fmt.Errorf("packet endpoint read: %w", err)
			}
			time.Sleep(10 * time.Millisecond)
			continue
		}
		dataPlaneStats.outboundQueueDepth.Add(1)
		select {
		case queue <- raw:
		default:
			dataPlaneStats.outboundQueueDepth.Add(-1)
			recordDataPlaneDrop()
			debugDrop("outbound queue full")
		}
	}
}

func isPermanentPacketReadError(err error) bool {
	return errors.Is(err, io.EOF) ||
		errors.Is(err, io.ErrClosedPipe) ||
		errors.Is(err, io.ErrUnexpectedEOF) ||
		errors.Is(err, os.ErrClosed) ||
		errors.Is(err, syscall.EIO) ||
		errors.Is(err, syscall.EBADF) ||
		errors.Is(err, syscall.ENODEV)
}

// forwardLocalPacket reads a packet from the local userspace endpoint, applies
// policy for the outbound direction and forwards it to the owning overlay peer.
func (client *Client) forwardLocalPacket(ctx context.Context, raw []byte) {
	if len(raw) == 0 || len(raw) > maxOverlayPacket {
		recordDataPlaneDrop()
		debugDrop("forward: size %d", len(raw))
		return
	}
	ipPacket := packet.IPv4Packet(raw)
	if err := ipPacket.Validate(); err != nil {
		recordDataPlaneDrop()
		debugDrop("forward: invalid %v", err)
		return
	}
	destination, err := client.peerByIP(ipPacket.Destination())
	if err != nil {
		// Not an overlay peer: try a certified subnet/exit route.
		gateway, ok := client.subnetGateway(ipPacket.Destination())
		if !ok {
			recordDataPlaneDrop()
			debugDrop("forward: %v", err)
			return
		}
		flow, hasFlow := ipPacket.Flow()
		if !(hasFlow && client.flows.ReplyAllowed(conntrack.Key(flow))) {
			protocolName, port := describePacket(ipPacket)
			allowed, authErr := client.authorize(gateway, protocolName, port)
			if authErr != nil || !allowed {
				recordDataPlaneDrop()
				debugDrop("forward: denied subnet %s/%d via %s (err=%v)", protocolName, port, gateway.OverlayIP, authErr)
				return
			}
			if hasFlow {
				client.flows.Observe(conntrack.Key(flow))
			}
		}
		client.sendToPeer(gateway, raw)
		return
	}
	flow, hasFlow := ipPacket.Flow()
	// Outbound return traffic: this packet answers something we admitted
	// inbound, so the reverse policy must not be required to also allow it.
	if hasFlow && !isEchoRequest(ipPacket) && client.flows.ReplyAllowed(conntrack.Key(flow)) {
		client.sendToPeer(destination, raw)
		return
	}
	protocolName, port := describePacket(ipPacket)
	allowed, err := client.authorize(destination, protocolName, port)
	if err != nil || !allowed {
		recordDataPlaneDrop()
		debugDrop("forward: denied %s/%d to %s (err=%v)", protocolName, port, destination.OverlayIP, err)
		return
	}
	// Remember the flow so the reply direction is admitted without requiring a
	// second, mirror-image policy rule.
	if hasFlow {
		client.flows.Observe(conntrack.Key(flow))
	}
	client.sendToPeer(destination, raw)
}

func (client *Client) sendToPeer(destination model.PeerRecord, raw []byte) bool {
	if !client.admitOutbound(len(raw)) {
		client.markOutboundDrop("outbound packet exceeded the active quota")
		return false
	}
	target, err := peer.Decode(destination.PeerID)
	if err != nil {
		recordDataPlaneDrop()
		client.markOutboundDrop("outbound destination has an invalid peer identifier")
		return false
	}
	source, err := peer.Decode(client.selfPeerID())
	if err != nil {
		recordDataPlaneDrop()
		client.markOutboundDrop("local peer identifier is invalid")
		return false
	}
	if err := client.syncPathSelector(); err != nil {
		recordDataPlaneDrop()
		client.recordPathSelection(target, PathSelectionStatus{
			State: PathSelectionSyncFailed, Err: err,
		})
		client.markOutboundDrop(fmt.Sprintf("path synchronization to %s failed: %v", destination.PeerID, err))
		debugDrop("path sync from %s to %s: %v", client.selfPeerID(), destination.PeerID, err)
		return false
	}
	assignment, path, status := client.paths.selectWithStatus(source, target)
	client.recordPathSelection(target, status)
	if !status.OK {
		recordDataPlaneDrop()
		client.markOutboundDrop(fmt.Sprintf("%s to %s: %v", status.State, destination.PeerID, status.Err))
		debugDrop("path selection from %s to %s state=%s: %v",
			client.selfPeerID(), destination.PeerID, status.State, status.Err)
		return false
	}
	if path.Kind == model.PathKindDirect {
		if !client.directPathsEnabled() {
			recordDataPlaneDrop()
			client.markOutboundDrop(fmt.Sprintf("direct path disabled to %s", destination.PeerID))
			debugDrop("direct path disabled from %s to %s", client.selfPeerID(), destination.PeerID)
			return false
		}
		if !client.sendFrame(target, raw) {
			client.markOutboundDrop(fmt.Sprintf("direct frame delivery to %s failed", destination.PeerID))
			return false
		}
		client.clearOutboundDrop()
		return true
	}
	if err := client.paths.forwarder.Send(source, target, assignment.ID, path.ID, raw); err != nil {
		recordDataPlaneDrop()
		client.markOutboundDrop(fmt.Sprintf("forward to %s via %s failed: %v", destination.PeerID, path.ID, err))
		debugDrop("forward from %s to %s via %s: %v", client.selfPeerID(), destination.PeerID, path.ID, err)
		return false
	}
	client.clearOutboundDrop()
	return true
}

func (client *Client) syncPathSelector() error {
	if client.paths == nil {
		return fmt.Errorf("%w: path selector unavailable", ErrPathSyncFailed)
	}
	client.mu.RLock()
	snapshot := client.snapshot
	client.mu.RUnlock()
	return client.paths.syncSnapshot(snapshot)
}

// admitOutbound applies this peer's source-side budget. The first certified
// manager hop independently enforces both endpoint budgets.
func (client *Client) admitOutbound(size int) bool {
	client.mu.RLock()
	enforcer := client.quota
	enforced := client.snapshot.State.Settings.QuotaEnforcementEnabled
	self := client.self
	client.mu.RUnlock()
	if enforcer == nil {
		return true
	}
	decision := enforcer.Check(self.PeerID, self.Groups, "", uint64(size))
	if !decision.Allowed && enforced {
		recordDataPlaneDrop()
		debugDrop("quota: %s blocked by budget %s (%s)", self.PeerID, decision.BudgetID, decision.Action)
		return false
	}
	if decision.Delay > 0 && enforced {
		time.Sleep(decision.Delay)
	}
	return true
}

// admitDestination applies the local destination budget to a direct frame. A
// via-manager envelope has already been charged by the first manager hop.
func (client *Client) admitDestination(size int) bool {
	client.mu.RLock()
	enforcer := client.quota
	enforced := client.snapshot.State.Settings.QuotaEnforcementEnabled
	self := client.self
	client.mu.RUnlock()
	if enforcer == nil || !enforced {
		return true
	}
	decision := enforcer.Check(self.PeerID, self.Groups, "", uint64(size))
	if !decision.Allowed || decision.Delay > 0 {
		recordDataPlaneDrop()
		debugDrop("quota: destination %s blocked by budget %s (%s)", self.PeerID, decision.BudgetID, decision.Action)
		return false
	}
	return true
}

func (client *Client) directPathsEnabled() bool {
	client.mu.RLock()
	defer client.mu.RUnlock()
	return client.snapshot.State.Settings.DirectPathEnabled
}

func (client *Client) handleEnvelope(remote peer.ID, wire []byte) {
	envelope, err := forward.DecodeEnvelope(wire)
	if err != nil {
		recordDataPlaneDrop()
		debugDrop("forwarded envelope: %v", err)
		return
	}
	source, err := peer.Decode(envelope.Header.SourcePeerID)
	if err != nil {
		recordDataPlaneDrop()
		debugDrop("forwarded source: %v", err)
		return
	}
	delivered, err := client.forwarding.Accept(remote, envelope)
	if err != nil || !delivered {
		if err != nil {
			recordDataPlaneDrop()
			debugDrop("forwarded envelope: %v", err)
		}
		return
	}
	client.handleFrameWithAdmission(source, envelope.Payload, false)
}

func (client *Client) sendFrame(target peer.ID, raw []byte) bool {
	client.mu.RLock()
	frames := client.frames
	client.mu.RUnlock()
	if frames == nil {
		recordDataPlaneDrop()
		return false
	}
	if err := frames.SendPacket(target, raw); err != nil {
		recordDataPlaneDrop()
		return false
	}
	return true
}

// handleFrame is the inbound data path: verify the frame really came from the
// peer that owns the source address, then admit it either as return traffic for
// a flow we originated or through the inbound policy.
func (client *Client) handleFrame(remote peer.ID, raw []byte) {
	client.handleFrameWithAdmission(remote, raw, true)
}

func (client *Client) handleFrameWithAdmission(remote peer.ID, raw []byte, admit bool) {
	if len(raw) == 0 || len(raw) > maxOverlayPacket {
		recordDataPlaneDrop()
		debugDrop("inbound: size %d", len(raw))
		return
	}
	ipPacket := packet.IPv4Packet(raw)
	if err := ipPacket.Validate(); err != nil {
		recordDataPlaneDrop()
		debugDrop("inbound: invalid %v", err)
		return
	}
	source, err := client.peerByPeerID(remote.String())
	if err != nil {
		recordDataPlaneDrop()
		debugDrop("inbound: %v", err)
		return
	}
	if source.OverlayIP != ipPacket.Source().String() {
		// A certified exit/subnet gateway legitimately speaks for foreign
		// source addresses when it masquerades a flow we originated. Accept
		// the return leg only when the gateway covers the source address and
		// the packet matches an outbound flow; everything else is spoofing.
		if flow, hasFlow := ipPacket.Flow(); hasFlow && client.flows.ReplyAllowed(conntrack.Key(flow)) &&
			client.gatewayCoversRemote(source, ipPacket.Source()) {
			if admit && !client.admitDestination(len(raw)) {
				return
			}
			_ = client.sink.WritePacket(raw)
			return
		}
		recordDataPlaneDrop()
		debugDrop("inbound: source %s does not own %s", source.OverlayIP, ipPacket.Source())
		return
	}
	if isEchoReply(ipPacket) && client.deliverAdmission(ipPacket) {
		return
	}
	if ipPacket.Destination().String() != client.selfOverlayIP() {
		// A certified exit/subnet gateway hands the packet to the local network
		// stack; the kernel forwards and masquerades it.
		if client.exitNodeForPacket(source, ipPacket.Destination()) {
			flow, hasFlow := ipPacket.Flow()
			if hasFlow {
				client.flows.Observe(conntrack.Key(flow))
			}
			if admit && !client.admitDestination(len(raw)) {
				return
			}
			_ = client.sink.WritePacket(raw)
			return
		}
		// Otherwise we do not forward on behalf of third parties.
		recordDataPlaneDrop()
		debugDrop("inbound: not for us (%s)", ipPacket.Destination())
		return
	}
	flow, hasFlow := ipPacket.Flow()
	if hasFlow && !isEchoRequest(ipPacket) && client.flows.ReplyAllowed(conntrack.Key(flow)) {
		if admit && !client.admitDestination(len(raw)) {
			return
		}
		_ = client.sink.WritePacket(raw)
		return
	}
	protocolName, port := describePacket(ipPacket)
	allowed, err := client.authorizeInbound(source, protocolName, port)
	if err != nil || !allowed {
		recordDataPlaneDrop()
		debugDrop("inbound: denied %s/%d from %s (err=%v)", protocolName, port, source.OverlayIP, err)
		return
	}
	if admit && !client.admitDestination(len(raw)) {
		return
	}
	// The response the local stack produces is return traffic for this flow.
	if hasFlow {
		client.flows.Observe(conntrack.Key(flow))
	}
	if client.synthesizeICMP {
		if reply, ok := buildEchoReply(ipPacket); ok {
			if isEchoReply(reply) && client.deliverAdmissionSynthesized(reply) {
				return
			}
			// The userspace endpoint has no kernel to answer the echo request,
			// so build the reply here. Route it through the same certified
			// assignment lookup as any other outbound packet so a
			// via-manager-only network can answer.
			client.sendToPeer(source, reply)
			return
		}
	}
	_ = client.sink.WritePacket(raw)
}

func (client *Client) refreshPeerAddressesLoop(ctx context.Context) {
	ticker := time.NewTicker(peerAddressRefreshInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			client.refreshPeerAddresses()
		}
	}
}

func (client *Client) refreshPeerAddresses() {
	if client.node == nil || client.node.Host == nil {
		return
	}
	client.mu.RLock()
	snapshot := client.snapshot
	client.mu.RUnlock()
	local := client.node.Host.ID()
	store := client.node.Host.Peerstore()
	for _, record := range snapshot.State.Peers {
		peerID, err := peer.Decode(record.PeerID)
		if err != nil || peerID == local {
			continue
		}
		addresses := make([]multiaddr.Multiaddr, 0, len(record.Addresses))
		for _, value := range record.Addresses {
			address, err := multiaddr.NewMultiaddr(value)
			if err != nil {
				continue
			}
			addresses = append(addresses, address)
		}
		// Certified addresses are refreshed continuously but are not permanent:
		// if snapshots stop, libp2p eventually forgets stale dial targets.
		store.SetAddrs(peerID, addresses, peerstore.AddressTTL)
	}
}
