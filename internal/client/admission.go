package client

import (
	"net"
	"time"

	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/netp2p/netp2p/internal/model"
	"github.com/netp2p/netp2p/internal/packet"
	netproto "github.com/netp2p/netp2p/internal/protocol"
)

const admissionTimeout = 500 * time.Millisecond

type admissionWaiter struct {
	destinationIP string
	kind          model.PathKind
	replies       chan []byte
}

func assignmentHeightLocked(snapshot model.SignedSnapshot) uint64 {
	return snapshot.Height
}

func (client *Client) selfPeerID() string {
	return client.node.Host.ID().String()
}

func (client *Client) sendViaAssignment(sourceID, destinationID string, raw []byte) bool {
	source, err := peer.Decode(sourceID)
	if err != nil {
		return true
	}
	destination, err := peer.Decode(destinationID)
	if err != nil {
		return true
	}
	assignment, path, ok := client.paths.selectFor(source, destination)
	if !ok {
		return false
	}
	if path.Kind == model.PathKindDirect {
		return false
	}
	return client.paths.forwarder.Send(source, destination, assignment.ID, path.ID, raw) == nil
}

func (client *Client) runAdmissionProbe(snapshot model.SignedSnapshot, selfID string) {
	source, err := peer.Decode(selfID)
	if err != nil {
		return
	}
	for _, assignment := range snapshot.State.Assignments {
		if assignment.SourcePeerID != selfID {
			continue
		}
		destination, err := peer.Decode(assignment.DestinationPeerID)
		if err != nil {
			continue
		}
		for _, path := range assignment.Paths() {
			started := time.Now()
			ok := client.probePath(source, destination, assignment, path)
			client.paths.record(path.ID, ok)
			client.reportAdmission(netproto.AdmissionReport{
				AssignmentID: assignment.ID,
				PathID:       path.ID,
				OK:           ok,
				RTTMs:        float64(time.Since(started).Microseconds()) / 1000,
				ObservedAt:   time.Now().UTC(),
			})
		}
	}
}

func (client *Client) probePath(source, destination peer.ID, assignment model.RouteAssignment, path model.PathSpec) bool {
	destinationRecord, err := client.peerByPeerID(destination.String())
	if err != nil || path.ID == "" {
		return false
	}
	sourceIP := net.ParseIP(client.selfOverlayIP())
	targetIP := net.ParseIP(destinationRecord.OverlayIP)
	if sourceIP == nil || targetIP == nil {
		return false
	}
	request, err := packet.BuildEchoRequest(sourceIP, targetIP, 0x4e50, 1, []byte("admission"))
	if err != nil {
		return false
	}
	replies := make(chan []byte, 1)
	waiter := &admissionWaiter{destinationIP: targetIP.String(), kind: path.Kind, replies: replies}
	client.setAdmissionWaiter(waiter)
	defer client.setAdmissionWaiter(nil)
	if path.Kind == model.PathKindDirect {
		client.sendFrame(destination, request)
	} else if err := client.paths.forwarder.Send(source, destination, assignment.ID, path.ID, request); err != nil {
		return false
	}
	timer := time.NewTimer(admissionTimeout)
	defer timer.Stop()
	select {
	case response := <-replies:
		ipPacket := packet.IPv4Packet(response)
		return ipPacket.Validate() == nil && ipPacket.Source().String() == targetIP.String()
	case <-timer.C:
		return false
	}
}

func (client *Client) setAdmissionWaiter(waiter *admissionWaiter) {
	client.mu.Lock()
	client.admissionWaiter = waiter
	client.mu.Unlock()
}

func (client *Client) deliverAdmission(ipPacket packet.IPv4Packet) bool {
	client.mu.RLock()
	waiter := client.admissionWaiter
	client.mu.RUnlock()
	if waiter == nil || ipPacket.Destination().String() != waiter.destinationIP {
		return false
	}
	select {
	case waiter.replies <- append([]byte(nil), ipPacket...):
		return true
	default:
		return true
	}
}

func (client *Client) deliverAdmissionSynthesized(reply packet.IPv4Packet) bool {
	client.mu.RLock()
	waiter := client.admissionWaiter
	var kind model.PathKind
	if waiter != nil {
		kind = waiter.kind
	}
	client.mu.RUnlock()
	if kind != model.PathKindViaManager {
		return false
	}
	return client.deliverAdmission(reply)
}
