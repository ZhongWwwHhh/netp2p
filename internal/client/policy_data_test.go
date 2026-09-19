package client

import (
	"net"
	"testing"

	"github.com/netp2p/netp2p/internal/model"
	"github.com/netp2p/netp2p/internal/packet"
)

func testSnapshot() model.SignedSnapshot {
	return model.SignedSnapshot{
		Epoch: 3,
		State: model.NetworkState{
			NetworkID: "net-test",
			Groups: []model.Group{
				{ID: "clients-a", PeerIDs: []string{"peer-a"}},
				{ID: "clients-b", PeerIDs: []string{"peer-b"}},
			},
			Policies: []model.Policy{
				{
					ID: "allow-a-to-b", SourceGroups: []string{"clients-a"}, DestinationGroups: []string{"clients-b"},
					Services: []model.Service{{Protocol: "icmp"}}, Effect: model.EffectAllow,
				},
				{
					ID: "deny-b-to-a", SourceGroups: []string{"clients-b"}, DestinationGroups: []string{"clients-a"},
					Services: []model.Service{{Protocol: "icmp"}}, Effect: model.EffectDeny, Priority: 100,
				},
			},
		},
	}
}

func testClient(peerID, overlayIP string) *Client {
	snapshot := testSnapshot()
	self := model.PeerRecord{PeerID: peerID, OverlayIP: overlayIP}
	return &Client{snapshot: snapshot, self: self}
}

// TestAuthorizeDirection pins the outbound/inbound asymmetry: allow A->B and
// deny B->A must both hold regardless of which side evaluates the packet.
func TestAuthorizeDirection(t *testing.T) {
	peerA := model.PeerRecord{PeerID: "peer-a", OverlayIP: "100.64.0.1"}
	peerB := model.PeerRecord{PeerID: "peer-b", OverlayIP: "100.64.0.2"}
	clientA := testClient(peerA.PeerID, peerA.OverlayIP)
	clientB := testClient(peerB.PeerID, peerB.OverlayIP)

	allowed, err := clientA.authorize(peerB, "icmp", 0)
	if err != nil || !allowed {
		t.Fatalf("A outbound to B: allowed=%v err=%v, want allowed", allowed, err)
	}
	allowed, err = clientB.authorize(peerA, "icmp", 0)
	if err != nil || allowed {
		t.Fatalf("B outbound to A: allowed=%v err=%v, want denied", allowed, err)
	}
	allowed, err = clientB.authorizeInbound(peerA, "icmp", 0)
	if err != nil || !allowed {
		t.Fatalf("B inbound from A: allowed=%v err=%v, want allowed", allowed, err)
	}
	allowed, err = clientA.authorizeInbound(peerB, "icmp", 0)
	if err != nil || allowed {
		t.Fatalf("A inbound from B: allowed=%v err=%v, want denied", allowed, err)
	}
}

func TestEchoReplyHelpers(t *testing.T) {
	request, err := packet.BuildEchoRequest(net.ParseIP("100.64.0.1"), net.ParseIP("100.64.0.2"), 1, 1, []byte("x"))
	if err != nil {
		t.Fatal(err)
	}
	requestPacket := packet.IPv4Packet(request)
	if isEchoReply(requestPacket) {
		t.Fatal("echo request misdetected as reply")
	}
	reply, ok := buildEchoReply(requestPacket)
	if !ok {
		t.Fatal("echo request was not answered")
	}
	replyPacket := packet.IPv4Packet(reply)
	if !isEchoReply(replyPacket) {
		t.Fatal("echo reply not detected")
	}
	if !replyPacket.Source().Equal(net.ParseIP("100.64.0.2")) || !replyPacket.Destination().Equal(net.ParseIP("100.64.0.1")) {
		t.Fatalf("unexpected reply endpoints: %s -> %s", replyPacket.Source(), replyPacket.Destination())
	}
	if _, ok := buildEchoReply(replyPacket); ok {
		t.Fatal("echo reply was answered again")
	}
}
