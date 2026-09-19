package packet

import (
	"net"
	"testing"
	"time"
)

func TestUDPPacketSinkRoundTrip(t *testing.T) {
	receiver, err := NewUDPPacketSink("127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer receiver.Close()
	receiverAddress := receiver.LocalAddr().String()
	sender, err := net.Dial("udp", receiverAddress)
	if err != nil {
		t.Fatal(err)
	}
	defer sender.Close()

	payload := []byte{0x45, 0x00, 0x00, 0x14, 0x00, 0x00, 0x00, 0x00, 0x40, 0x01, 0x00, 0x00, 0x64, 0x40, 0x00, 0x01, 0x64, 0x40, 0x00, 0x02}
	frame, err := EncodeFrame(payload)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := sender.Write(frame); err != nil {
		t.Fatal(err)
	}
	done := make(chan []byte, 1)
	go func() {
		packet, err := receiver.ReadPacket()
		if err == nil {
			done <- packet
		}
	}()
	select {
	case received := <-done:
		if string(received) != string(payload) {
			t.Fatalf("payload mismatch: %v", received)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for packet")
	}
}

func TestUDPPacketSinkRejectsOversizedWrite(t *testing.T) {
	sink, err := NewUDPPacketSink("127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer sink.Close()
	if err := sink.WritePacket(make([]byte, MaxPacketSize+1)); err == nil {
		t.Fatal("oversized packet accepted")
	}
}

func TestBuildAndParseEcho(t *testing.T) {
	source := net.ParseIP("100.64.0.11")
	target := net.ParseIP("100.64.0.12")
	request, err := BuildEchoRequest(source, target, 0x1234, 7, []byte("hello"))
	if err != nil {
		t.Fatal(err)
	}
	ipPacket, icmp, err := ParseEchoRequest(request)
	if err != nil {
		t.Fatal(err)
	}
	if icmp.Identifier() != 0x1234 || icmp.Sequence() != 7 {
		t.Fatalf("unexpected icmp fields: id=%d seq=%d", icmp.Identifier(), icmp.Sequence())
	}
	if !ipPacket.Destination().Equal(target) {
		t.Fatalf("destination mismatch: %s", ipPacket.Destination())
	}
	reply, err := BuildEchoReply(ipPacket, icmp)
	if err != nil {
		t.Fatal(err)
	}
	replyPacket := IPv4Packet(reply)
	if err := replyPacket.Validate(); err != nil {
		t.Fatal(err)
	}
	if !replyPacket.Source().Equal(target) || !replyPacket.Destination().Equal(source) {
		t.Fatalf("unexpected reply endpoints: %s -> %s", replyPacket.Source(), replyPacket.Destination())
	}
	replyICMP := ICMPMessage(replyPacket[replyPacket.HeaderLength():])
	if replyICMP.Type() != ICMPTypeEchoReply {
		t.Fatalf("unexpected reply type %d", replyICMP.Type())
	}
}

// TestUDPPacketSinkWriteRequiresPeer ensures a reply is not silently dropped
// when no local sender address is known yet.
func TestUDPPacketSinkWriteRequiresPeer(t *testing.T) {
	sink, err := NewUDPPacketSink("127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer sink.Close()
	if err := sink.WritePacket([]byte{0x45, 0x00}); err == nil {
		t.Fatal("write without a known peer should fail")
	}
}
