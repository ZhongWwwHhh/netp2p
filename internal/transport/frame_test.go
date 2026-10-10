package transport

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"testing"

	"github.com/netp2p/netp2p/internal/forward"
)

func TestWriteReadFrameRoundTrip(t *testing.T) {
	payloads := [][]byte{
		{0x45, 0x00},
		bytes.Repeat([]byte{0xab}, 1400),
		bytes.Repeat([]byte{0xcd}, MaxFrameSize),
	}
	var buffer bytes.Buffer
	for _, payload := range payloads {
		if err := WriteFrame(&buffer, payload); err != nil {
			t.Fatalf("write: %v", err)
		}
	}
	for index, want := range payloads {
		got, err := ReadFrame(&buffer)
		if err != nil {
			t.Fatalf("frame %d: %v", index, err)
		}
		if !bytes.Equal(got, want) {
			t.Fatalf("frame %d mismatch: %d bytes vs %d", index, len(got), len(want))
		}
	}
	if _, err := ReadFrame(&buffer); !errors.Is(err, io.EOF) {
		t.Fatalf("trailing read error = %v, want EOF", err)
	}
}

func TestWriteFrameRejectsOversizedPayload(t *testing.T) {
	var buffer bytes.Buffer
	if err := WriteFrame(&buffer, make([]byte, MaxFrameSize+1)); err == nil {
		t.Fatal("expected oversized frame to be rejected")
	}
	if err := WriteFrame(&buffer, nil); err == nil {
		t.Fatal("expected empty frame to be rejected")
	}
}

func TestProtocolFrameRoundTrip(t *testing.T) {
	var buffer bytes.Buffer
	if err := WriteProtocolFrame(&buffer, ProtocolEnvelope, []byte("forwarded")); err != nil {
		t.Fatal(err)
	}
	frame, err := ReadProtocolFrame(&buffer)
	if err != nil {
		t.Fatal(err)
	}
	if frame.Protocol != ProtocolEnvelope || string(frame.Payload) != "forwarded" {
		t.Fatalf("frame = %+v", frame)
	}
	if _, err := ReadEnvelopeFrame(bytes.NewReader(nil)); !errors.Is(err, io.EOF) {
		t.Fatalf("empty reader error = %v, want EOF", err)
	}
}

func TestReadProtocolFrameRejectsInvalidInput(t *testing.T) {
	cases := map[string][]byte{
		"zero protocol":      append(u32(0), 'p'),
		"protocol too large": append(u32(MaxProtocolIDLength+1), 'p'),
		"truncated protocol": append(u32(2), 'p'),
		"zero payload":       typedFrame(ProtocolPacket, nil),
		"payload too large":  append(append(append(u32(len(ProtocolPacket)), []byte(ProtocolPacket)...), u32(MaxProtocolFramePayloadSize+1)...), 'x'),
		"truncated payload":  append(append(append(u32(len(ProtocolPacket)), []byte(ProtocolPacket)...), u32(10)...), 'x'),
	}
	for name, data := range cases {
		if _, err := ReadProtocolFrame(bytes.NewReader(data)); err == nil {
			t.Fatalf("%s: expected error", name)
		}
	}
	if _, err := ReadFrame(bytes.NewReader(typedFrame(ProtocolEnvelope, []byte("x")))); err == nil {
		t.Fatal("ReadFrame must reject envelope frames")
	}
	if _, err := ReadEnvelopeFrame(bytes.NewReader(typedFrame(ProtocolPacket, []byte("x")))); err == nil {
		t.Fatal("ReadEnvelopeFrame must reject packet frames")
	}
}

func u32(value int) []byte {
	var buffer [4]byte
	binary.BigEndian.PutUint32(buffer[:], uint32(value))
	return buffer[:]
}

func typedFrame(protocol string, payload []byte) []byte {
	var buffer bytes.Buffer
	buffer.Write(u32(len(protocol)))
	buffer.WriteString(protocol)
	buffer.Write(u32(len(payload)))
	buffer.Write(payload)
	return buffer.Bytes()
}

func TestFrameProtocolForClassifiesLegacySend(t *testing.T) {
	envelope, err := forward.EncodeEnvelope(forward.Envelope{
		Header: forward.Header{
			SourcePeerID: "source", DestinationPeerID: "destination",
			AssignmentID: "assignment", PathID: "path", TTL: 3,
		},
		Payload: []byte("forwarded"),
	})
	if err != nil {
		t.Fatal(err)
	}
	if got := frameProtocolFor(envelope); got != ProtocolEnvelope {
		t.Fatalf("envelope protocol = %q", got)
	}
	if got := frameProtocolFor([]byte{0x45, 0x00, 0x00, 0x14}); got != ProtocolPacket {
		t.Fatalf("IPv4 protocol = %q", got)
	}
	if got := frameProtocolFor([]byte{forward.MagicByte, 0x00, 0x00}); got != ProtocolPacket {
		t.Fatalf("malformed envelope protocol = %q", got)
	}
}
