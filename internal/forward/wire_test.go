package forward

import (
	"bytes"
	"errors"
	"testing"
)

func TestEnvelopeWireRoundTrip(t *testing.T) {
	envelope := Envelope{
		Header: Header{
			SourcePeerID: "source", DestinationPeerID: "destination",
			AssignmentID: "assignment", PathID: "path", TTL: 3,
		},
		Payload: []byte("packet"),
	}
	wire, err := EncodeEnvelope(envelope)
	if err != nil {
		t.Fatal(err)
	}
	if wire[0] != MagicByte {
		t.Fatalf("envelope magic = %#x, want %#x", wire[0], MagicByte)
	}
	decoded, err := DecodeEnvelope(wire)
	if err != nil {
		t.Fatal(err)
	}
	if decoded.Header != envelope.Header || !bytes.Equal(decoded.Payload, envelope.Payload) {
		t.Fatalf("decoded %+v", decoded)
	}
}

func TestEnvelopeWireRejectsMalformed(t *testing.T) {
	envelope := Envelope{Header: Header{SourcePeerID: "s", DestinationPeerID: "d", AssignmentID: "a", PathID: "p", TTL: 1}, Payload: []byte("x")}
	if _, err := EncodeEnvelope(Envelope{Header: envelope.Header, Payload: []byte("x")}); err != nil {
		t.Fatal(err)
	}
	zeroTTL := envelope
	zeroTTL.Header.TTL = 0
	if _, err := EncodeEnvelope(zeroTTL); !errors.Is(err, ErrTTLExceeded) {
		t.Fatalf("zero ttl error = %v", err)
	}
	wire, _ := EncodeEnvelope(envelope)
	if _, err := DecodeEnvelope(wire[:headerSize-1]); err == nil {
		t.Fatal("short envelope accepted")
	}
	missingMagic := append([]byte{}, wire...)
	missingMagic[0] = 0x45
	if _, err := DecodeEnvelope(missingMagic); !errors.Is(err, ErrMalformedEnvelope) {
		t.Fatalf("missing magic error = %v", err)
	}
	truncated := append([]byte{}, wire...)
	// Corrupt the assignment length so the declared header is inconsistent
	// with the actual frame size.
	truncated[5] = 0xff
	truncated[6] = 0xff
	if _, err := DecodeEnvelope(truncated); err == nil {
		t.Fatal("inconsistent header accepted")
	}
	oversized := append([]byte{}, wire...)
	oversized[1] = 0xff
	oversized[2] = 0xff
	if _, err := DecodeEnvelope(oversized); err == nil {
		t.Fatal("oversized source length accepted")
	}
}
