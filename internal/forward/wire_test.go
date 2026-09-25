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
	truncated := append([]byte{}, wire...)
	truncated[0] = 99
	if _, err := DecodeEnvelope(truncated); err == nil {
		t.Fatal("inconsistent header accepted")
	}
}
