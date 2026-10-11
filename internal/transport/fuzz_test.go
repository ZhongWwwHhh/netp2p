package transport

import (
	"bytes"
	"encoding/binary"
	"testing"

	"github.com/netp2p/netp2p/internal/forward"
)

func FuzzReadProtocolFrame(f *testing.F) {
	f.Add([]byte{0, 0, 0, 1, 'p', 0, 0, 0, 1, 'x'})
	f.Add([]byte{0xff, 0xff, 0xff, 0xff})
	f.Add([]byte{0, 0, 0, 2, 'p', 0xff, 0xff, 0xff, 0xff})
	f.Add([]byte{0, 0, 0, 1, 'p', 0, 0, 0, 0})

	f.Fuzz(func(t *testing.T, data []byte) {
		frame, err := ReadProtocolFrame(bytes.NewReader(data))
		if err != nil {
			return
		}
		if frame.Protocol == "" || len(frame.Payload) == 0 {
			t.Fatalf("accepted invalid frame: %+v", frame)
		}
	})
}

func FuzzForwardEnvelope(f *testing.F) {
	var valid bytes.Buffer
	encoded, err := forward.EncodeEnvelope(forward.Envelope{
		Header: forward.Header{
			SourcePeerID: "source", DestinationPeerID: "destination",
			AssignmentID: "assignment", PathID: "path", TTL: 4,
		},
		Payload: []byte("payload"),
	})
	if err != nil {
		f.Fatal(err)
	}
	valid.Write(encoded)
	f.Add(valid.Bytes())
	f.Add([]byte{forward.MagicByte, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x00})
	f.Add([]byte{0x45, 0, 0, 0})

	f.Fuzz(func(t *testing.T, data []byte) {
		envelope, err := forward.DecodeEnvelope(data)
		if err != nil {
			return
		}
		if envelope.Header.TTL == 0 {
			t.Fatal("decoded a zero-TTL envelope")
		}
	})
}

func TestMalformedLengthsDoNotAllocatePayload(t *testing.T) {
	var header [4]byte
	for _, length := range []uint32{0xffffffff, uint32(MaxProtocolFramePayloadSize + 1)} {
		data := make([]byte, 0, 4+len(ProtocolPacket)+4)
		binary.BigEndian.PutUint32(header[:], uint32(len(ProtocolPacket)))
		data = append(data, header[:]...)
		data = append(data, ProtocolPacket...)
		binary.BigEndian.PutUint32(header[:], length)
		data = append(data, header[:]...)
		if _, err := ReadProtocolFrame(bytes.NewReader(data)); err == nil {
			t.Fatalf("length %d was accepted", length)
		}
	}
}

func TestDecodeEnvelopeRejectsZeroTTL(t *testing.T) {
	var wire bytes.Buffer
	header := []byte{
		forward.MagicByte,
		1, 0, // source length
		1, 0, // destination length
		1, 0, // assignment length
		1, 0, // path length
		0, // TTL
	}
	wire.Write(header)
	wire.WriteString("sdapx")
	if _, err := forward.DecodeEnvelope(wire.Bytes()); err == nil {
		t.Fatal("DecodeEnvelope accepted a zero-TTL frame")
	}
}
