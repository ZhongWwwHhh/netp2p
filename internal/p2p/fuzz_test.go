package p2p

import (
	"bytes"
	"context"
	"encoding/binary"
	"io"
	"testing"
	"time"

	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
)

type fuzzEnvelopeStream struct {
	network.Stream
	reader io.Reader
}

func (stream fuzzEnvelopeStream) Read(buffer []byte) (int, error) {
	return stream.reader.Read(buffer)
}

func FuzzDecodeEnvelope(f *testing.F) {
	f.Add([]byte{0, 0, 0, 1, 'x', 0, 0, 0, 1, 'y'})
	f.Add([]byte{0xff, 0xff, 0xff, 0xff})
	f.Add([]byte{0, 0, 0, 1, 'x', 0xff, 0xff, 0xff, 0xff})
	f.Add([]byte{0, 0, 0, 1, 'x', 0, 0, 0, 0})

	f.Fuzz(func(t *testing.T, data []byte) {
		envelope, err := DecodeEnvelope(fuzzEnvelopeStream{reader: bytes.NewReader(data)})
		if err != nil {
			return
		}
		if len(envelope.Protocol) > MaxProtocolIDLength || len(envelope.Payload) > MaxEnvelopePayloadLength {
			t.Fatalf("decoded out-of-range envelope: %+v", envelope)
		}
	})
}

func TestLibp2pMalformedStreamStress(t *testing.T) {
	if testing.Short() {
		t.Skip("short mode skips the local libp2p stress run")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	server, err := New(ctx, Config{})
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	client, err := New(ctx, Config{})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()

	results := make(chan error, 32)
	server.Handle(FrameProtocol, func(stream network.Stream) {
		_, decodeErr := DecodeEnvelope(stream)
		_ = stream.Close()
		results <- decodeErr
	})

	var target peer.AddrInfo
	for _, address := range server.Addresses() {
		if info, parseErr := peer.AddrInfoFromString(address); parseErr == nil {
			target = *info
			break
		}
	}
	if target.ID == "" {
		t.Fatal("server has no usable local address")
	}
	if err := client.Host.Connect(ctx, target); err != nil {
		t.Fatal(err)
	}

	payloads := [][]byte{
		{0xff, 0xff, 0xff, 0xff},
		{0, 0, 0, 1, 'x', 0xff, 0xff, 0xff, 0xff},
		{0, 0, 0, 1, 'x', 0, 0, 0, 8, 1, 2, 3},
		{0, 0, 1, 0},
	}
	var random [64]byte
	for index := range random {
		random[index] = byte(index*31 + 7)
	}
	payloads = append(payloads, random[:])

	var header [4]byte
	binary.BigEndian.PutUint32(header[:], 1)
	valid := append(header[:], 'x')
	binary.BigEndian.PutUint32(header[:], 2)
	valid = append(valid, header[:]...)
	valid = append(valid, 'o', 'k')
	payloads = append(payloads, valid)

	for iteration := 0; iteration < 24; iteration++ {
		payload := payloads[iteration%len(payloads)]
		stream, err := client.Host.NewStream(ctx, server.Host.ID(), FrameProtocol)
		if err != nil {
			t.Fatalf("open stream %d: %v", iteration, err)
		}
		_ = stream.SetDeadline(time.Now().Add(2 * time.Second))
		if _, err := stream.Write(payload); err != nil {
			_ = stream.Close()
			t.Fatalf("write stream %d: %v", iteration, err)
		}
		_ = stream.CloseWrite()
		select {
		case <-results:
		case <-ctx.Done():
			_ = stream.Close()
			t.Fatalf("handler did not finish stream %d: %v", iteration, ctx.Err())
		}
		_ = stream.Close()
	}
}
