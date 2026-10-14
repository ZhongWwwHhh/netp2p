package p2p

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"os"
	"testing"
	"time"

	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/netp2p/netp2p/internal/wire/pb"
)

type envelopeStream struct {
	network.Stream
	reader io.Reader
}

func (stream envelopeStream) SetReadDeadline(time.Time) error { return nil }

func (stream envelopeStream) Read(buffer []byte) (int, error) {
	return stream.reader.Read(buffer)
}

type deadlineStream struct {
	network.Stream
	deadline time.Time
}

func (stream *deadlineStream) SetReadDeadline(deadline time.Time) error {
	stream.deadline = deadline
	return nil
}

func (stream *deadlineStream) Read([]byte) (int, error) {
	delay := time.Until(stream.deadline)
	if delay <= 0 {
		return 0, os.ErrDeadlineExceeded
	}
	time.Sleep(delay)
	return 0, os.ErrDeadlineExceeded
}

func TestDecodeEnvelopeTimesOutPartialFrame(t *testing.T) {
	previousDeadline := controlReadDeadline
	controlReadDeadline = 20 * time.Millisecond
	defer func() { controlReadDeadline = previousDeadline }()

	started := time.Now()
	if _, err := DecodeEnvelope(&deadlineStream{deadline: time.Now().Add(time.Hour)}); !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("DecodeEnvelope error = %v, want %v", err, os.ErrDeadlineExceeded)
	}
	if elapsed := time.Since(started); elapsed > time.Second {
		t.Fatalf("partial frame blocked for %s", elapsed)
	}
}

func TestEnvelopeRejectsOversizedPayload(t *testing.T) {
	var buffer bytes.Buffer
	if err := EncodeEnvelope(&buffer, FrameProtocol, make([]byte, MaxEnvelopePayloadLength+1)); err == nil {
		t.Fatal("encoding an oversized payload should fail")
	}

	frame := bytes.Buffer{}
	var header [4]byte
	binary.BigEndian.PutUint32(header[:], 1)
	if _, err := frame.Write(header[:]); err != nil {
		t.Fatal(err)
	}
	if _, err := frame.WriteString("x"); err != nil {
		t.Fatal(err)
	}
	binary.BigEndian.PutUint32(header[:], MaxEnvelopePayloadLength+1)
	if _, err := frame.Write(header[:]); err != nil {
		t.Fatal(err)
	}
	if _, err := DecodeEnvelope(envelopeStream{reader: bytes.NewReader(frame.Bytes())}); err == nil {
		t.Fatal("decoding an oversized payload should fail")
	}
}

func TestTwoNodesOpenSecureStream(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	nodeA, err := New(ctx, Config{})
	if err != nil {
		t.Fatal(err)
	}
	defer nodeA.Close()
	nodeB, err := New(ctx, Config{})
	if err != nil {
		t.Fatal(err)
	}
	defer nodeB.Close()

	received := make(chan network.Stream, 1)
	nodeA.Handle(FrameProtocol, func(stream network.Stream) {
		received <- stream
	})

	addresses := nodeA.Addresses()
	if len(addresses) == 0 {
		t.Fatal("node A has no addresses")
	}
	var target peer.AddrInfo
	for _, address := range addresses {
		if info, parseErr := peer.AddrInfoFromString(address); parseErr == nil {
			target = *info
			break
		}
	}
	if target.ID == "" {
		t.Fatal("could not parse node A address")
	}
	if err := nodeB.Host.Connect(ctx, target); err != nil {
		t.Fatal(err)
	}
	if err := nodeB.Send(ctx, nodeA.Host.ID(), FrameProtocol, &pb.ProbeRequest{Kind: "hello", Nonce: 1}); err != nil {
		t.Fatal(err)
	}
	select {
	case <-received:
	case <-ctx.Done():
		t.Fatal("handler did not receive stream")
	}
}
