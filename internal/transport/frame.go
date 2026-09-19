// Package transport carries overlay packets over long-lived libp2p streams.
//
// Each peer pair keeps one persistent outbound stream per direction instead of
// opening a stream and JSON-encoding an envelope per packet. That framing costs
// a stream handshake and a base64 expansion per packet, which makes TCP over the
// overlay impossible.
package transport

import (
	"encoding/binary"
	"fmt"
	"io"
)

// MaxFrameSize bounds a single overlay packet. It matches the IPv4 maximum so
// the framing never becomes the limiting factor.
const MaxFrameSize = 65535

// WriteFrame writes a length-prefixed frame.
func WriteFrame(writer io.Writer, payload []byte) error {
	if len(payload) == 0 {
		return fmt.Errorf("empty frame")
	}
	if len(payload) > MaxFrameSize {
		return fmt.Errorf("frame of %d bytes exceeds limit %d", len(payload), MaxFrameSize)
	}
	var header [4]byte
	binary.BigEndian.PutUint32(header[:], uint32(len(payload)))
	if _, err := writer.Write(header[:]); err != nil {
		return err
	}
	_, err := writer.Write(payload)
	return err
}

// ReadFrame reads one length-prefixed frame, returning io.EOF when the stream
// ends cleanly between frames.
func ReadFrame(reader io.Reader) ([]byte, error) {
	var header [4]byte
	if _, err := io.ReadFull(reader, header[:]); err != nil {
		return nil, err
	}
	length := int(binary.BigEndian.Uint32(header[:]))
	if length <= 0 || length > MaxFrameSize {
		return nil, fmt.Errorf("invalid frame length %d", length)
	}
	payload := make([]byte, length)
	if _, err := io.ReadFull(reader, payload); err != nil {
		return nil, err
	}
	return payload, nil
}
