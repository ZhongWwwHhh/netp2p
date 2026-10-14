package transport

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

const (
	// MaxFrameSize preserves the IPv4 packet limit used by the data plane.
	MaxFrameSize = 65535
	// MaxProtocolIDLength bounds an explicit frame protocol identifier.
	MaxProtocolIDLength = 256
	// MaxProtocolFramePayloadSize bounds any typed transport frame.
	MaxProtocolFramePayloadSize = 4 << 20
)

const (
	// ProtocolPacket identifies a raw overlay packet.
	ProtocolPacket = "packet"
	// ProtocolEnvelope identifies a manager-forwarded envelope.
	ProtocolEnvelope = "envelope"
	// ProtocolScale identifies a domain-scoped global-routing envelope.
	ProtocolScale = "scale"
)

// Frame is one explicitly typed transport frame.
type Frame struct {
	Protocol string
	Payload  []byte
}

// WriteFrame writes a raw packet frame. It preserves the legacy 65,535-byte
// packet limit even though typed frames may carry larger control payloads.
func WriteFrame(writer io.Writer, payload []byte) error {
	if len(payload) > MaxFrameSize {
		return fmt.Errorf("frame of %d bytes exceeds limit %d", len(payload), MaxFrameSize)
	}
	return WriteProtocolFrame(writer, ProtocolPacket, payload)
}

// WriteEnvelopeFrame writes a manager-forwarded envelope frame.
func WriteEnvelopeFrame(writer io.Writer, payload []byte) error {
	return WriteProtocolFrame(writer, ProtocolEnvelope, payload)
}

// WriteScaleFrame writes a global-routing scale envelope.
func WriteScaleFrame(writer io.Writer, payload []byte) error {
	return WriteProtocolFrame(writer, ProtocolScale, payload)
}

// WriteProtocolFrame writes a length-prefixed protocol ID and payload.
func WriteProtocolFrame(writer io.Writer, protocolID string, payload []byte) error {
	if protocolID == "" {
		return errors.New("empty frame protocol")
	}
	if len(protocolID) > MaxProtocolIDLength {
		return fmt.Errorf("frame protocol of %d bytes exceeds limit %d", len(protocolID), MaxProtocolIDLength)
	}
	if len(payload) == 0 {
		return errors.New("empty frame")
	}
	if len(payload) > MaxProtocolFramePayloadSize {
		return fmt.Errorf("frame payload of %d bytes exceeds limit %d", len(payload), MaxProtocolFramePayloadSize)
	}

	var header [4]byte
	binary.BigEndian.PutUint32(header[:], uint32(len(protocolID)))
	if _, err := writer.Write(header[:]); err != nil {
		return err
	}
	if _, err := io.WriteString(writer, protocolID); err != nil {
		return err
	}
	binary.BigEndian.PutUint32(header[:], uint32(len(payload)))
	if _, err := writer.Write(header[:]); err != nil {
		return err
	}
	_, err := writer.Write(payload)
	return err
}

// ReadFrame reads one raw packet frame and rejects other frame protocols.
func ReadFrame(reader io.Reader) ([]byte, error) {
	frame, err := ReadProtocolFrame(reader)
	if err != nil {
		return nil, err
	}
	if frame.Protocol != ProtocolPacket {
		return nil, fmt.Errorf("unexpected frame protocol %q", frame.Protocol)
	}
	if len(frame.Payload) > MaxFrameSize {
		return nil, fmt.Errorf("packet frame of %d bytes exceeds limit %d", len(frame.Payload), MaxFrameSize)
	}
	return frame.Payload, nil
}

// ReadEnvelopeFrame reads one forwarded-envelope frame.
func ReadEnvelopeFrame(reader io.Reader) ([]byte, error) {
	frame, err := ReadProtocolFrame(reader)
	if err != nil {
		return nil, err
	}
	if frame.Protocol != ProtocolEnvelope {
		return nil, fmt.Errorf("unexpected frame protocol %q", frame.Protocol)
	}
	return frame.Payload, nil
}

// ReadScaleFrame reads a global-routing scale envelope.
func ReadScaleFrame(reader io.Reader) ([]byte, error) {
	frame, err := ReadProtocolFrame(reader)
	if err != nil {
		return nil, err
	}
	if frame.Protocol != ProtocolScale {
		return nil, fmt.Errorf("unexpected frame protocol %q", frame.Protocol)
	}
	return frame.Payload, nil
}

// ReadProtocolFrame reads one explicitly typed frame. It returns io.EOF on a
// clean stream boundary and io.ErrUnexpectedEOF when a header or body is cut
// short by a peer, timeout, reset, or closed stream.
func ReadProtocolFrame(reader io.Reader) (Frame, error) {
	var header [4]byte
	if _, err := io.ReadFull(reader, header[:]); err != nil {
		return Frame{}, err
	}
	protocolLength := int(binary.BigEndian.Uint32(header[:]))
	if protocolLength <= 0 || protocolLength > MaxProtocolIDLength {
		return Frame{}, fmt.Errorf("invalid frame protocol length %d", protocolLength)
	}
	protocolID := make([]byte, protocolLength)
	if _, err := io.ReadFull(reader, protocolID); err != nil {
		return Frame{}, err
	}
	if _, err := io.ReadFull(reader, header[:]); err != nil {
		return Frame{}, err
	}
	payloadLength := int(binary.BigEndian.Uint32(header[:]))
	if payloadLength <= 0 || payloadLength > MaxProtocolFramePayloadSize {
		return Frame{}, fmt.Errorf("invalid frame payload length %d", payloadLength)
	}
	payload := make([]byte, payloadLength)
	if _, err := io.ReadFull(reader, payload); err != nil {
		return Frame{}, err
	}
	return Frame{Protocol: string(protocolID), Payload: payload}, nil
}
