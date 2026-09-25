package forward

import (
	"encoding/binary"
	"errors"
)

const headerSize = 2 + 2 + 2 + 2 + 1

// MaxFrameSize matches the IPv4 maximum and the framed transport limit.
const MaxFrameSize = 65535

var ErrMalformedEnvelope = errors.New("malformed forwarding envelope")

// EncodeEnvelope uses a compact little-endian header:
// sourceLen | destinationLen | assignmentLen | pathLen | ttl.
// libp2p already authenticates the transport peer; strings are carried in-band
// so the destination can bind them to certified assignments.
func EncodeEnvelope(envelope Envelope) ([]byte, error) {
	if envelope.Header.TTL == 0 {
		return nil, ErrTTLExceeded
	}
	if len(envelope.Payload) == 0 || len(envelope.Payload) > MaxFrameSize {
		return nil, errors.New("invalid forwarding payload")
	}
	source := []byte(envelope.Header.SourcePeerID)
	destination := []byte(envelope.Header.DestinationPeerID)
	assignment := []byte(envelope.Header.AssignmentID)
	path := []byte(envelope.Header.PathID)
	if len(source) > 0xffff || len(destination) > 0xffff || len(assignment) > 0xffff || len(path) > 0xffff {
		return nil, ErrMalformedEnvelope
	}
	size := headerSize + len(source) + len(destination) + len(assignment) + len(path) + len(envelope.Payload)
	wire := make([]byte, 0, size)
	wire = appendU16(wire, len(source))
	wire = appendU16(wire, len(destination))
	wire = appendU16(wire, len(assignment))
	wire = appendU16(wire, len(path))
	wire = append(wire, envelope.Header.TTL)
	wire = append(wire, source...)
	wire = append(wire, destination...)
	wire = append(wire, assignment...)
	wire = append(wire, path...)
	wire = append(wire, envelope.Payload...)
	return wire, nil
}

func DecodeEnvelope(wire []byte) (Envelope, error) {
	if len(wire) < headerSize {
		return Envelope{}, ErrMalformedEnvelope
	}
	sourceLength := int(binary.LittleEndian.Uint16(wire[0:2]))
	destinationLength := int(binary.LittleEndian.Uint16(wire[2:4]))
	assignmentLength := int(binary.LittleEndian.Uint16(wire[4:6]))
	pathLength := int(binary.LittleEndian.Uint16(wire[6:8]))
	ttl := wire[8]
	required := headerSize + sourceLength + destinationLength + assignmentLength + pathLength
	if sourceLength == 0 || destinationLength == 0 || assignmentLength == 0 || pathLength == 0 ||
		required > len(wire) {
		return Envelope{}, ErrMalformedEnvelope
	}
	offset := headerSize
	source := string(wire[offset : offset+sourceLength])
	offset += sourceLength
	destination := string(wire[offset : offset+destinationLength])
	offset += destinationLength
	assignment := string(wire[offset : offset+assignmentLength])
	offset += assignmentLength
	path := string(wire[offset : offset+pathLength])
	offset += pathLength
	return Envelope{
		Header: Header{
			SourcePeerID: source, DestinationPeerID: destination,
			AssignmentID: assignment, PathID: path, TTL: ttl,
		},
		Payload: append([]byte(nil), wire[offset:]...),
	}, nil
}

func appendU16(destination []byte, value int) []byte {
	var encoded [2]byte
	binary.LittleEndian.PutUint16(encoded[:], uint16(value))
	return append(destination, encoded[:]...)
}
