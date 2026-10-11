package forward

import (
	"encoding/binary"
	"errors"
)

const (
	ScaleMagicByte  = 0x03
	scaleHeaderSize = 1 + 6*2 + 1 + 8 + 8
)

var (
	ErrMalformedScaleEnvelope = errors.New("malformed scale forwarding envelope")
	ErrScaleUnauthorized      = errors.New("scale forwarding envelope is not authorized")
	ErrFaceBudgetExceeded     = errors.New("face token budget exceeded")
)

// ScaleEnvelope removes the per-peer-pair AssignmentID from the hot data path.
// A manager authorizes source, destination scope, flow class, and path family
// from compiled certified state.
type ScaleHeader struct {
	SourcePeerID      string
	DestinationPeerID string
	RoutingDomainID   string
	PathFamilyID      string
	PathInstanceID    string
	FlowClass         string
	FlowHash          uint64
	Sequence          uint64
	TTL               uint8
}

type ScaleEnvelope struct {
	Header  ScaleHeader
	Payload []byte
}

func EncodeScaleEnvelope(envelope ScaleEnvelope) ([]byte, error) {
	if envelope.Header.TTL == 0 {
		return nil, ErrTTLExceeded
	}
	if len(envelope.Payload) == 0 || len(envelope.Payload) > MaxFrameSize {
		return nil, errors.New("invalid forwarding payload")
	}
	source := []byte(envelope.Header.SourcePeerID)
	destination := []byte(envelope.Header.DestinationPeerID)
	routingDomain := []byte(envelope.Header.RoutingDomainID)
	pathFamily := []byte(envelope.Header.PathFamilyID)
	pathInstance := []byte(envelope.Header.PathInstanceID)
	flowClass := []byte(envelope.Header.FlowClass)
	if len(source) > 0xffff || len(destination) > 0xffff || len(routingDomain) > 0xffff ||
		len(pathFamily) > 0xffff || len(pathInstance) > 0xffff || len(flowClass) > 0xffff {
		return nil, ErrMalformedScaleEnvelope
	}
	if len(source) == 0 || len(destination) == 0 || len(routingDomain) == 0 ||
		len(pathFamily) == 0 || len(pathInstance) == 0 || len(flowClass) == 0 {
		return nil, ErrMalformedScaleEnvelope
	}
	if scaleHeaderSize+len(source)+len(destination)+len(routingDomain)+len(pathFamily)+len(pathInstance)+len(flowClass)+len(envelope.Payload) > MaxFrameSize {
		return nil, ErrMalformedScaleEnvelope
	}

	wire := make([]byte, 0, scaleHeaderSize+len(envelope.Payload))
	wire = append(wire, ScaleMagicByte)
	wire = appendU16(wire, len(source))
	wire = appendU16(wire, len(destination))
	wire = appendU16(wire, len(routingDomain))
	wire = appendU16(wire, len(pathFamily))
	wire = appendU16(wire, len(pathInstance))
	wire = appendU16(wire, len(flowClass))
	wire = append(wire, envelope.Header.TTL)
	var fixed [16]byte
	binary.LittleEndian.PutUint64(fixed[:8], envelope.Header.FlowHash)
	binary.LittleEndian.PutUint64(fixed[8:], envelope.Header.Sequence)
	wire = append(wire, fixed[:]...)
	wire = append(wire, source...)
	wire = append(wire, destination...)
	wire = append(wire, routingDomain...)
	wire = append(wire, pathFamily...)
	wire = append(wire, pathInstance...)
	wire = append(wire, flowClass...)
	wire = append(wire, envelope.Payload...)
	return wire, nil
}

func DecodeScaleEnvelope(wire []byte) (ScaleEnvelope, error) {
	if len(wire) < scaleHeaderSize || len(wire) > MaxFrameSize || wire[0] != ScaleMagicByte {
		return ScaleEnvelope{}, ErrMalformedScaleEnvelope
	}
	sourceLength := int(binary.LittleEndian.Uint16(wire[1:3]))
	destinationLength := int(binary.LittleEndian.Uint16(wire[3:5]))
	domainLength := int(binary.LittleEndian.Uint16(wire[5:7]))
	familyLength := int(binary.LittleEndian.Uint16(wire[7:9]))
	instanceLength := int(binary.LittleEndian.Uint16(wire[9:11]))
	classLength := int(binary.LittleEndian.Uint16(wire[11:13]))
	ttl := wire[13]
	flowHash := binary.LittleEndian.Uint64(wire[14:22])
	sequence := binary.LittleEndian.Uint64(wire[22:30])
	required := scaleHeaderSize + sourceLength + destinationLength + domainLength + familyLength + instanceLength + classLength
	if sourceLength == 0 || destinationLength == 0 || domainLength == 0 || familyLength == 0 ||
		instanceLength == 0 || classLength == 0 || required > len(wire) {
		return ScaleEnvelope{}, ErrMalformedScaleEnvelope
	}
	offset := scaleHeaderSize
	read := func(length int) string {
		value := string(wire[offset : offset+length])
		offset += length
		return value
	}
	header := ScaleHeader{
		SourcePeerID: read(sourceLength), DestinationPeerID: read(destinationLength),
		RoutingDomainID: read(domainLength), PathFamilyID: read(familyLength),
		PathInstanceID: read(instanceLength), FlowClass: read(classLength),
		FlowHash: flowHash, Sequence: sequence, TTL: ttl,
	}
	if offset >= len(wire) {
		return ScaleEnvelope{}, ErrMalformedScaleEnvelope
	}
	return ScaleEnvelope{Header: header, Payload: append([]byte(nil), wire[offset:]...)}, nil
}

type ScaleAuthorization struct {
	FaceID              string
	NextHop             string
	ExpectedPredecessor string
	Destination         bool
}

type ScaleAuthorizer func(sourcePeerID, destinationPeerID, routingDomainID, pathFamilyID, flowClass string) (ScaleAuthorization, error)
