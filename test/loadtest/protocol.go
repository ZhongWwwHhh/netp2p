// Package loadtest provides protocol-complete scale fixtures for NetP2P.
//
// The package is intentionally outside the product packages. It consumes the
// real model, packet, and policy types where they exist, and defines the
// missing global-routing protocol shapes from the internal design so that
// product integration can replace the adapters without changing the harness.
package loadtest

import (
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"hash/fnv"
	"math"
	"sort"
	"strings"
	"time"

	"github.com/netp2p/netp2p/internal/model"
	"github.com/netp2p/netp2p/internal/packet"
)

type FlowClass string

const (
	FlowLatency     FlowClass = "latency"
	FlowThroughput  FlowClass = "throughput"
	FlowCost        FlowClass = "cost"
	FlowReliability FlowClass = "reliability"
	FlowRealtime    FlowClass = "realtime"
)

var AllFlowClasses = []FlowClass{
	FlowLatency,
	FlowThroughput,
	FlowCost,
	FlowReliability,
	FlowRealtime,
}

func ValidFlowClass(class FlowClass) bool {
	switch class {
	case FlowLatency, FlowThroughput, FlowCost, FlowReliability, FlowRealtime:
		return true
	default:
		return false
	}
}

// RoutingDomainKey identifies a routing allocation without naming a peer pair.
type RoutingDomainKey struct {
	SourceManagerID  string    `json:"sourceManagerId"`
	SourceGroupID    string    `json:"sourceGroupId"`
	DestinationScope string    `json:"destinationScope"`
	FlowClass        FlowClass `json:"flowClass"`
}

func (key RoutingDomainKey) String() string {
	return key.SourceManagerID + "\x00" + key.SourceGroupID + "\x00" + key.DestinationScope + "\x00" + string(key.FlowClass)
}

// PathFamily is the certified candidate unit. It is deliberately coarse: a
// family covers groups/scopes/classes, never one source-destination pair.
type PathFamily struct {
	ID                 string         `json:"id"`
	Kind               model.PathKind `json:"kind"`
	ManagerHops        []string       `json:"managerHops,omitempty"`
	SourceGroups       []string       `json:"sourceGroups"`
	DestinationScopes  []string       `json:"destinationScopes"`
	FlowClasses        []FlowClass    `json:"flowClasses"`
	MaxRTTMilliseconds float64        `json:"maxRttMilliseconds"`
	MaxLossPercent     float64        `json:"maxLossPercent"`
	MinBandwidthMbps   float64        `json:"minBandwidthMbps"`
}

type EdgeTelemetry struct {
	EdgeID             string    `json:"edgeId"`
	ManagerID          string    `json:"managerId"`
	QueueDepth         float64   `json:"queueDepth"`
	QueueDepthEWMA     float64   `json:"queueDepthEwma"`
	SendBytesPerSecond float64   `json:"sendBytesPerSecond"`
	DropRate           float64   `json:"dropRate"`
	ActiveFlows        uint64    `json:"activeFlows"`
	RTTMilliseconds    float64   `json:"rttMilliseconds"`
	JitterMilliseconds float64   `json:"jitterMilliseconds"`
	LossPercent        float64   `json:"lossPercent"`
	MeasuredBandwidth  float64   `json:"measuredBandwidth"`
	MonthlyUsedBytes   uint64    `json:"monthlyUsedBytes"`
	MonthlyLimitBytes  uint64    `json:"monthlyLimitBytes"`
	UpdatedAt          time.Time `json:"updatedAt"`
}

type FlowDemandSample struct {
	PeerID           string    `json:"peerId"`
	SourceGroupID    string    `json:"sourceGroupId"`
	DestinationScope string    `json:"destinationScope"`
	FlowClass        FlowClass `json:"flowClass"`
	Bytes            uint64    `json:"bytes"`
	DurationMS       uint64    `json:"durationMs"`
	PathID           string    `json:"pathId"`
	ObservedAt       time.Time `json:"observedAt"`
}

type DemandReport struct {
	PeerID          string             `json:"peerId"`
	Samples         []FlowDemandSample `json:"samples"`
	ReportingWindow time.Duration      `json:"reportingWindow"`
}

type PathWeight struct {
	PathID string  `json:"pathId"`
	Weight float64 `json:"weight"`
	Reason string  `json:"reason,omitempty"`
}

type PathAllocation struct {
	Key   RoutingDomainKey `json:"key"`
	Paths []PathWeight     `json:"paths"`
}

type RoutingEpoch struct {
	NetworkID        string           `json:"networkId"`
	SnapshotHeight   uint64           `json:"snapshotHeight"`
	CandidateSetHash []byte           `json:"candidateSetHash"`
	Version          uint64           `json:"version"`
	GeneratedAt      time.Time        `json:"generatedAt"`
	ExpiresAt        time.Time        `json:"expiresAt"`
	Allocations      []PathAllocation `json:"allocations"`
	PlannerDigest    []byte           `json:"plannerDigest"`
	ManagerID        string           `json:"managerId"`
	Signature        []byte           `json:"signature"`
}

type ForwardingEnvelope struct {
	SourcePeerID      string           `json:"sourcePeerId"`
	DestinationPeerID string           `json:"destinationPeerId"`
	Domain            RoutingDomainKey `json:"domain"`
	PathFamilyID      string           `json:"pathFamilyId"`
	PathInstanceID    string           `json:"pathInstanceId"`
	FlowClass         FlowClass        `json:"flowClass"`
	Protocol          uint8            `json:"protocol"`
	DestinationPort   uint16           `json:"destinationPort"`
	FlowHash          uint64           `json:"flowHash"`
	Sequence          uint64           `json:"sequence"`
	TTL               uint8            `json:"ttl"`
	Payload           []byte           `json:"payload"`
	FEC               *FECExtension    `json:"fec,omitempty"`
}

type FECExtension struct {
	GroupID         string `json:"groupId"`
	GroupSize       uint16 `json:"groupSize"`
	Index           uint16 `json:"index"`
	RedundancyCount uint16 `json:"redundancyCount"`
	Codec           string `json:"codec"`
}

func FlowHash(flow packet.Flow) uint64 {
	hash := fnv.New64a()
	var buffer [18]byte
	buffer[0] = flow.Protocol
	binary.BigEndian.PutUint16(buffer[1:3], flow.SourcePort)
	binary.BigEndian.PutUint16(buffer[3:5], flow.DestinationPort)
	if flow.Source.IsValid() {
		source := flow.Source.As4()
		copy(buffer[5:9], source[:])
	}
	if flow.Destination.IsValid() {
		destination := flow.Destination.As4()
		copy(buffer[9:13], destination[:])
	}
	_, _ = hash.Write(buffer[:])
	return hash.Sum64()
}

func CandidateSetHash(families []PathFamily) []byte {
	encoded := make([]string, 0, len(families))
	for _, family := range families {
		encoded = append(encoded, fmt.Sprintf("%s|%s|%s|%s|%s",
			family.ID,
			family.Kind,
			strings.Join(family.ManagerHops, ","),
			strings.Join(family.SourceGroups, ","),
			strings.Join(family.DestinationScopes, ","),
		))
	}
	sort.Strings(encoded)
	digest := sha256.New()
	for _, value := range encoded {
		_, _ = digest.Write([]byte(value))
		_, _ = digest.Write([]byte{0})
	}
	return digest.Sum(nil)
}

func PlannerDigest(epoch RoutingEpoch) []byte {
	digest := sha256.New()
	_ = binary.Write(digest, binary.LittleEndian, epoch.Version)
	_, _ = digest.Write(epoch.CandidateSetHash)
	for _, allocation := range epoch.Allocations {
		_, _ = digest.Write([]byte(allocation.Key.String()))
		_, _ = digest.Write([]byte{0})
		for _, weight := range allocation.Paths {
			_, _ = digest.Write([]byte(weight.PathID))
			_, _ = digest.Write([]byte{0})
			_ = binary.Write(digest, binary.LittleEndian, weight.Weight)
		}
	}
	return digest.Sum(nil)
}

const epochMagic = uint32(0x4e50324c)

func appendUvarint(destination []byte, value uint64) []byte {
	var buffer [binary.MaxVarintLen64]byte
	length := binary.PutUvarint(buffer[:], value)
	return append(destination, buffer[:length]...)
}

func appendString(destination []byte, value string) []byte {
	destination = appendUvarint(destination, uint64(len(value)))
	return append(destination, value...)
}

func appendBytes(destination []byte, value []byte) []byte {
	destination = appendUvarint(destination, uint64(len(value)))
	return append(destination, value...)
}

// EncodeEpoch uses a compact string dictionary. At 10,000 domains and five
// flow classes, JSON field names and repeated IDs would exceed the 5 MB epoch
// budget even though the semantic object remains small.
func EncodeEpoch(epoch RoutingEpoch) ([]byte, error) {
	dictionary := make(map[string]uint32)
	values := make([]string, 0, 64)
	intern := func(value string) uint32 {
		if index, exists := dictionary[value]; exists {
			return index
		}
		index := uint32(len(values))
		dictionary[value] = index
		values = append(values, value)
		return index
	}
	networkIndex := intern(epoch.NetworkID)
	managerIndex := intern(epoch.ManagerID)
	allocationIndices := make([]uint32, 0, len(epoch.Allocations)*8)
	for _, allocation := range epoch.Allocations {
		allocationIndices = append(allocationIndices,
			intern(allocation.Key.SourceManagerID),
			intern(allocation.Key.SourceGroupID),
			intern(allocation.Key.DestinationScope),
			intern(string(allocation.Key.FlowClass)),
			uint32(len(allocation.Paths)),
		)
		for _, path := range allocation.Paths {
			allocationIndices = append(allocationIndices, intern(path.PathID), intern(path.Reason))
		}
	}

	encoded := make([]byte, 0, 128+len(epoch.Allocations)*32)
	var header [4]byte
	binary.LittleEndian.PutUint32(header[:], epochMagic)
	encoded = append(encoded, header[:]...)
	encoded = appendUvarint(encoded, uint64(len(values)))
	for _, value := range values {
		encoded = appendString(encoded, value)
	}
	encoded = appendUvarint(encoded, uint64(networkIndex))
	encoded = appendUvarint(encoded, epoch.SnapshotHeight)
	encoded = appendBytes(encoded, epoch.CandidateSetHash)
	encoded = appendUvarint(encoded, epoch.Version)
	encoded = appendUvarint(encoded, uint64(epoch.GeneratedAt.UnixNano()))
	encoded = appendUvarint(encoded, uint64(epoch.ExpiresAt.UnixNano()))
	encoded = appendUvarint(encoded, uint64(len(epoch.Allocations)))
	for _, index := range allocationIndices {
		encoded = appendUvarint(encoded, uint64(index))
	}
	for _, allocation := range epoch.Allocations {
		for _, path := range allocation.Paths {
			var weight [4]byte
			binary.LittleEndian.PutUint32(weight[:], math.Float32bits(float32(path.Weight)))
			encoded = append(encoded, weight[:]...)
		}
	}
	encoded = appendBytes(encoded, epoch.PlannerDigest)
	encoded = appendUvarint(encoded, uint64(managerIndex))
	encoded = appendBytes(encoded, epoch.Signature)
	return encoded, nil
}

type epochDecoder struct {
	data   []byte
	offset int
}

func (decoder *epochDecoder) uvarint() (uint64, error) {
	value, length := binary.Uvarint(decoder.data[decoder.offset:])
	if length <= 0 {
		return 0, errors.New("invalid epoch varint")
	}
	decoder.offset += length
	return value, nil
}

func (decoder *epochDecoder) bytes() ([]byte, error) {
	length, err := decoder.uvarint()
	if err != nil {
		return nil, err
	}
	if uint64(len(decoder.data)-decoder.offset) < length {
		return nil, errors.New("truncated epoch bytes")
	}
	value := append([]byte(nil), decoder.data[decoder.offset:decoder.offset+int(length)]...)
	decoder.offset += int(length)
	return value, nil
}

func (decoder *epochDecoder) string() (string, error) {
	value, err := decoder.bytes()
	return string(value), err
}

func DecodeEpoch(encoded []byte) (RoutingEpoch, error) {
	decoder := &epochDecoder{data: encoded}
	if len(encoded) < 4 || binary.LittleEndian.Uint32(encoded) != epochMagic {
		return RoutingEpoch{}, errors.New("invalid epoch magic")
	}
	decoder.offset = 4
	count, err := decoder.uvarint()
	if err != nil {
		return RoutingEpoch{}, err
	}
	if count > uint64(len(encoded)) {
		return RoutingEpoch{}, errors.New("invalid epoch dictionary size")
	}
	values := make([]string, count)
	for index := uint64(0); index < count; index++ {
		value, err := decoder.string()
		if err != nil {
			return RoutingEpoch{}, err
		}
		values[index] = value
	}
	lookup := func(index uint64) (string, error) {
		if index >= uint64(len(values)) {
			return "", errors.New("epoch dictionary index out of range")
		}
		return values[index], nil
	}
	networkIndex, err := decoder.uvarint()
	if err != nil {
		return RoutingEpoch{}, err
	}
	epoch := RoutingEpoch{}
	epoch.NetworkID, err = lookup(networkIndex)
	if err != nil {
		return RoutingEpoch{}, err
	}
	if epoch.SnapshotHeight, err = decoder.uvarint(); err != nil {
		return RoutingEpoch{}, err
	}
	if epoch.CandidateSetHash, err = decoder.bytes(); err != nil {
		return RoutingEpoch{}, err
	}
	if epoch.Version, err = decoder.uvarint(); err != nil {
		return RoutingEpoch{}, err
	}
	generatedNano, err := decoder.uvarint()
	if err != nil {
		return RoutingEpoch{}, err
	}
	expiresNano, err := decoder.uvarint()
	if err != nil {
		return RoutingEpoch{}, err
	}
	epoch.GeneratedAt = time.Unix(0, int64(generatedNano))
	epoch.ExpiresAt = time.Unix(0, int64(expiresNano))
	allocationCount, err := decoder.uvarint()
	if err != nil {
		return RoutingEpoch{}, err
	}
	if allocationCount > uint64(len(encoded)) {
		return RoutingEpoch{}, errors.New("invalid epoch allocation count")
	}
	epoch.Allocations = make([]PathAllocation, allocationCount)
	for index := uint64(0); index < allocationCount; index++ {
		sourceManagerIndex, err := decoder.uvarint()
		if err != nil {
			return RoutingEpoch{}, err
		}
		sourceGroupIndex, err := decoder.uvarint()
		if err != nil {
			return RoutingEpoch{}, err
		}
		destinationIndex, err := decoder.uvarint()
		if err != nil {
			return RoutingEpoch{}, err
		}
		classIndex, err := decoder.uvarint()
		if err != nil {
			return RoutingEpoch{}, err
		}
		pathCount, err := decoder.uvarint()
		if err != nil {
			return RoutingEpoch{}, err
		}
		if pathCount > uint64(len(encoded)) {
			return RoutingEpoch{}, errors.New("invalid epoch path count")
		}
		allocation := PathAllocation{Paths: make([]PathWeight, pathCount)}
		allocation.Key.SourceManagerID, err = lookup(sourceManagerIndex)
		if err != nil {
			return RoutingEpoch{}, err
		}
		allocation.Key.SourceGroupID, err = lookup(sourceGroupIndex)
		if err != nil {
			return RoutingEpoch{}, err
		}
		allocation.Key.DestinationScope, err = lookup(destinationIndex)
		if err != nil {
			return RoutingEpoch{}, err
		}
		class, err := lookup(classIndex)
		if err != nil {
			return RoutingEpoch{}, err
		}
		allocation.Key.FlowClass = FlowClass(class)
		for pathIndex := uint64(0); pathIndex < pathCount; pathIndex++ {
			pathIDIndex, err := decoder.uvarint()
			if err != nil {
				return RoutingEpoch{}, err
			}
			reasonIndex, err := decoder.uvarint()
			if err != nil {
				return RoutingEpoch{}, err
			}
			allocation.Paths[pathIndex].PathID, err = lookup(pathIDIndex)
			if err != nil {
				return RoutingEpoch{}, err
			}
			allocation.Paths[pathIndex].Reason, err = lookup(reasonIndex)
			if err != nil {
				return RoutingEpoch{}, err
			}
		}
		epoch.Allocations[index] = allocation
	}
	for index := range epoch.Allocations {
		for pathIndex := range epoch.Allocations[index].Paths {
			if decoder.offset+4 > len(decoder.data) {
				return RoutingEpoch{}, errors.New("truncated epoch weights")
			}
			epoch.Allocations[index].Paths[pathIndex].Weight = float64(math.Float32frombits(binary.LittleEndian.Uint32(decoder.data[decoder.offset:])))
			decoder.offset += 4
		}
	}
	if epoch.PlannerDigest, err = decoder.bytes(); err != nil {
		return RoutingEpoch{}, err
	}
	var managerIndex uint64
	managerIndex, err = decoder.uvarint()
	if err != nil {
		return RoutingEpoch{}, err
	}
	if epoch.ManagerID, err = lookup(managerIndex); err != nil {
		return RoutingEpoch{}, err
	}
	if epoch.Signature, err = decoder.bytes(); err != nil {
		return RoutingEpoch{}, err
	}
	if decoder.offset != len(decoder.data) {
		return RoutingEpoch{}, errors.New("trailing epoch bytes")
	}
	return epoch, nil
}
