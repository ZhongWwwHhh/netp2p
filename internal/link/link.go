// Package link aggregates signed link observations from the manager mesh.
//
// Clients are deliberately outside this model. Their reports are never merged
// here, so a malicious client cannot affect another peer's view of the network.
package link

import (
	"crypto/sha256"
	"encoding/json"
	"sort"
	"time"
)

type Scope string

const (
	ScopeManagerMesh Scope = "manager_mesh"
	ScopeAccess      Scope = "access"
	ScopePeerDirect  Scope = "peer_direct"
)

type Direction string

const (
	DirectionOutbound  Direction = "outbound"
	DirectionInbound   Direction = "inbound"
	DirectionRoundTrip Direction = "roundtrip"
)

type Observation struct {
	ObserverID         string    `json:"observerId"`
	SubjectID          string    `json:"subjectId"`
	Scope              Scope     `json:"scope"`
	Direction          Direction `json:"direction"`
	RTTMilliseconds    float64   `json:"rttMilliseconds"`
	LossPercent        float64   `json:"lossPercent"`
	JitterMilliseconds float64   `json:"jitterMilliseconds"`
	BandwidthMbps      float64   `json:"bandwidthMbps"`
	Samples            int       `json:"samples"`
	MeasuredAt         time.Time `json:"measuredAt"`
	Sequence           uint64    `json:"sequence"`
	Signature          []byte    `json:"signature,omitempty"`
}

func (observation Observation) Valid(now time.Time, ttl time.Duration) bool {
	return observation.ObserverID != "" && observation.SubjectID != "" &&
		observation.ObserverID != observation.SubjectID &&
		observation.Samples > 0 && observation.RTTMilliseconds >= 0 &&
		observation.LossPercent >= 0 && observation.LossPercent <= 100 &&
		observation.BandwidthMbps >= 0 &&
		!observation.MeasuredAt.IsZero() &&
		now.Sub(observation.MeasuredAt) >= 0 && now.Sub(observation.MeasuredAt) <= ttl
}

type SegmentView struct {
	From            string    `json:"from"`
	To              string    `json:"to"`
	RTTMilliseconds float64   `json:"rttMilliseconds"`
	LossPercent     float64   `json:"lossPercent"`
	BandwidthMbps   float64   `json:"bandwidthMbps"`
	Confidence      float64   `json:"confidence"`
	SampleCount     int       `json:"sampleCount"`
	Observers       []string  `json:"observers"`
	UpdatedAt       time.Time `json:"updatedAt"`
}

type LinkView struct {
	GeneratedAt time.Time     `json:"generatedAt"`
	Segments    []SegmentView `json:"segments"`
	Hash        []byte        `json:"hash"`
}

// AssignmentID derives a stable, deterministic ID for a directed peer pair.
func AssignmentID(sourcePeerID, destinationPeerID string) string {
	hash := sha256.Sum256([]byte(sourcePeerID + "\x00" + destinationPeerID))
	return "assignment-" + encodeHexPrefix(hash[:])
}

func encodeHexPrefix(raw []byte) string {
	const hexDigits = "0123456789abcdef"
	result := make([]byte, 0, 12)
	for index := 0; index < 6 && index < len(raw); index++ {
		result = append(result, hexDigits[raw[index]>>4], hexDigits[raw[index]&0x0f])
	}
	return string(result)
}

// Aggregate builds a deterministic manager-mesh view. It uses a two-observer
// median when available, falling back to a single fresh observation with lower
// confidence. Outliers beyond maxRTT are ignored entirely.
func Aggregate(observations []Observation, now time.Time, ttl time.Duration, maxRTT float64) LinkView {
	type key struct{ from, to string }
	groups := make(map[key][]Observation)
	for _, observation := range observations {
		if observation.Scope != ScopeManagerMesh || !observation.Valid(now, ttl) {
			continue
		}
		if maxRTT > 0 && observation.RTTMilliseconds > maxRTT {
			continue
		}
		forwardKey := key{observation.ObserverID, observation.SubjectID}
		reverseKey := key{observation.SubjectID, observation.ObserverID}
		if len(groups[reverseKey]) > 0 {
			groups[reverseKey] = append(groups[reverseKey], observation)
			continue
		}
		groups[forwardKey] = append(groups[forwardKey], observation)
	}

	segments := make([]SegmentView, 0, len(groups))
	for groupKey, group := range groups {
		sort.Slice(group, func(i, j int) bool {
			if !group[i].MeasuredAt.Equal(group[j].MeasuredAt) {
				return group[i].MeasuredAt.After(group[j].MeasuredAt)
			}
			return group[i].Sequence > group[j].Sequence
		})
		recent := group[0]
		segment := SegmentView{
			From: groupKey.from, To: groupKey.to,
			RTTMilliseconds: recent.RTTMilliseconds,
			LossPercent:     recent.LossPercent,
			BandwidthMbps:   recent.BandwidthMbps,
			SampleCount:     recent.Samples,
			Observers:       []string{recent.ObserverID},
			UpdatedAt:       recent.MeasuredAt,
			Confidence:      0.4,
		}
		if len(group) > 1 {
			previous := group[1]
			segment.RTTMilliseconds = (recent.RTTMilliseconds + previous.RTTMilliseconds) / 2
			segment.LossPercent = (recent.LossPercent + previous.LossPercent) / 2
			segment.BandwidthMbps = (recent.BandwidthMbps + previous.BandwidthMbps) / 2
			segment.SampleCount += previous.Samples
			segment.Observers = append(segment.Observers, previous.ObserverID)
			sort.Strings(segment.Observers)
			segment.Confidence = 0.8
		}
		segments = append(segments, segment)
	}
	sort.Slice(segments, func(i, j int) bool {
		if segments[i].From != segments[j].From {
			return segments[i].From < segments[j].From
		}
		return segments[i].To < segments[j].To
	})
	hash := sha256.Sum256(canonicalJSON(segments))
	return LinkView{GeneratedAt: now.UTC(), Segments: segments, Hash: hash[:]}
}

func canonicalJSON(value any) []byte {
	encoded, _ := json.Marshal(value)
	return encoded
}
