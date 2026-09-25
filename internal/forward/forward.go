// Package forward implements manager-side overlay frame forwarding. It is a
// small control loop around libp2p's secure framed transport; authority comes
// exclusively from certified RouteAssignments.
package forward

import (
	"errors"
	"sync"
	"sync/atomic"

	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/netp2p/netp2p/internal/model"
)

const DefaultTTL = 4

var (
	ErrNoAssignment      = errors.New("no certified assignment")
	ErrInvalidSource     = errors.New("frame source is not authorized")
	ErrTTLExceeded       = errors.New("frame hop limit exceeded")
	ErrQueueFull         = errors.New("forwarding queue full")
	ErrDestinationHeader = errors.New("frame destination header mismatch")
)

type Header struct {
	SourcePeerID      string `json:"sourcePeerId"`
	DestinationPeerID string `json:"destinationPeerId"`
	AssignmentID      string `json:"assignmentId"`
	PathID            string `json:"pathId"`
	TTL               uint8  `json:"ttl"`
}

type Envelope struct {
	Header    Header `json:"header"`
	Payload   []byte `json:"payload"`
	Signature []byte `json:"signature"`
}

type Sender func(remote peer.ID, envelope Envelope) error

type Table struct {
	mu       sync.RWMutex
	state    model.NetworkState
	sender   Sender
	localID  string
	sequence atomic.Uint64
	dropped  atomic.Uint64
}

func NewTable(state model.NetworkState, localID string, sender Sender) *Table {
	return &Table{state: state, localID: localID, sender: sender}
}

// Replace atomically applies a certified snapshot's assignment table.
func (table *Table) Replace(state model.NetworkState) {
	table.mu.Lock()
	table.state = state
	table.mu.Unlock()
}

// Accept validates an inbound manager-forwarded frame and sends it to the next
// hop, or reports that this node is the destination.
func (table *Table) Accept(envelope Envelope) (bool, error) {
	if envelope.Header.TTL == 0 {
		table.dropped.Add(1)
		return false, ErrTTLExceeded
	}
	table.mu.RLock()
	state := table.state
	table.mu.RUnlock()
	assignment, ok := findAssignment(state, envelope.Header.AssignmentID)
	if !ok || !assignmentContains(assignment, envelope.Header.PathID) {
		table.dropped.Add(1)
		return false, ErrNoAssignment
	}
	if envelope.Header.SourcePeerID != assignment.SourcePeerID ||
		envelope.Header.DestinationPeerID != assignment.DestinationPeerID {
		table.dropped.Add(1)
		return false, ErrInvalidSource
	}
	if pathContains(assignment.Paths(), envelope.Header.PathID, table.localID) {
		next, ok := nextHop(assignment, envelope.Header.PathID, table.localID)
		if !ok {
			return true, nil
		}
		remote, err := peer.Decode(next)
		if err != nil {
			table.dropped.Add(1)
			return false, err
		}
		forwarded := envelope
		forwarded.Header.TTL--
		if err := table.sender(remote, forwarded); err != nil {
			table.dropped.Add(1)
			return false, err
		}
		return false, nil
	}
	if table.localID != assignment.DestinationPeerID {
		table.dropped.Add(1)
		return false, ErrNoAssignment
	}
	return true, nil
}

// Send wraps an overlay packet for a certified path and sends it to the first
// hop. Source clients use this instead of dialing remote peers directly.
func (table *Table) Send(source, destination peer.ID, assignmentID, pathID string, payload []byte) error {
	table.mu.RLock()
	state := table.state
	table.mu.RUnlock()
	assignment, ok := findAssignment(state, assignmentID)
	if !ok || assignment.SourcePeerID != source.String() || assignment.DestinationPeerID != destination.String() {
		return ErrNoAssignment
	}
	if !assignmentContains(assignment, pathID) {
		return ErrNoAssignment
	}
	hop, ok := nextHop(assignment, pathID, source.String())
	if !ok {
		return ErrNoAssignment
	}
	remote, err := peer.Decode(hop)
	if err != nil {
		return err
	}
	envelope := Envelope{
		Header: Header{
			SourcePeerID: source.String(), DestinationPeerID: destination.String(),
			AssignmentID: assignmentID, PathID: pathID, TTL: DefaultTTL,
		},
		Payload: payload,
	}
	return table.sender(remote, envelope)
}

func (table *Table) Dropped() uint64 { return table.dropped.Load() }

func findAssignment(state model.NetworkState, id string) (model.RouteAssignment, bool) {
	for _, assignment := range state.Assignments {
		if assignment.ID == id {
			return assignment, true
		}
	}
	return model.RouteAssignment{}, false
}

func assignmentContains(assignment model.RouteAssignment, pathID string) bool {
	if assignment.Primary.ID == pathID {
		return true
	}
	for _, path := range assignment.Fallbacks {
		if path.ID == pathID {
			return true
		}
	}
	return false
}

func containsPeerID(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}

func pathContains(paths []model.PathSpec, pathID, target string) bool {
	for _, path := range paths {
		if path.ID == pathID && containsPeerID(path.ManagerHops, target) {
			return true
		}
	}
	return false
}

func nextHop(assignment model.RouteAssignment, pathID, source string) (string, bool) {
	path := assignment.Primary
	if path.ID != pathID {
		for _, candidate := range assignment.Fallbacks {
			if candidate.ID == pathID {
				path = candidate
				break
			}
		}
	}
	for index, hop := range path.ManagerHops {
		if hop == source {
			if index+1 < len(path.ManagerHops) {
				return path.ManagerHops[index+1], true
			}
			return assignment.DestinationPeerID, true
		}
	}
	if source == assignment.SourcePeerID && len(path.ManagerHops) > 0 {
		return path.ManagerHops[0], true
	}
	return "", false
}
