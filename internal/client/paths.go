package client

import (
	"time"

	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/netp2p/netp2p/internal/forward"
	"github.com/netp2p/netp2p/internal/model"
)

const (
	admissionThreshold = 2
	pathMinimumDwell   = 10 * time.Second
)

type admissionState struct {
	consecutiveOK     int
	consecutiveFailed int
	ok                bool
	lastChanged       time.Time
}

type pathSelector struct {
	assignments   map[string]model.RouteAssignment
	byDestination map[string]model.RouteAssignment
	current       map[string]string
	admissions    map[string]admissionState
	forwarder     *forward.Table
	now           func() time.Time
}

func newPathSelector(forwarder *forward.Table) *pathSelector {
	return &pathSelector{
		assignments:   make(map[string]model.RouteAssignment),
		byDestination: make(map[string]model.RouteAssignment),
		current:       make(map[string]string),
		admissions:    make(map[string]admissionState),
		forwarder:     forwarder,
		now:           time.Now,
	}
}

func (selector *pathSelector) reset() {
	selector.assignments = make(map[string]model.RouteAssignment)
	selector.byDestination = make(map[string]model.RouteAssignment)
	selector.current = make(map[string]string)
	selector.admissions = make(map[string]admissionState)
}

func (selector *pathSelector) replaceAssignments(assignments []model.RouteAssignment) {
	selector.assignments = make(map[string]model.RouteAssignment, len(assignments))
	selector.byDestination = make(map[string]model.RouteAssignment, len(assignments))
	selector.current = make(map[string]string)
	for _, assignment := range assignments {
		selector.assignments[assignment.ID] = assignment
		selector.byDestination[assignment.DestinationPeerID] = assignment
	}
}

func (selector *pathSelector) record(pathID string, ok bool) {
	now := selector.now()
	state := selector.admissions[pathID]
	changed := false
	if ok {
		state.consecutiveOK++
		state.consecutiveFailed = 0
		if !state.ok && state.consecutiveOK >= admissionThreshold {
			state.ok = true
			state.lastChanged = now
			changed = true
		}
	} else {
		state.consecutiveFailed++
		state.consecutiveOK = 0
		if state.ok && state.consecutiveFailed >= admissionThreshold {
			state.ok = false
			state.lastChanged = now
			changed = true
		}
	}
	if !changed && state.lastChanged.IsZero() {
		state.lastChanged = now
	}
	selector.admissions[pathID] = state
}

func (selector *pathSelector) usable(path model.PathSpec) bool {
	state, exists := selector.admissions[path.ID]
	if !exists {
		return true
	}
	return state.ok
}

func (selector *pathSelector) selectFor(source, destination peer.ID) (model.RouteAssignment, model.PathSpec, bool) {
	assignment, exists := selector.byDestination[destination.String()]
	if !exists || assignment.SourcePeerID != source.String() || assignment.DestinationPeerID != destination.String() {
		return model.RouteAssignment{}, model.PathSpec{}, false
	}
	paths := assignment.Paths()
	if len(paths) == 0 {
		return model.RouteAssignment{}, model.PathSpec{}, false
	}
	destinationKey := destination.String()
	for _, path := range paths {
		if path.Kind == model.PathKindDirect && selector.usable(path) {
			selector.record(path.ID, true)
			selector.current[destinationKey] = path.ID
			return assignment, path, true
		}
	}
	if currentPathID, hasCurrent := selector.current[destinationKey]; hasCurrent {
		for _, path := range paths {
			if path.ID == currentPathID && selector.usable(path) {
				return assignment, path, true
			}
		}
	}
	for _, path := range paths {
		if path.ID == "" || !selector.usable(path) {
			continue
		}
		selector.current[destinationKey] = path.ID
		return assignment, path, true
	}
	return model.RouteAssignment{}, model.PathSpec{}, false
}

func (selector *pathSelector) send(source, destination peer.ID, payload []byte) error {
	assignment, path, ok := selector.selectFor(source, destination)
	if !ok {
		return forward.ErrNoAssignment
	}
	if path.Kind == model.PathKindDirect {
		return nil
	}
	return selector.forwarder.Send(source, destination, assignment.ID, path.ID, payload)
}
