package client

import (
	"time"

	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/netp2p/netp2p/internal/forward"
	"github.com/netp2p/netp2p/internal/model"
)

const (
	admissionThreshold = 2
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
	store         *pathStore
	now           func() time.Time
}

func newPathSelector(forwarder *forward.Table, store *pathStore) *pathSelector {
	return &pathSelector{
		assignments:   make(map[string]model.RouteAssignment),
		byDestination: make(map[string]model.RouteAssignment),
		current:       make(map[string]string),
		admissions:    make(map[string]admissionState),
		forwarder:     forwarder,
		store:         store,
		now:           time.Now,
	}
}

func (selector *pathSelector) reset() {
	selector.assignments = make(map[string]model.RouteAssignment)
	selector.byDestination = make(map[string]model.RouteAssignment)
	selector.current = make(map[string]string)
	selector.admissions = make(map[string]admissionState)
}

// hydrate seeds the admission map from the persisted store so a restart resumes
// the previous usability conclusions. Persisted entries never override a live
// conclusion: they only fill paths the selector has not observed yet.
func (selector *pathSelector) hydrate(paths []model.PathSpec) {
	if selector.store == nil {
		return
	}
	for _, path := range paths {
		if path.ID == "" {
			continue
		}
		if _, exists := selector.admissions[path.ID]; exists {
			continue
		}
		if ok, found := selector.store.admission(path.ID); found {
			selector.admissions[path.ID] = admissionState{ok: ok, lastChanged: selector.now()}
		}
	}
}

func (selector *pathSelector) replaceAssignments(assignments []model.RouteAssignment) {
	selector.assignments = make(map[string]model.RouteAssignment, len(assignments))
	selector.byDestination = make(map[string]model.RouteAssignment, len(assignments))
	selector.current = make(map[string]string)
	for _, assignment := range assignments {
		selector.assignments[assignment.ID] = assignment
		selector.byDestination[assignment.DestinationPeerID] = assignment
		selector.hydrate(assignment.Paths())
	}
}

func (selector *pathSelector) record(pathID string, ok bool) {
	now := selector.now()
	state := selector.admissions[pathID]
	if ok {
		state.consecutiveOK++
		state.consecutiveFailed = 0
		if !state.ok && state.consecutiveOK >= admissionThreshold {
			state.ok = true
			state.lastChanged = now
		}
	} else {
		state.consecutiveFailed++
		state.consecutiveOK = 0
		if state.ok && state.consecutiveFailed >= admissionThreshold {
			state.ok = false
			state.lastChanged = now
		}
	}
	if state.lastChanged.IsZero() {
		state.lastChanged = now
	}
	selector.admissions[pathID] = state
	if selector.store != nil {
		selector.store.recordAdmission(pathID, state.ok)
	}
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
	destinationKey := destination.String()
	// A persisted last-known-good path is a hint, not authority: it may only
	// reorder the certified set, and only to a path that is still usable.
	if lkg, ok := selector.lastGoodFor(assignment); ok {
		selector.current[destinationKey] = lkg.ID
		return assignment, lkg, true
	}
	// The certified order is authoritative: try Primary first, then each
	// fallback in sequence. Local admission state only skips paths already
	// proven unreachable; it never reorders or invents a path.
	for _, path := range assignment.Paths() {
		if path.ID == "" || !selector.usable(path) {
			continue
		}
		selector.current[destinationKey] = path.ID
		if selector.store != nil {
			selector.store.setLastGood(destinationKey, path.ID)
		}
		return assignment, path, true
	}
	return model.RouteAssignment{}, model.PathSpec{}, false
}

// lastGoodFor returns the persisted path for this assignment's destination when
// it is still part of the certified set and not marked unusable.
func (selector *pathSelector) lastGoodFor(assignment model.RouteAssignment) (model.PathSpec, bool) {
	if selector.store == nil {
		return model.PathSpec{}, false
	}
	pathID, ok := selector.store.lastGood(assignment.DestinationPeerID)
	if !ok {
		return model.PathSpec{}, false
	}
	for _, path := range assignment.Paths() {
		if path.ID == pathID && path.ID != "" && selector.usable(path) {
			return path, true
		}
	}
	return model.PathSpec{}, false
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
