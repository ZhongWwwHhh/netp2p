package client

import (
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/multiformats/go-multiaddr"
	"github.com/netp2p/netp2p/internal/forward"
	"github.com/netp2p/netp2p/internal/model"
)

const (
	admissionThreshold = 2
)

var (
	ErrPathSyncFailed            = errors.New("path selector is not synchronized with a certified snapshot")
	ErrAssignmentMissing         = errors.New("no certified assignment for destination")
	ErrDirectPathDisabled        = errors.New("direct paths are disabled")
	ErrDirectPeerUnavailable     = errors.New("direct peer has no valid address")
	ErrNoUsableCertifiedPath     = errors.New("certified assignment has no usable path")
	ErrDirectRequiresFrameSender = errors.New("direct path requires the client frame transport")
)

type PathSelectionState string

const (
	PathSelectionCertified         PathSelectionState = "certified"
	PathSelectionDirect            PathSelectionState = "direct"
	PathSelectionAssignmentMissing PathSelectionState = "assignment-missing"
	PathSelectionDirectDisabled    PathSelectionState = "direct-disabled"
	PathSelectionPeerUnavailable   PathSelectionState = "direct-peer-unavailable"
	PathSelectionNoUsablePath      PathSelectionState = "no-usable-path"
	PathSelectionSyncFailed        PathSelectionState = "sync-failed"
)

// PathSelectionStatus makes a failed selection observable instead of reducing
// every case to a bare boolean. Certified is true only when the path came from
// a RouteAssignment; an unassigned direct path is explicitly uncertified.
type PathSelectionStatus struct {
	State        PathSelectionState
	AssignmentID string
	PathID       string
	Kind         model.PathKind
	Certified    bool
	OK           bool
	Err          error
}

type admissionState struct {
	consecutiveOK     int
	consecutiveFailed int
	ok                bool
	lastChanged       time.Time
}

type pathSelector struct {
	mu             sync.Mutex
	assignments    map[string]model.RouteAssignment
	byDestination  map[string]model.RouteAssignment
	current        map[string]string
	admissions     map[string]admissionState
	forwarder      *forward.Table
	store          *pathStore
	now            func() time.Time
	directEnabled  bool
	directPeers    map[peer.ID]struct{}
	stateSynced    bool
	networkID      string
	snapshotHeight uint64
	syncErr        error
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
		directPeers:   make(map[peer.ID]struct{}),
	}
}

func (selector *pathSelector) reset() {
	selector.mu.Lock()
	defer selector.mu.Unlock()
	selector.assignments = make(map[string]model.RouteAssignment)
	selector.byDestination = make(map[string]model.RouteAssignment)
	selector.current = make(map[string]string)
	selector.admissions = make(map[string]admissionState)
	selector.directEnabled = false
	selector.directPeers = make(map[peer.ID]struct{})
	selector.stateSynced = false
	selector.networkID = ""
	selector.snapshotHeight = 0
	selector.syncErr = nil
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
	selector.mu.Lock()
	defer selector.mu.Unlock()
	selector.installAssignmentsLocked(assignments)
	selector.stateSynced = false
	selector.networkID = ""
	selector.snapshotHeight = 0
	selector.syncErr = nil
}

func (selector *pathSelector) installAssignmentsLocked(assignments []model.RouteAssignment) {
	selector.assignments = make(map[string]model.RouteAssignment, len(assignments))
	selector.byDestination = make(map[string]model.RouteAssignment, len(assignments))
	selector.current = make(map[string]string)
	for _, assignment := range assignments {
		selector.assignments[assignment.ID] = assignment
		selector.byDestination[assignment.DestinationPeerID] = assignment
		selector.hydrate(assignment.Paths())
	}
}

// syncSnapshot installs the certified settings, peer addresses and assignment
// table as one generation. It is called by the data plane before selection so
// the selector never mixes settings from one snapshot with assignments from
// another.
func (selector *pathSelector) syncSnapshot(snapshot model.SignedSnapshot) error {
	selector.mu.Lock()
	defer selector.mu.Unlock()
	if snapshot.State.NetworkID == "" {
		selector.stateSynced = false
		selector.syncErr = fmt.Errorf("%w: network id is empty", ErrPathSyncFailed)
		return selector.syncErr
	}
	if selector.stateSynced {
		if snapshot.State.NetworkID != selector.networkID {
			selector.stateSynced = false
			selector.syncErr = fmt.Errorf("%w: network id changed from %q to %q",
				ErrPathSyncFailed, selector.networkID, snapshot.State.NetworkID)
			return selector.syncErr
		}
		if snapshot.Height == selector.snapshotHeight {
			return nil
		}
		if snapshot.Height < selector.snapshotHeight {
			selector.stateSynced = false
			selector.syncErr = fmt.Errorf("%w: snapshot height %d is older than %d",
				ErrPathSyncFailed, snapshot.Height, selector.snapshotHeight)
			return selector.syncErr
		}
	}
	selector.installAssignmentsLocked(snapshot.State.Assignments)
	selector.directEnabled = snapshot.State.Settings.DirectPathEnabled
	selector.directPeers = directPeers(snapshot.State)
	selector.networkID = snapshot.State.NetworkID
	selector.snapshotHeight = snapshot.Height
	selector.stateSynced = true
	selector.syncErr = nil
	return nil
}

func directPeers(state model.NetworkState) map[peer.ID]struct{} {
	result := make(map[peer.ID]struct{})
	for _, record := range state.Peers {
		peerID, err := peer.Decode(record.PeerID)
		if err != nil {
			continue
		}
		for _, value := range record.Addresses {
			if _, err := multiaddr.NewMultiaddr(value); err != nil {
				continue
			}
			result[peerID] = struct{}{}
			break
		}
	}
	return result
}

func (selector *pathSelector) record(pathID string, ok bool) {
	selector.mu.Lock()
	defer selector.mu.Unlock()
	now := selector.now()
	state := selector.admissions[pathID]
	if _, known := selector.admissions[pathID]; !known {
		// An unobserved path is usable until it has actually failed twice.
		// Otherwise one timed-out startup probe suppresses a fresh certified
		// assignment for the rest of the process lifetime.
		state = admissionState{ok: true, lastChanged: now}
	}
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
	assignment, path, status := selector.selectWithStatus(source, destination)
	return assignment, path, status.OK
}

func (selector *pathSelector) selectWithStatus(source, destination peer.ID) (model.RouteAssignment, model.PathSpec, PathSelectionStatus) {
	selector.mu.Lock()
	defer selector.mu.Unlock()
	if !selector.stateSynced {
		err := selector.syncErr
		if err == nil {
			err = ErrPathSyncFailed
		}
		return model.RouteAssignment{}, model.PathSpec{}, failedSelection(PathSelectionSyncFailed, err)
	}
	assignment, exists := selector.byDestination[destination.String()]
	if !exists || assignment.SourcePeerID != source.String() || assignment.DestinationPeerID != destination.String() {
		return selector.selectUnassignedDirect(destination)
	}
	destinationKey := destination.String()
	// A persisted last-known-good path is a hint, not authority: it may only
	// reorder the certified set, and only to a path that is still usable.
	if lkg, ok := selector.lastGoodFor(assignment); ok {
		selector.current[destinationKey] = lkg.ID
		return assignment, lkg, successfulSelection(assignment, lkg)
	}
	// The certified order is authoritative: try Primary first, then each
	// fallback in sequence. Local admission state only skips paths already
	// proven unreachable; it never reorders or invents a path.
	for _, path := range assignment.Paths() {
		if path.ID == "" || !selector.pathEligible(path) || !selector.usable(path) {
			continue
		}
		selector.current[destinationKey] = path.ID
		if selector.store != nil {
			selector.store.setLastGood(destinationKey, path.ID)
		}
		return assignment, path, successfulSelection(assignment, path)
	}
	// A local admission conclusion is advisory. If every certified path is
	// currently marked unusable, prefer the certified order over dropping the
	// packet: the next probe or manager recovery can make it healthy again.
	for _, path := range assignment.Paths() {
		if path.ID == "" || !selector.pathEligible(path) {
			continue
		}
		selector.current[destinationKey] = path.ID
		return assignment, path, successfulSelection(assignment, path)
	}
	if selector.certifiedPathsAreDirectOnly(assignment) && !selector.directEnabled {
		return model.RouteAssignment{}, model.PathSpec{}, failedSelection(PathSelectionDirectDisabled, ErrDirectPathDisabled)
	}
	return model.RouteAssignment{}, model.PathSpec{}, failedSelection(PathSelectionNoUsablePath, ErrNoUsableCertifiedPath)
}

func (selector *pathSelector) selectUnassignedDirect(destination peer.ID) (model.RouteAssignment, model.PathSpec, PathSelectionStatus) {
	if !selector.directEnabled {
		err := errors.Join(ErrAssignmentMissing, ErrDirectPathDisabled)
		return model.RouteAssignment{}, model.PathSpec{}, failedSelection(PathSelectionAssignmentMissing, err)
	}
	if _, available := selector.directPeers[destination]; !available {
		err := errors.Join(ErrAssignmentMissing, ErrDirectPeerUnavailable)
		return model.RouteAssignment{}, model.PathSpec{}, failedSelection(PathSelectionAssignmentMissing, err)
	}
	path := model.PathSpec{ID: "direct", Kind: model.PathKindDirect}
	return model.RouteAssignment{}, path, PathSelectionStatus{
		State: PathSelectionDirect, PathID: path.ID, Kind: path.Kind, Certified: false, OK: true,
	}
}

func (selector *pathSelector) pathEligible(path model.PathSpec) bool {
	if path.Kind == model.PathKindDirect {
		return selector.directEnabled
	}
	return true
}

func (selector *pathSelector) certifiedPathsAreDirectOnly(assignment model.RouteAssignment) bool {
	paths := assignment.Paths()
	if len(paths) == 0 {
		return false
	}
	for _, path := range paths {
		if path.Kind != model.PathKindDirect {
			return false
		}
	}
	return true
}

func successfulSelection(assignment model.RouteAssignment, path model.PathSpec) PathSelectionStatus {
	return PathSelectionStatus{
		State: PathSelectionCertified, AssignmentID: assignment.ID, PathID: path.ID,
		Kind: path.Kind, Certified: true, OK: true,
	}
}

func failedSelection(state PathSelectionState, err error) PathSelectionStatus {
	return PathSelectionStatus{State: state, Err: err}
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
		if path.ID == pathID && path.ID != "" && selector.pathEligible(path) && selector.usable(path) {
			return path, true
		}
	}
	return model.PathSpec{}, false
}

func (selector *pathSelector) send(source, destination peer.ID, payload []byte) error {
	assignment, path, status := selector.selectWithStatus(source, destination)
	if !status.OK {
		return status.Err
	}
	if path.Kind == model.PathKindDirect {
		return ErrDirectRequiresFrameSender
	}
	return selector.forwarder.Send(source, destination, assignment.ID, path.ID, payload)
}
