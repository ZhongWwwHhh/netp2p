// Package forward implements manager-side overlay frame forwarding. It is a
// small control loop around libp2p's secure framed transport; authority comes
// exclusively from certified RouteAssignments.
package forward

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"time"

	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/netp2p/netp2p/internal/metrics"
	"github.com/netp2p/netp2p/internal/model"
	"github.com/netp2p/netp2p/internal/path"
	"github.com/netp2p/netp2p/internal/quota"
	"github.com/netp2p/netp2p/internal/tracing"
	"go.opentelemetry.io/otel"
)

const DefaultTTL = 4

var (
	ErrNoAssignment      = errors.New("no certified assignment")
	ErrInvalidSource     = errors.New("frame source is not authorized")
	ErrTTLExceeded       = errors.New("frame hop limit exceeded")
	ErrQueueFull         = errors.New("forwarding queue full")
	ErrDestinationHeader = errors.New("frame destination header mismatch")
	ErrQuotaExceeded     = errors.New("frame exceeded a traffic budget")
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

type ScaleSender func(remote peer.ID, envelope ScaleEnvelope) error

type Table struct {
	mu              sync.RWMutex
	state           model.NetworkState
	sender          Sender
	localID         string
	quota           *quota.Enforcer
	connections     map[string]struct{}
	sequence        atomic.Uint64
	forwarded       atomic.Uint64
	dropped         atomic.Uint64
	quotaBlocked    atomic.Uint64
	queueDepth      atomic.Int64
	reservations    atomic.Uint64
	bytes           atomic.Uint64
	metrics         *metrics.Metrics
	faceBudgets     *quota.FaceBudgetSet
	scaleAuthorizer ScaleAuthorizer
	scaleSender     ScaleSender
}

func NewTable(state model.NetworkState, localID string, sender Sender) *Table {
	return NewTableWithMetrics(state, localID, sender, nil)
}

func NewTableWithMetrics(state model.NetworkState, localID string, sender Sender, collector *metrics.Metrics) *Table {
	return &Table{
		state:       state,
		localID:     localID,
		sender:      sender,
		quota:       quota.NewEnforcer(state.Budgets),
		connections: make(map[string]struct{}),
		metrics:     collector,
	}
}

func (table *Table) SetFaceBudgets(budgets *quota.FaceBudgetSet) {
	table.mu.Lock()
	table.faceBudgets = budgets
	table.mu.Unlock()
}

func (table *Table) SetScaleRouting(authorizer ScaleAuthorizer, sender ScaleSender) {
	table.mu.Lock()
	table.scaleAuthorizer = authorizer
	table.scaleSender = sender
	table.mu.Unlock()
}

// Replace atomically applies a certified snapshot's assignment table.
func (table *Table) Replace(state model.NetworkState) {
	table.mu.Lock()
	table.state = state
	if table.connections == nil {
		table.connections = make(map[string]struct{})
	}
	table.mu.Unlock()
	table.quota.Replace(state.Budgets)
}

// Accept validates an inbound manager-forwarded frame from remote and sends it
// to the next hop, or reports that this node is the destination.
//
// The remote peer must be the frame's rightful predecessor on the certified
// path: the source client for the first hop, or the previous manager for a
// multi-hop path. libp2p authenticates the transport peer, so this binds the
// in-band header to a real identity instead of trusting it.
func (table *Table) Accept(remote peer.ID, envelope Envelope) (bool, error) {
	if tracing.Enabled() {
		_, span := otel.Tracer("netp2p").Start(context.Background(), "forward.accept")
		defer span.End()
	}
	if envelope.Header.TTL == 0 {
		table.recordDrop()
		return false, ErrTTLExceeded
	}
	table.mu.RLock()
	state := table.state
	table.mu.RUnlock()
	assignment, ok := findAssignment(state, envelope.Header.AssignmentID)
	if !ok || !assignmentContains(assignment, envelope.Header.PathID) {
		table.recordDrop()
		return false, ErrNoAssignment
	}
	if envelope.Header.SourcePeerID != assignment.SourcePeerID ||
		envelope.Header.DestinationPeerID != assignment.DestinationPeerID {
		table.recordDrop()
		return false, ErrInvalidSource
	}
	path, _ := pathByID(assignment, envelope.Header.PathID)
	isManagerHop := pathContains(assignment.Paths(), envelope.Header.PathID, table.localID)
	if isManagerHop {
		if !predecessorMatches(assignment, envelope.Header.PathID, table.localID, remote.String()) {
			table.recordDrop()
			return false, ErrInvalidSource
		}
		// Charge each envelope once, at the first certified manager hop.
		if remote.String() == assignment.SourcePeerID && state.Settings.QuotaEnforcementEnabled &&
			!table.admitQuotas(state, assignment, uint64(len(envelope.Payload))) {
			table.recordQuotaBlocked()
			table.recordDrop()
			return false, ErrQuotaExceeded
		}
		next, ok := nextHop(assignment, envelope.Header.PathID, table.localID)
		if !ok {
			return true, nil
		}
		nextPeer, err := peer.Decode(next)
		if err != nil {
			table.recordDrop()
			return false, err
		}
		forwarded := envelope
		forwarded.Header.TTL--
		if err := table.send(nextPeer, forwarded); err != nil {
			table.recordDrop()
			return false, err
		}
		table.observeConnection(remote)
		table.bytes.Add(uint64(len(envelope.Payload)))
		table.recordForwarded()
		return false, nil
	}
	if table.localID != assignment.DestinationPeerID {
		table.recordDrop()
		return false, ErrNoAssignment
	}
	if expected, ok := destinationPredecessor(assignment, envelope.Header.PathID); !ok || expected != remote.String() {
		table.recordDrop()
		return false, ErrInvalidSource
	}
	if len(path.ManagerHops) == 0 && state.Settings.QuotaEnforcementEnabled &&
		!table.admitQuotas(state, assignment, uint64(len(envelope.Payload))) {
		table.recordQuotaBlocked()
		table.recordDrop()
		return false, ErrQuotaExceeded
	}
	table.observeConnection(remote)
	table.bytes.Add(uint64(len(envelope.Payload)))
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
	if err := table.send(remote, envelope); err != nil {
		return err
	}
	table.reservations.Add(1)
	table.bytes.Add(uint64(len(payload)))
	return nil
}

// SendScale emits a domain-scoped envelope without requiring a per-peer-pair
// assignment. Authorization is supplied by the compiled certified network map.
func (table *Table) SendScale(source, destination peer.ID, envelope ScaleEnvelope) error {
	if envelope.Header.SourcePeerID != source.String() || envelope.Header.DestinationPeerID != destination.String() {
		return ErrScaleUnauthorized
	}
	table.mu.RLock()
	authorizer := table.scaleAuthorizer
	sender := table.scaleSender
	table.mu.RUnlock()
	if authorizer == nil || sender == nil {
		return ErrScaleUnauthorized
	}
	authorization, err := authorizer(envelope.Header.SourcePeerID, envelope.Header.DestinationPeerID,
		envelope.Header.RoutingDomainID, envelope.Header.PathFamilyID, envelope.Header.FlowClass)
	if err != nil {
		return err
	}
	if authorization.Destination || authorization.NextHop == "" {
		return ErrScaleUnauthorized
	}
	next, err := peer.Decode(authorization.NextHop)
	if err != nil {
		return err
	}
	if err := table.sendScale(next, envelope); err != nil {
		return err
	}
	table.reservations.Add(1)
	table.bytes.Add(uint64(len(envelope.Payload)))
	return nil
}

// AcceptScale validates and forwards a scale envelope. The remote transport
// identity must equal the authorization's expected predecessor.
func (table *Table) AcceptScale(remote peer.ID, envelope ScaleEnvelope) (bool, error) {
	if envelope.Header.TTL == 0 {
		table.recordDrop()
		return false, ErrTTLExceeded
	}
	table.mu.RLock()
	authorizer := table.scaleAuthorizer
	sender := table.scaleSender
	faceBudgets := table.faceBudgets
	table.mu.RUnlock()
	if authorizer == nil {
		table.recordDrop()
		return false, ErrScaleUnauthorized
	}
	authorization, err := authorizer(envelope.Header.SourcePeerID, envelope.Header.DestinationPeerID,
		envelope.Header.RoutingDomainID, envelope.Header.PathFamilyID, envelope.Header.FlowClass)
	if err != nil {
		table.recordDrop()
		return false, err
	}
	if authorization.ExpectedPredecessor != remote.String() {
		table.recordDrop()
		return false, ErrScaleUnauthorized
	}
	if authorization.Destination {
		table.observeConnection(remote)
		table.bytes.Add(uint64(len(envelope.Payload)))
		return true, nil
	}
	if authorization.NextHop == "" || sender == nil {
		table.recordDrop()
		return false, ErrScaleUnauthorized
	}
	if faceBudgets != nil && authorization.FaceID != "" {
		table.observeFaceQueue(authorization.FaceID)
		decision := faceBudgets.Admit(authorization.FaceID, path.FlowClass(envelope.Header.FlowClass), uint64(len(envelope.Payload)), time.Now().UTC())
		if !decision.Allowed || decision.Delay > 0 {
			table.recordQuotaBlocked()
			table.recordDrop()
			return false, ErrFaceBudgetExceeded
		}
	}
	next, err := peer.Decode(authorization.NextHop)
	if err != nil {
		table.recordDrop()
		return false, err
	}
	forwarded := envelope
	forwarded.Header.TTL--
	if err := table.sendScale(next, forwarded); err != nil {
		table.recordDrop()
		return false, err
	}
	table.observeConnection(remote)
	table.bytes.Add(uint64(len(envelope.Payload)))
	table.recordForwarded()
	return false, nil
}

func (table *Table) Dropped() uint64 { return table.dropped.Load() }

// Stats reports how many frames this table forwarded onward and how many it
// dropped. It exists for tests and diagnostics.
func (table *Table) Stats() (forwarded, dropped uint64) {
	return table.forwarded.Load(), table.dropped.Load()
}

func (table *Table) QueueDepth() int64 {
	return table.queueDepth.Load()
}

func (table *Table) QuotaBlocked() uint64 {
	return table.quotaBlocked.Load()
}

func (table *Table) send(remote peer.ID, envelope Envelope) error {
	table.enterSend()
	defer table.exitSend()
	return table.sender(remote, envelope)
}

func (table *Table) sendScale(remote peer.ID, envelope ScaleEnvelope) error {
	table.mu.RLock()
	sender := table.scaleSender
	table.mu.RUnlock()
	if sender == nil {
		return ErrScaleUnauthorized
	}
	table.enterSend()
	defer table.exitSend()
	return sender(remote, envelope)
}

func (table *Table) observeFaceQueue(faceID string) {
	table.mu.RLock()
	budgets := table.faceBudgets
	table.mu.RUnlock()
	if budgets == nil {
		return
	}
	const queueCapacity = 1024
	_, _ = budgets.ObserveQueue(faceID, uint64(table.queueDepth.Load()), queueCapacity, time.Now().UTC())
}

func (table *Table) ScaleFeedback(faceID string) (quota.FaceFeedback, error) {
	table.mu.RLock()
	budgets := table.faceBudgets
	table.mu.RUnlock()
	if budgets == nil {
		return quota.FaceFeedback{}, ErrFaceBudgetExceeded
	}
	return budgets.Feedback(faceID)
}

func (table *Table) enterSend() {
	table.queueDepth.Add(1)
	table.publishQueueDepth()
}

func (table *Table) exitSend() {
	table.queueDepth.Add(-1)
	table.publishQueueDepth()
}

func (table *Table) publishQueueDepth() {
	if table.metrics == nil {
		return
	}
	table.metrics.ForwardQueueDepth.Set(float64(table.queueDepth.Load()))
}

func (table *Table) recordForwarded() {
	table.forwarded.Add(1)
	if table.metrics != nil {
		table.metrics.Forwarded.Inc()
	}
}

func (table *Table) recordDrop() {
	table.dropped.Add(1)
	if table.metrics != nil {
		table.metrics.ForwardDrops.Inc()
	}
}

func (table *Table) recordQuotaBlocked() {
	table.quotaBlocked.Add(1)
	if table.metrics != nil {
		table.metrics.QuotaBlocked.Inc()
	}
}

// RelayStats reports unique successful relay predecessors, certified path
// reservations, and payload bytes. It complements Stats for capacity planning.
func (table *Table) RelayStats() (connections, reservations, bytes uint64) {
	table.mu.RLock()
	connections = uint64(len(table.connections))
	table.mu.RUnlock()
	return connections, table.reservations.Load(), table.bytes.Load()
}

func (table *Table) observeConnection(remote peer.ID) {
	table.mu.Lock()
	if table.connections == nil {
		table.connections = make(map[string]struct{})
	}
	table.connections[remote.String()] = struct{}{}
	table.mu.Unlock()
}

func (table *Table) admitQuotas(state model.NetworkState, assignment model.RouteAssignment, bytes uint64) bool {
	sourceGroups := peerGroups(state, assignment.SourcePeerID)
	destinationGroups := peerGroups(state, assignment.DestinationPeerID)

	sourceBudget, sourceMatched := table.quota.Resolve(assignment.SourcePeerID, sourceGroups, "")
	destinationBudget, destinationMatched := table.quota.Resolve(assignment.DestinationPeerID, destinationGroups, "")
	if sourceMatched && destinationMatched && sourceBudget.ID == destinationBudget.ID {
		decision := table.quota.Check(assignment.SourcePeerID, sourceGroups, "", bytes)
		return decision.Allowed && decision.Delay == 0
	}
	if sourceMatched {
		decision := table.quota.Check(assignment.SourcePeerID, sourceGroups, "", bytes)
		if !decision.Allowed || decision.Delay > 0 {
			return false
		}
	}
	if destinationMatched {
		decision := table.quota.Check(assignment.DestinationPeerID, destinationGroups, "", bytes)
		if !decision.Allowed || decision.Delay > 0 {
			return false
		}
	}
	return true
}

func peerGroups(state model.NetworkState, peerID string) []string {
	groups := make([]string, 0, 4)
	for _, peer := range state.Peers {
		if peer.PeerID != peerID {
			continue
		}
		groups = append(groups, peer.Groups...)
		break
	}
	for _, group := range state.Groups {
		if containsPeerID(group.PeerIDs, peerID) {
			groups = append(groups, group.ID)
		}
	}
	return groups
}

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
	path, ok := pathByID(assignment, pathID)
	if !ok {
		return "", false
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

func pathByID(assignment model.RouteAssignment, pathID string) (model.PathSpec, bool) {
	if assignment.Primary.ID == pathID {
		return assignment.Primary, true
	}
	for _, candidate := range assignment.Fallbacks {
		if candidate.ID == pathID {
			return candidate, true
		}
	}
	return model.PathSpec{}, false
}

// predecessorMatches reports whether remote is the identity allowed to hand a
// frame at this hop to localID. For the first hop that is the source client;
// for later hops it is the preceding manager on the certified path.
func predecessorMatches(assignment model.RouteAssignment, pathID, localID, remoteID string) bool {
	path, ok := pathByID(assignment, pathID)
	if !ok {
		return false
	}
	for index, hop := range path.ManagerHops {
		if hop != localID {
			continue
		}
		if index == 0 {
			return remoteID == assignment.SourcePeerID
		}
		return remoteID == path.ManagerHops[index-1]
	}
	return false
}

// destinationPredecessor returns the identity that may deliver a frame to the
// assignment's destination: the last manager hop, or the source client when the
// path is direct.
func destinationPredecessor(assignment model.RouteAssignment, pathID string) (string, bool) {
	path, ok := pathByID(assignment, pathID)
	if !ok {
		return "", false
	}
	if len(path.ManagerHops) == 0 {
		return assignment.SourcePeerID, true
	}
	return path.ManagerHops[len(path.ManagerHops)-1], true
}
