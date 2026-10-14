// Package forward implements manager-side overlay frame forwarding. It is a
// small control loop around libp2p's secure framed transport; authority comes
// exclusively from certified RouteAssignments.
package forward

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/netp2p/netp2p/internal/conntrack"
	"github.com/netp2p/netp2p/internal/metrics"
	"github.com/netp2p/netp2p/internal/model"
	"github.com/netp2p/netp2p/internal/packet"
	"github.com/netp2p/netp2p/internal/path"
	"github.com/netp2p/netp2p/internal/policy"
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
	faceID          string
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
	scaleFlows      *conntrack.Table
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
		faceID:      localID,
		sender:      sender,
		quota:       quota.NewEnforcer(state.Budgets),
		scaleFlows:  conntrack.NewTable(),
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

// SetFaceID sets the manager label used by the capacity-budget faces. The
// forwarding path identifies peers by libp2p PeerID, while budgets identify a
// manager by its certified committee ID; the two must not be conflated.
func (table *Table) SetFaceID(faceID string) {
	if faceID == "" {
		return
	}
	table.mu.Lock()
	table.faceID = faceID
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
	state := table.state
	faceBudgets := table.faceBudgets
	authorizer := table.scaleAuthorizer
	sender := table.scaleSender
	table.mu.RUnlock()
	if err := table.validateScaleEnvelope(state, envelope); err != nil {
		table.recordDrop()
		return err
	}
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
	if !table.admitScaleQuotas(state, envelope.Header.SourcePeerID, envelope.Header.DestinationPeerID, uint64(len(envelope.Payload))) {
		table.recordQuotaBlocked()
		table.recordDrop()
		return ErrQuotaExceeded
	}
	if !table.admitScaleFace(faceBudgets, authorization.FaceID, envelope.Header.FlowClass, uint64(len(envelope.Payload))) {
		table.recordQuotaBlocked()
		table.recordDrop()
		return ErrFaceBudgetExceeded
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
	state := table.state
	authorizer := table.scaleAuthorizer
	sender := table.scaleSender
	faceBudgets := table.faceBudgets
	table.mu.RUnlock()
	returnAuthorization, isReturn, err := table.authorizeScaleReturn(state, remote, envelope)
	if err != nil {
		table.recordDrop()
		return false, err
	}
	if isReturn {
		if !table.admitScaleQuotas(state, envelope.Header.SourcePeerID, envelope.Header.DestinationPeerID, uint64(len(envelope.Payload))) {
			table.recordQuotaBlocked()
			table.recordDrop()
			return false, ErrQuotaExceeded
		}
		if !table.admitScaleFace(faceBudgets, returnAuthorization.FaceID, envelope.Header.FlowClass, uint64(len(envelope.Payload))) {
			table.recordQuotaBlocked()
			table.recordDrop()
			return false, ErrFaceBudgetExceeded
		}
		next, err := peer.Decode(returnAuthorization.NextHop)
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
	if err := table.validateScaleEnvelope(state, envelope); err != nil {
		table.recordDrop()
		return false, err
	}
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
		return false, fmt.Errorf("%w: unexpected predecessor", ErrScaleUnauthorized)
	}
	table.recordScaleSelection(envelope)
	if authorization.Destination {
		table.observeConnection(remote)
		table.bytes.Add(uint64(len(envelope.Payload)))
		return true, nil
	}
	if !table.admitScaleFace(faceBudgets, authorization.FaceID, envelope.Header.FlowClass, uint64(len(envelope.Payload))) {
		table.recordQuotaBlocked()
		table.recordDrop()
		return false, ErrFaceBudgetExceeded
	}
	// Peer budgets are charged once, at the first certified manager hop. Later
	// hops enforce their own face budget but must not double-count endpoints.
	if remote.String() == envelope.Header.SourcePeerID &&
		!table.admitScaleQuotas(state, envelope.Header.SourcePeerID, envelope.Header.DestinationPeerID, uint64(len(envelope.Payload))) {
		table.recordQuotaBlocked()
		table.recordDrop()
		return false, ErrQuotaExceeded
	}
	if authorization.NextHop == "" || sender == nil {
		table.recordDrop()
		return false, ErrScaleUnauthorized
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
	table.observeScaleFlow(envelope)
	table.observeConnection(remote)
	table.bytes.Add(uint64(len(envelope.Payload)))
	table.recordForwarded()
	return false, nil
}

// ValidateScaleEnvelope performs the packet-level checks that a routing-domain
// authorization cannot express: overlay address ownership, service admission,
// route CIDR membership, and flow-hash integrity.
func (table *Table) ValidateScaleEnvelope(envelope ScaleEnvelope) error {
	table.mu.RLock()
	state := table.state
	table.mu.RUnlock()
	return table.validateScaleEnvelope(state, envelope)
}

func (table *Table) validateScaleEnvelope(state model.NetworkState, envelope ScaleEnvelope) error {
	if envelope.Header.PathFamilyID == "" || envelope.Header.PathInstanceID == "" {
		return fmt.Errorf("%w: path family is missing", ErrScaleUnauthorized)
	}
	flow, ok := packet.ParseIPFlow(envelope.Payload)
	if !ok {
		return ErrMalformedScaleEnvelope
	}
	flowHash, ok := packet.FlowHash(envelope.Payload)
	if !ok || flowHash != envelope.Header.FlowHash {
		return fmt.Errorf("%w: flow hash mismatch", ErrScaleUnauthorized)
	}
	source, ok := peerByID(state, envelope.Header.SourcePeerID)
	if !ok {
		return ErrInvalidSource
	}
	destination, ok := peerByID(state, envelope.Header.DestinationPeerID)
	if !ok {
		return ErrDestinationHeader
	}
	sourceIP, err := netip.ParseAddr(source.OverlayIP)
	if err != nil || sourceIP.Unmap() != flow.Source {
		return ErrInvalidSource
	}
	domain, ok := routingDomainByID(state, envelope.Header.RoutingDomainID)
	if !ok || domain.Key.FlowClass != envelope.Header.FlowClass {
		return fmt.Errorf("%w: routing domain does not match", ErrScaleUnauthorized)
	}
	family, ok := pathFamilyByID(state, envelope.Header.PathFamilyID)
	if !ok || family.Kind == model.PathKindDirect || !family.Covers(domain.Key) ||
		!containsString(domain.PathFamilyIDs, family.ID) {
		return fmt.Errorf("%w: path family does not cover domain", ErrScaleUnauthorized)
	}
	if !scaleDestinationAllows(state, domain, destination, flow) {
		return ErrDestinationHeader
	}
	return scalePolicyAllowsPacket(state, domain, source, destination, flow)
}

func (table *Table) authorizeScaleReturn(
	state model.NetworkState, remote peer.ID, envelope ScaleEnvelope,
) (ScaleAuthorization, bool, error) {
	table.mu.RLock()
	faceID := table.faceID
	table.mu.RUnlock()
	flow, ok := packet.ParseIPFlow(envelope.Payload)
	if !ok {
		return ScaleAuthorization{}, false, ErrMalformedScaleEnvelope
	}
	scaleKey, ok := scaleFlowKey(envelope.Payload)
	if !ok || !table.scaleFlows.ReplyAllowed(scaleKey) {
		return ScaleAuthorization{}, false, nil
	}
	if err := validateScaleReturnEnvelope(state, envelope, flow); err != nil {
		return ScaleAuthorization{}, false, err
	}
	family, _ := pathFamilyByID(state, envelope.Header.PathFamilyID)
	localIndex := -1
	for index, hop := range family.ManagerHops {
		if hop == table.localID {
			localIndex = index
			break
		}
	}
	if localIndex < 0 {
		return ScaleAuthorization{}, false, fmt.Errorf("%w: local manager is not on return family", ErrScaleUnauthorized)
	}
	// The destination peer may submit its return envelope to any manager on
	// the certified family. A manager-to-manager leg must then follow the
	// family backwards toward the original source.
	if remote.String() != envelope.Header.SourcePeerID {
		if localIndex+1 >= len(family.ManagerHops) ||
			family.ManagerHops[localIndex+1] != remote.String() {
			return ScaleAuthorization{}, false, fmt.Errorf("%w: unexpected return predecessor", ErrScaleUnauthorized)
		}
	}
	nextHop := envelope.Header.DestinationPeerID
	if localIndex > 0 {
		nextHop = family.ManagerHops[localIndex-1]
	}
	return ScaleAuthorization{
		FaceID: faceID, NextHop: nextHop,
		ExpectedPredecessor: remote.String(),
	}, true, nil
}

func validateScaleReturnEnvelope(state model.NetworkState, envelope ScaleEnvelope, flow packet.IPFlow) error {
	if envelope.Header.PathFamilyID == "" || envelope.Header.PathInstanceID == "" {
		return fmt.Errorf("%w: path family is missing", ErrScaleUnauthorized)
	}
	flowHash, ok := packet.FlowHash(envelope.Payload)
	if !ok || flowHash != envelope.Header.FlowHash {
		return fmt.Errorf("%w: flow hash mismatch", ErrScaleUnauthorized)
	}
	source, ok := peerByID(state, envelope.Header.SourcePeerID)
	if !ok {
		return ErrInvalidSource
	}
	destination, ok := peerByID(state, envelope.Header.DestinationPeerID)
	if !ok {
		return ErrDestinationHeader
	}
	sourceIP, err := netip.ParseAddr(source.OverlayIP)
	if err != nil || sourceIP.Unmap() != flow.Source {
		return ErrInvalidSource
	}
	destinationIP, err := netip.ParseAddr(destination.OverlayIP)
	if err != nil || destinationIP.Unmap() != flow.Destination {
		return ErrDestinationHeader
	}
	domain, ok := routingDomainByID(state, envelope.Header.RoutingDomainID)
	if !ok || domain.Key.FlowClass != envelope.Header.FlowClass {
		return fmt.Errorf("%w: routing domain does not match", ErrScaleUnauthorized)
	}
	family, ok := pathFamilyByID(state, envelope.Header.PathFamilyID)
	if !ok || family.Kind == model.PathKindDirect || !family.Covers(domain.Key) ||
		!containsString(domain.PathFamilyIDs, family.ID) {
		return fmt.Errorf("%w: path family does not cover domain", ErrScaleUnauthorized)
	}
	return nil
}

func (table *Table) observeScaleFlow(envelope ScaleEnvelope) {
	key, ok := scaleFlowKey(envelope.Payload)
	if ok {
		table.scaleFlows.Observe(key)
	}
}

func scaleFlowKey(raw []byte) (conntrack.Key, bool) {
	flow, ok := packet.ParseIPFlow(raw)
	if !ok {
		return conntrack.Key{}, false
	}
	key := conntrack.Key{
		Protocol: flow.Protocol, Source: flow.Source, Destination: flow.Destination,
		SourcePort: flow.SourcePort, DestinationPort: flow.DestinationPort,
	}
	if flow.Protocol == packet.ProtocolICMP || flow.Protocol == 58 {
		offset := 40
		if flow.Version == 4 {
			offset = (int(raw[0]) & 0x0f) * 4
		}
		if len(raw) >= offset+6 {
			identifier := binary.BigEndian.Uint16(raw[offset+4 : offset+6])
			key.SourcePort = identifier
			key.DestinationPort = identifier
		}
	}
	return key, true
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

func (table *Table) recordScaleSelection(envelope ScaleEnvelope) {
	if table.metrics == nil {
		return
	}
	table.mu.RLock()
	state := table.state
	table.mu.RUnlock()
	family, ok := pathFamilyByID(state, envelope.Header.PathFamilyID)
	if !ok {
		return
	}
	table.metrics.RecordScalePathSelection(family.ID, string(family.Kind), len(family.ManagerHops))
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
	return table.admitPeerQuotas(state, assignment.SourcePeerID, assignment.DestinationPeerID, bytes)
}

func (table *Table) admitScaleQuotas(state model.NetworkState, sourcePeerID, destinationPeerID string, bytes uint64) bool {
	return table.admitPeerQuotas(state, sourcePeerID, destinationPeerID, bytes)
}

func (table *Table) admitPeerQuotas(state model.NetworkState, sourcePeerID, destinationPeerID string, bytes uint64) bool {
	sourceGroups := peerGroups(state, sourcePeerID)
	destinationGroups := peerGroups(state, destinationPeerID)

	sourceBudget, sourceMatched := table.quota.Resolve(sourcePeerID, sourceGroups, "")
	destinationBudget, destinationMatched := table.quota.Resolve(destinationPeerID, destinationGroups, "")
	if sourceMatched && destinationMatched && sourceBudget.ID == destinationBudget.ID {
		decision := table.quota.Check(sourcePeerID, sourceGroups, "", bytes)
		return decision.Allowed && decision.Delay == 0
	}
	if sourceMatched {
		decision := table.quota.Check(sourcePeerID, sourceGroups, "", bytes)
		if !decision.Allowed || decision.Delay > 0 {
			return false
		}
	}
	if destinationMatched {
		decision := table.quota.Check(destinationPeerID, destinationGroups, "", bytes)
		if !decision.Allowed || decision.Delay > 0 {
			return false
		}
	}
	return true
}

func (table *Table) admitScaleFace(budgets *quota.FaceBudgetSet, faceID, flowClass string, bytes uint64) bool {
	if budgets == nil || faceID == "" {
		return true
	}
	table.observeFaceQueue(faceID)
	decision := budgets.Admit(faceID, path.FlowClass(flowClass), bytes, time.Now().UTC())
	return decision.Allowed && decision.Delay == 0
}

func peerByID(state model.NetworkState, peerID string) (model.PeerRecord, bool) {
	for _, peer := range state.Peers {
		if peer.PeerID == peerID {
			return peer, true
		}
	}
	return model.PeerRecord{}, false
}

func routingDomainByID(state model.NetworkState, domainID string) (model.RoutingDomainAuthorization, bool) {
	for _, domain := range state.RoutingDomains {
		if domain.ID == domainID {
			return domain, true
		}
	}
	return model.RoutingDomainAuthorization{}, false
}

func pathFamilyByID(state model.NetworkState, familyID string) (model.PathFamily, bool) {
	for _, family := range state.PathFamilies {
		if family.ID == familyID {
			return family, true
		}
	}
	return model.PathFamily{}, false
}

func scaleDestinationAllows(state model.NetworkState, domain model.RoutingDomainAuthorization, destination model.PeerRecord, flow packet.IPFlow) bool {
	kind, id, _ := model.ParseDestinationScope(domain.Key.DestinationScope)
	switch kind {
	case model.DestinationScopeGroup, model.DestinationScopePeer:
		destinationIP, err := netip.ParseAddr(destination.OverlayIP)
		return err == nil && destinationIP.Unmap() == flow.Destination
	case model.DestinationScopeRoute:
		route, ok := routeByID(state, id)
		if !ok || !destination.IsExitNode || !containsString(peerGroups(state, destination.PeerID), route.RoutingGroup) {
			return false
		}
		prefix, err := netip.ParsePrefix(route.Destination)
		return err == nil && prefix.Contains(flow.Destination)
	default:
		return false
	}
}

func routeByID(state model.NetworkState, routeID string) (model.Route, bool) {
	for _, route := range state.Routes {
		if route.ID == routeID {
			return route, true
		}
	}
	return model.Route{}, false
}

func scalePolicyAllowsPacket(
	state model.NetworkState, domain model.RoutingDomainAuthorization, source, destination model.PeerRecord, flow packet.IPFlow,
) error {
	policies := make([]model.Policy, 0, len(domain.PolicyIDs))
	for _, policyID := range domain.PolicyIDs {
		for _, item := range state.Policies {
			if item.ID == policyID {
				policies = append(policies, item)
				break
			}
		}
	}
	if len(policies) == 0 {
		return fmt.Errorf("%w: domain has no policies", ErrScaleUnauthorized)
	}
	allowed, err := policy.Authorize(policy.State{
		NetworkID: state.NetworkID, Groups: state.Groups, Policies: policies,
		Routes: state.Routes, Budgets: state.Budgets,
	}, source.PeerID, destination.PeerID, flow.ProtocolName(), flow.DestinationPort, source.Posture)
	if err != nil {
		return err
	}
	if !allowed {
		return fmt.Errorf("%w: packet service is denied", ErrScaleUnauthorized)
	}
	return nil
}

func containsString(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
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
