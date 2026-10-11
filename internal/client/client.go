package client

import (
	"context"
	"errors"
	"fmt"
	"log"
	"os"
	"runtime"
	"sort"
	"sync"
	"time"

	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/core/peerstore"
	"github.com/libp2p/go-libp2p/core/protocol"
	"github.com/multiformats/go-multiaddr"
	"github.com/netp2p/netp2p/internal/bft"
	"github.com/netp2p/netp2p/internal/conntrack"
	"github.com/netp2p/netp2p/internal/exitnode"
	"github.com/netp2p/netp2p/internal/forward"
	"github.com/netp2p/netp2p/internal/link"
	"github.com/netp2p/netp2p/internal/model"
	"github.com/netp2p/netp2p/internal/p2p"
	"github.com/netp2p/netp2p/internal/packet"
	"github.com/netp2p/netp2p/internal/policy"
	netproto "github.com/netp2p/netp2p/internal/protocol"
	"github.com/netp2p/netp2p/internal/quota"
	"github.com/netp2p/netp2p/internal/transport"
	"github.com/netp2p/netp2p/internal/version"
	"github.com/netp2p/netp2p/internal/wire"
	"github.com/netp2p/netp2p/internal/wire/pb"
	"google.golang.org/protobuf/proto"
)

type Client struct {
	node             *p2p.Node
	manager          peer.AddrInfo
	managers         []peer.AddrInfo
	managerAddresses []string
	activeManager    int
	connectionState  ClientState
	lastManagerError string
	pathState        PathSelectionState
	pathError        string
	outboundDrop     string
	sink             packet.PacketSink
	snapshot         model.SignedSnapshot
	self             model.PeerRecord
	networkMap       policy.NetworkMap
	mu               sync.RWMutex

	flows           *conntrack.Table
	frames          *transport.Transport
	forwarding      *forward.Table
	paths           *pathSelector
	quota           *quota.Enforcer
	hostname        string
	admissionQueue  []netproto.AdmissionReport
	admissionWaiter *admissionWaiter
	pathStore       *pathStore
	stateStore      *clientStateStore
	synthesizeICMP  bool
	routesReady     bool
	posture         []string
	exitReconciler  *exitnode.Reconciler
	exitNodeEnabled bool
	dnsUpdater      DNSUpdater
	dnsUpstreams    []string
	retrySleep      func(context.Context, time.Duration) error
}

const (
	loginRetryLimit    = 10
	recoveryRetryLimit = 10
	retryInitialDelay  = 250 * time.Millisecond
	retryMaxDelay      = 5 * time.Second
	connectTimeout     = 3 * time.Second
)

func New(node *p2p.Node, managerAddr string, sink packet.PacketSink, options ...Option) (*Client, error) {
	if _, err := peer.AddrInfoFromString(managerAddr); err != nil {
		return nil, fmt.Errorf("invalid manager address: %w", err)
	}
	client := &Client{
		node: node, sink: sink, flows: conntrack.NewTable(),
		managerAddresses: []string{managerAddr},
		retrySleep:       sleepWithContext,
	}
	client.forwarding = forward.NewTable(model.NetworkState{}, node.Host.ID().String(), func(remote peer.ID, envelope forward.Envelope) error {
		frames := client.frameTransport()
		if frames == nil {
			return fmt.Errorf("frame transport unavailable")
		}
		wire, err := forward.EncodeEnvelope(envelope)
		if err != nil {
			return err
		}
		return frames.SendEnvelope(remote, wire)
	})
	for _, option := range options {
		option(client)
	}
	if err := client.setManagers(); err != nil {
		return nil, err
	}
	client.restorePersistedState()
	client.paths = newPathSelector(client.forwarding, client.pathStore)
	if marker, ok := sink.(packet.UserspaceICMP); ok {
		client.synthesizeICMP = marker.SynthesizeICMP()
	}
	// Answer manager probes so the committee can estimate access-link quality.
	node.Handle(p2p.ProbeProtocol, link.NewProbeResponder().Handle)
	return client, nil
}

// LoginError carries the manager's machine-readable failure code so the client
// can react (re-authenticate, retry) without matching error prose.
type LoginError struct {
	Code    string
	Message string
}

func (err *LoginError) Error() string {
	if err.Message != "" {
		return err.Message
	}
	return "login failed: " + err.Code
}

// SyncError is a manager response that will not become valid by retrying the
// same request, such as a network or peer identity mismatch.
type SyncError struct {
	Code    string
	Message string
}

func (err *SyncError) Error() string {
	if err.Message != "" {
		return err.Message
	}
	return "sync failed: " + err.Code
}

// RetryExhaustedError marks a bounded retry sequence so callers can show a
// terminal state instead of looping forever at the process boundary.
type RetryExhaustedError struct {
	Operation string
	Attempts  int
	Err       error
}

func (err *RetryExhaustedError) Error() string {
	return fmt.Sprintf("%s failed after %d attempts: %v", err.Operation, err.Attempts, err.Err)
}

func (err *RetryExhaustedError) Unwrap() error { return err.Err }

var ErrNeedsLogin = errors.New("client needs login")

func (client *Client) Login(ctx context.Context, networkID, setupKey, jwtToken string) error {
	if client.hasRecoverableState() {
		err := client.Recover(ctx)
		if err == nil {
			return nil
		}
		var syncErr *SyncError
		if !errors.As(err, &syncErr) {
			return err
		}
		// Peer removal or a network mismatch invalidates the old recovery
		// record; explicit login is then the next boundary.
	}
	return client.loginWithRetry(ctx, networkID, setupKey, jwtToken)
}

func (client *Client) loginWithRetry(ctx context.Context, networkID, setupKey, jwtToken string) error {
	var lastErr error
	for attempt := 1; attempt <= loginRetryLimit; attempt++ {
		err := client.loginOnce(ctx, networkID, setupKey, jwtToken)
		if err == nil {
			return nil
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
		var loginErr *LoginError
		if errors.As(err, &loginErr) {
			return err
		}
		lastErr = err
		if attempt < loginRetryLimit {
			if err := client.sleepBeforeRetry(ctx, attempt); err != nil {
				return err
			}
		}
	}
	return &RetryExhaustedError{Operation: "login", Attempts: loginRetryLimit, Err: lastErr}
}

func (client *Client) loginOnce(ctx context.Context, networkID, setupKey, jwtToken string) error {
	if err := client.connect(ctx); err != nil {
		return fmt.Errorf("connect manager: %w", err)
	}
	request := netproto.LoginRequest{
		NetworkID: networkID, SetupKey: setupKey, JWTToken: jwtToken,
		PeerID: client.node.Host.ID().String(), Addresses: client.node.Addresses(),
		ProtocolVersion: version.ProtocolVersion, Capabilities: version.Capabilities(),
	}
	request.Hostname = client.Hostname()
	request.OS = runtime.GOOS
	request.ClientVersion = version.Version
	request.Posture = append([]string(nil), client.posture...)
	var loginReply pb.LoginResponse
	if err := client.request(ctx, p2p.LoginProtocol, wire.LoginRequestToProto(request), &loginReply); err != nil {
		client.markManagerRequestFailure(err)
		return err
	}
	response := wire.LoginResponseFromProto(&loginReply)
	if response.Error != "" {
		client.setClientState(ClientStateNeedsLogin)
		if response.Code != "" {
			return &LoginError{Code: response.Code, Message: response.Error}
		}
		return fmt.Errorf("login failed: %s", response.Error)
	}
	if err := bft.ValidateClientSnapshot(response.Snapshot); err != nil {
		client.setClientState(ClientStateFailed)
		return fmt.Errorf("invalid certified snapshot: %w", err)
	}
	client.applySnapshot(response.Snapshot, response.Peer)
	return nil
}

// Sync long-polls the manager for a newer certified snapshot. A heartbeat at
// the same height confirms that persisted state is current without treating a
// quiet long poll as a stream error.
func (client *Client) Sync(ctx context.Context) error {
	client.mu.Lock()
	height := client.snapshot.Height
	networkID := client.snapshot.State.NetworkID
	assignmentHeight := assignmentHeightLocked(client.snapshot)
	admissions := client.admissionQueue
	client.admissionQueue = nil
	client.mu.Unlock()
	if err := client.connect(ctx); err != nil {
		return fmt.Errorf("connect manager: %w", err)
	}
	syncRequest := netproto.SyncRequest{
		NetworkID: networkID, PeerID: client.node.Host.ID().String(), Height: height,
		AssignmentsHeight: assignmentHeight, Admissions: admissions,
		ProtocolVersion: version.ProtocolVersion,
	}
	result, err := client.requestSync(ctx, syncRequest)
	if err != nil {
		client.queueAdmissions(admissions)
		var syncErr *SyncError
		if errors.As(err, &syncErr) {
			client.markSyncError(syncErr)
		} else {
			client.markManagerRequestFailure(err)
		}
		return err
	}
	snapshot := result.snapshot
	if result.heartbeat.networkID != "" {
		if result.heartbeat.networkID != networkID {
			client.setClientState(ClientStateNeedsLogin)
			return &SyncError{Code: "network_mismatch", Message: "sync heartbeat network does not match local state"}
		}
		if result.heartbeat.height < height {
			client.setClientState(ClientStateDegraded)
			return &SyncError{Code: "stale_manager", Message: "manager is behind the local certified snapshot"}
		}
		client.mu.Lock()
		client.lastManagerError = ""
		if height > 0 {
			client.connectionState = ClientStateReady
		}
		client.mu.Unlock()
		return nil
	}
	if err := bft.ValidateClientSnapshot(snapshot); err != nil {
		if client.SnapshotHeight() > 0 {
			client.setClientState(ClientStateDegraded)
		} else {
			client.setClientState(ClientStateFailed)
		}
		return err
	}
	if snapshot.State.NetworkID != networkID || snapshot.Height < height {
		client.setClientState(ClientStateDegraded)
		return &SyncError{Code: "invalid_snapshot", Message: "manager snapshot does not match local certified state"}
	}
	client.mu.RLock()
	self := client.self
	client.mu.RUnlock()
	if peerRecord, ok := findPeer(snapshot, self.PeerID); ok {
		self = peerRecord
	} else if self.PeerID != "" {
		client.setClientState(ClientStateNeedsLogin)
		return &SyncError{Code: "peer_removed", Message: "local peer is no longer present in certified state"}
	}
	client.applySnapshot(snapshot, self)
	return nil
}

type syncHeartbeat struct {
	networkID string
	height    uint64
}

type syncResult struct {
	snapshot  model.SignedSnapshot
	heartbeat syncHeartbeat
}

func (client *Client) requestSync(ctx context.Context, request netproto.SyncRequest) (syncResult, error) {
	stream, err := client.node.Host.NewStream(ctx, client.manager.ID, p2p.SyncProtocol)
	if err != nil {
		return syncResult{}, err
	}
	defer stream.Close()
	if err := p2p.WriteMessage(stream, p2p.SyncProtocol, wire.SyncRequestToProto(request)); err != nil {
		return syncResult{}, err
	}
	if closer, ok := stream.(interface{ CloseWrite() error }); ok {
		_ = closer.CloseWrite()
	}
	for {
		envelope, err := p2p.DecodeEnvelope(stream)
		if err != nil {
			return syncResult{}, err
		}
		if envelope.Protocol != p2p.SyncProtocol {
			return syncResult{}, fmt.Errorf("unexpected sync response protocol %q", envelope.Protocol)
		}
		var reply pb.SyncResponse
		if err := proto.Unmarshal(envelope.Payload, &reply); err != nil {
			return syncResult{}, err
		}
		switch response := reply.GetResponse().(type) {
		case *pb.SyncResponse_Snapshot:
			return syncResult{snapshot: wire.SignedSnapshotFromProto(response.Snapshot)}, nil
		case *pb.SyncResponse_Heartbeat:
			heartbeat := response.Heartbeat
			if heartbeat == nil {
				return syncResult{}, fmt.Errorf("empty sync heartbeat")
			}
			return syncResult{heartbeat: syncHeartbeat{
				networkID: heartbeat.GetNetworkId(), height: heartbeat.GetHeight(),
			}}, nil
		case *pb.SyncResponse_Error:
			syncErr := response.Error
			if syncErr == nil {
				return syncResult{}, fmt.Errorf("empty sync error")
			}
			return syncResult{}, &SyncError{Code: syncErr.GetCode(), Message: syncErr.GetMessage()}
		default:
			return syncResult{}, fmt.Errorf("sync response had no payload")
		}
	}
}

// Recover refreshes persisted certified state without registering the peer
// again. It is the startup and manager-failover path for an existing identity.
func (client *Client) Recover(ctx context.Context) error {
	if !client.hasRecoverableState() {
		client.setClientState(ClientStateNeedsLogin)
		return ErrNeedsLogin
	}
	var lastErr error
	for attempt := 1; attempt <= recoveryRetryLimit; attempt++ {
		err := client.Sync(ctx)
		if err == nil {
			return nil
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
		var syncErr *SyncError
		if errors.As(err, &syncErr) {
			return err
		}
		lastErr = err
		if attempt < recoveryRetryLimit {
			if err := client.sleepBeforeRetry(ctx, attempt); err != nil {
				return err
			}
		}
	}
	client.markManagerRequestFailure(lastErr)
	return &RetryExhaustedError{Operation: "recovery", Attempts: recoveryRetryLimit, Err: lastErr}
}

func (client *Client) hasRecoverableState() bool {
	client.mu.RLock()
	defer client.mu.RUnlock()
	if client.snapshot.Height == 0 || client.self.PeerID != client.node.Host.ID().String() {
		return false
	}
	_, present := findPeer(client.snapshot, client.self.PeerID)
	return present
}

func (client *Client) sleepBeforeRetry(ctx context.Context, attempt int) error {
	delay := retryInitialDelay << (attempt - 1)
	if delay > retryMaxDelay || delay <= 0 {
		delay = retryMaxDelay
	}
	return client.retrySleep(ctx, delay)
}

func sleepWithContext(ctx context.Context, delay time.Duration) error {
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

// SyncLoop keeps the local certified snapshot fresh for the lifetime of ctx.
func (client *Client) SyncLoop(ctx context.Context) {
	for ctx.Err() == nil {
		if err := client.Sync(ctx); err != nil {
			if ctx.Err() != nil {
				return
			}
			log.Printf("sync: %v", err)
			select {
			case <-ctx.Done():
				return
			case <-time.After(time.Second):
			}
		}
	}
}

func (client *Client) connect(ctx context.Context) error {
	client.mu.RLock()
	candidates := append([]peer.AddrInfo(nil), client.managers...)
	start := client.activeManager
	client.mu.RUnlock()
	if len(candidates) == 0 {
		return fmt.Errorf("no manager endpoints configured")
	}
	var lastErr error
	for offset := range candidates {
		index := (start + offset) % len(candidates)
		candidate := candidates[index]
		connectContext, cancel := context.WithTimeout(ctx, connectTimeout)
		err := client.node.Host.Connect(connectContext, candidate)
		cancel()
		if err != nil {
			lastErr = err
			continue
		}
		client.mu.Lock()
		client.manager = candidate
		client.activeManager = index
		client.lastManagerError = ""
		if client.snapshot.Height > 0 {
			client.connectionState = ClientStateReady
		} else {
			client.connectionState = ClientStateNeedsLogin
		}
		client.mu.Unlock()
		return nil
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("no manager endpoint was reachable")
	}
	client.mu.Lock()
	client.lastManagerError = lastErr.Error()
	if client.snapshot.Height > 0 {
		client.connectionState = ClientStateDegraded
	} else {
		client.connectionState = ClientStateFailed
	}
	client.mu.Unlock()
	return lastErr
}

func (client *Client) applySnapshot(snapshot model.SignedSnapshot, self model.PeerRecord) {
	networkMap := policy.Compile(policy.State{
		NetworkID: snapshot.State.NetworkID,
		Groups:    snapshot.State.Groups,
		Policies:  snapshot.State.Policies,
		Routes:    snapshot.State.Routes,
		Budgets:   snapshot.State.Budgets,
	}, self.PeerID, snapshot.Epoch)
	client.mu.Lock()
	client.snapshot = snapshot
	if self.PeerID != "" {
		client.self = self
	}
	client.networkMap = networkMap
	client.connectionState = ClientStateReady
	client.lastManagerError = ""
	if client.quota == nil {
		client.quota = quota.NewEnforcer(snapshot.State.Budgets)
	} else {
		client.quota.Replace(snapshot.State.Budgets)
	}
	localPeerID := client.node.Host.ID()
	overlayIPs := client.peerOverlayIPsLocked()
	client.mu.Unlock()
	client.persistSnapshot(snapshot, self)
	client.rememberPeers(snapshot, localPeerID)
	client.reconcileRoutesWhenReady(overlayIPs)
	client.reconcileNetworks()
	client.reconcileExitNode()
	client.publishDNS()
	client.paths.replaceAssignments(snapshot.State.Assignments)
	client.forwarding.Replace(snapshot.State)
	go client.runAdmissionProbe(snapshot, self.PeerID)
}

func (client *Client) queueAdmissions(reports []netproto.AdmissionReport) {
	if len(reports) == 0 {
		return
	}
	client.mu.Lock()
	client.admissionQueue = append(reports, client.admissionQueue...)
	client.mu.Unlock()
}

func (client *Client) reportAdmission(report netproto.AdmissionReport) {
	client.mu.Lock()
	client.admissionQueue = append(client.admissionQueue, report)
	client.mu.Unlock()
}

func (client *Client) frameTransport() *transport.Transport {
	client.mu.RLock()
	defer client.mu.RUnlock()
	return client.frames
}

// peerOverlayIPsLocked lists every other peer's overlay address.
//
// Routes intentionally cover all peers rather than only policy-allowed ones.
// The kernel needs a route to emit reply traffic, and a reply for a flow we
// admitted inbound is legitimate even when the mirror-image policy denies it.
// Access control stays in this process: every packet, in both directions, is
// checked against the certified policy before it is forwarded. The route only
// decides which destinations the kernel hands to the overlay instead of the
// default gateway. The caller must hold the client lock.
func (client *Client) peerOverlayIPsLocked() []string {
	self := client.self.PeerID
	result := make([]string, 0, len(client.snapshot.State.Peers))
	for _, record := range client.snapshot.State.Peers {
		if record.PeerID == self || record.OverlayIP == "" {
			continue
		}
		result = append(result, record.OverlayIP)
	}
	sort.Strings(result)
	return result
}

// ReconcileRoutes pushes the current overlay addresses into the kernel
// routing table. It is called after the device is configured, because the login
// snapshot is applied before the interface has an address. Calling it also
// lifts the gate that suppresses route writes until then.
func (client *Client) ReconcileRoutes() {
	client.mu.Lock()
	client.routesReady = true
	overlayIPs := client.peerOverlayIPsLocked()
	client.mu.Unlock()
	client.applyRoutes(overlayIPs)
	client.reconcileNetworks()
}

// reconcileNetworks installs certified subnet/exit CIDR routes so the kernel
// hands those destinations to the overlay instead of the default gateway.
func (client *Client) reconcileNetworks() {
	client.mu.RLock()
	ready := client.routesReady
	client.mu.RUnlock()
	if !ready {
		return
	}
	reconciler, ok := client.sink.(packet.RouteReconciler)
	if !ok {
		return
	}
	if err := reconciler.ReconcileNetworks(client.networkCIDRs()); err != nil {
		log.Printf("overlay network route reconcile: %v", err)
	}
}

// reconcileExitNode installs the kernel forwarding state for routes this node
// serves as an exit/subnet gateway.
func (client *Client) reconcileExitNode() {
	client.mu.RLock()
	reconciler := client.exitReconciler
	client.mu.RUnlock()
	if reconciler == nil {
		return
	}
	if err := reconciler.Reconcile(client.exitRoutes()); err != nil {
		log.Printf("exit node reconcile: %v", err)
	}
}

// reconcileRoutesWhenReady installs routes for a freshly applied snapshot, but
// skips the write while the interface is not configured yet. The kernel would
// reject the route with "Device for nexthop is not up", so the post-configure
// ReconcileRoutes call is the one that installs the initial table.
func (client *Client) reconcileRoutesWhenReady(overlayIPs []string) {
	client.mu.RLock()
	ready := client.routesReady
	client.mu.RUnlock()
	if !ready {
		return
	}
	client.applyRoutes(overlayIPs)
}

func (client *Client) applyRoutes(overlayIPs []string) {
	reconciler, ok := client.sink.(packet.RouteReconciler)
	if !ok {
		return
	}
	if err := reconciler.ReconcileRoutes(overlayIPs); err != nil {
		log.Printf("overlay route reconcile: %v", err)
	}
}

// rememberPeers teaches the libp2p peerstore how to dial overlay peers so that
// frame streams can open without an explicit connect step.
func (client *Client) rememberPeers(snapshot model.SignedSnapshot, local peer.ID) {
	for _, record := range snapshot.State.Peers {
		peerID, err := peer.Decode(record.PeerID)
		if err != nil || peerID == local {
			continue
		}
		addresses := make([]multiaddr.Multiaddr, 0, len(record.Addresses))
		for _, value := range record.Addresses {
			address, err := multiaddr.NewMultiaddr(value)
			if err != nil {
				continue
			}
			addresses = append(addresses, address)
		}
		if len(addresses) > 0 {
			client.node.Host.Peerstore().AddAddrs(peerID, addresses, peerstore.PermanentAddrTTL)
		}
	}
}

func findPeer(snapshot model.SignedSnapshot, peerID string) (model.PeerRecord, bool) {
	for _, record := range snapshot.State.Peers {
		if record.PeerID == peerID {
			return record, true
		}
	}
	return model.PeerRecord{}, false
}

func (client *Client) request(ctx context.Context, protocolID protocol.ID, request proto.Message, response proto.Message) error {
	stream, err := client.node.Host.NewStream(ctx, client.manager.ID, protocolID)
	if err != nil {
		return err
	}
	defer stream.Close()
	if err := p2p.WriteMessage(stream, protocolID, request); err != nil {
		return err
	}
	if closer, ok := stream.(interface{ CloseWrite() error }); ok {
		_ = closer.CloseWrite()
	}
	envelope, err := p2p.DecodeEnvelope(stream)
	if err != nil {
		return err
	}
	return proto.Unmarshal(envelope.Payload, response)
}

func (client *Client) Self() model.PeerRecord {
	client.mu.RLock()
	defer client.mu.RUnlock()
	return client.self
}

// Hostname returns the identity advertised during login. Operators may set a
// stable name for containers; otherwise the operating system hostname is used.
func (client *Client) Hostname() string {
	client.mu.RLock()
	hostname := client.hostname
	client.mu.RUnlock()
	if hostname != "" {
		return hostname
	}
	hostname, _ = os.Hostname()
	return hostname
}

func (client *Client) SnapshotHeight() uint64 {
	client.mu.RLock()
	defer client.mu.RUnlock()
	return client.snapshot.Height
}

func (client *Client) Snapshot() model.SignedSnapshot {
	client.mu.RLock()
	defer client.mu.RUnlock()
	return client.snapshot
}
