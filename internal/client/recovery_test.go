package client

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/libp2p/go-libp2p/core/network"
	"github.com/netp2p/netp2p/internal/model"
	"github.com/netp2p/netp2p/internal/p2p"
	"github.com/netp2p/netp2p/internal/wire/pb"
	"google.golang.org/protobuf/proto"
)

func TestLoadRecoveryBootstrapRejectsMissingState(t *testing.T) {
	if _, err := LoadRecoveryBootstrap(t.TempDir()); err == nil {
		t.Fatal("LoadRecoveryBootstrap accepted missing state")
	}
}

func TestLoadRecoveryBootstrapReturnsValidatedManagerEndpoints(t *testing.T) {
	const networkID = "net-bootstrap"
	local := newTestP2PNode(t)
	primary := newTestP2PNode(t)
	secondary := newTestP2PNode(t)
	primaryAddress := primary.Addresses()[0]
	secondaryAddress := secondary.Addresses()[0]
	stateDir := t.TempDir()
	self := model.PeerRecord{PeerID: local.Host.ID().String(), OverlayIP: "10.80.0.9"}

	existing, err := New(local, primaryAddress, nil,
		WithStateDir(stateDir), WithManagerFailover(secondaryAddress))
	if err != nil {
		t.Fatal(err)
	}
	existing.applySnapshot(certifiedClientSnapshot(t, networkID, self), self)
	existing.Close()

	bootstrap, err := LoadRecoveryBootstrap(stateDir)
	if err != nil {
		t.Fatalf("LoadRecoveryBootstrap: %v", err)
	}
	if bootstrap.LocalPeerID != local.Host.ID().String() || bootstrap.NetworkID != networkID {
		t.Fatalf("unexpected bootstrap identity/network: %+v", bootstrap)
	}
	if len(bootstrap.ManagerEndpoints) != 2 ||
		bootstrap.ManagerEndpoints[0] != primaryAddress || bootstrap.ManagerEndpoints[1] != secondaryAddress {
		t.Fatalf("unexpected bootstrap manager endpoints: %+v", bootstrap.ManagerEndpoints)
	}
}

func TestLoginRecoversPersistedStateWithoutRegistering(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	const networkID = "net-recovery"
	local := newTestP2PNode(t)
	primary := newTestP2PNode(t)
	secondary := newTestP2PNode(t)
	primaryAddress := primary.Addresses()[0]
	secondaryAddress := secondary.Addresses()[0]

	var syncCount, loginCount atomic.Int64
	primary.Handle(p2p.SyncProtocol, func(stream network.Stream) {
		defer stream.Close()
		writeTestHeartbeat(t, stream)
	})
	secondary.Handle(p2p.SyncProtocol, func(stream network.Stream) {
		defer stream.Close()
		syncCount.Add(1)
		writeTestHeartbeat(t, stream)
	})
	primary.Handle(p2p.LoginProtocol, func(stream network.Stream) {
		defer stream.Close()
		loginCount.Add(1)
	})
	secondary.Handle(p2p.LoginProtocol, func(stream network.Stream) {
		defer stream.Close()
		loginCount.Add(1)
	})

	stateDir := t.TempDir()
	self := model.PeerRecord{PeerID: local.Host.ID().String(), OverlayIP: "10.80.0.9"}
	snapshot := certifiedClientSnapshot(t, networkID, self)
	existing, err := New(local, primaryAddress, nil,
		WithStateDir(stateDir), WithManagerFailover(secondaryAddress))
	if err != nil {
		t.Fatal(err)
	}
	existing.applySnapshot(snapshot, self)
	existing.Close()

	if err := primary.Close(); err != nil {
		t.Fatal(err)
	}
	restarted, err := New(local, primaryAddress, nil,
		WithStateDir(stateDir), WithManagerFailover(secondaryAddress))
	if err != nil {
		t.Fatal(err)
	}
	defer restarted.Close()
	if restarted.State() != ClientStateDegraded {
		t.Fatalf("restored state = %q, want degraded", restarted.State())
	}

	if err := restarted.Login(ctx, networkID, "setup-key-should-not-be-used", ""); err != nil {
		t.Fatalf("recovery login: %v (sync=%d login=%d active=%s state=%s)",
			err, syncCount.Load(), loginCount.Load(), restarted.ManagerStatus().ActiveManager, restarted.State())
	}
	if restarted.State() != ClientStateReady {
		t.Fatalf("state after recovery = %q, want ready", restarted.State())
	}
	if restarted.ManagerStatus().ActiveManager != secondary.Host.ID() {
		t.Fatalf("active manager after recovery = %q, want %q",
			restarted.ManagerStatus().ActiveManager, secondary.Host.ID())
	}
	if syncCount.Load() != 1 {
		t.Fatalf("sync requests = %d, want 1", syncCount.Load())
	}
	if loginCount.Load() != 0 {
		t.Fatalf("login requests = %d, want 0", loginCount.Load())
	}
	if action := restarted.NextAction(); action == "" {
		t.Fatal("next action is empty for a ready client")
	}
}

func TestLoginUsesBoundedExponentialBackoff(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	manager := newTestP2PNode(t)
	managerAddress := manager.Addresses()[0]
	if err := manager.Close(); err != nil {
		t.Fatal(err)
	}
	local := newTestP2PNode(t)
	netClient, err := New(local, managerAddress, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer netClient.Close()

	var sleeps []time.Duration
	netClient.retrySleep = func(_ context.Context, delay time.Duration) error {
		sleeps = append(sleeps, delay)
		return nil
	}
	err = netClient.Login(ctx, "net-retry", "setup-key", "")
	var exhausted *RetryExhaustedError
	if !errors.As(err, &exhausted) {
		t.Fatalf("login error = %v, want RetryExhaustedError", err)
	}
	if exhausted.Attempts != loginRetryLimit {
		t.Fatalf("login attempts = %d, want %d", exhausted.Attempts, loginRetryLimit)
	}
	want := []time.Duration{
		250 * time.Millisecond, 500 * time.Millisecond, time.Second, 2 * time.Second, 4 * time.Second,
	}
	if len(sleeps) != loginRetryLimit-1 {
		t.Fatalf("retry sleeps = %d, want %d", len(sleeps), loginRetryLimit-1)
	}
	for index, delay := range want {
		if sleeps[index] != delay {
			t.Fatalf("retry delay %d = %s, want %s", index, sleeps[index], delay)
		}
	}
	for _, delay := range sleeps[5:] {
		if delay != retryMaxDelay {
			t.Fatalf("capped retry delay = %s, want %s", delay, retryMaxDelay)
		}
	}
	if netClient.State() != ClientStateFailed {
		t.Fatalf("state after exhausted retries = %q, want failed", netClient.State())
	}
	if netClient.NextAction() == "" {
		t.Fatal("failed client has no next action")
	}
}

func writeTestHeartbeat(t *testing.T, stream network.Stream) {
	t.Helper()
	envelope, err := p2p.DecodeEnvelope(stream)
	if err != nil {
		return
	}
	var request pb.SyncRequest
	if err := proto.Unmarshal(envelope.Payload, &request); err != nil {
		return
	}
	response := &pb.SyncResponse{Response: &pb.SyncResponse_Heartbeat{Heartbeat: &pb.SyncHeartbeat{
		NetworkId: request.GetNetworkId(), Height: request.GetHeight(), ServerTimeUnixMs: time.Now().UnixMilli(),
	}}}
	if err := p2p.WriteMessage(stream, p2p.SyncProtocol, response); err != nil {
		return
	}
	if closer, ok := stream.(interface{ CloseWrite() error }); ok {
		_ = closer.CloseWrite()
	}
}
