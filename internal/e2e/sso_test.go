package e2e

import (
	"context"
	"testing"
	"time"

	"github.com/netp2p/netp2p/internal/client"
	"github.com/netp2p/netp2p/internal/manager"
	"github.com/netp2p/netp2p/internal/model"
	"github.com/netp2p/netp2p/internal/oidc"
	"github.com/netp2p/netp2p/internal/oidctest"
	"github.com/netp2p/netp2p/internal/p2p"
	"github.com/netp2p/netp2p/internal/packet"
)

// TestSSODeviceFlowRegistersUserAndGroups drives the full SSO path: a mock IdP
// issues an ID token, the manager verifies it, mirrors the IdP group into
// certified state and binds the new peer to the user.
func TestSSODeviceFlowRegistersUserAndGroups(t *testing.T) {
	ctx := t.Context()
	provider, err := oidctest.New("127.0.0.1:0", oidctest.Options{
		AutoApprove: true,
		Default: &oidctest.User{
			Subject: "user-sso", Email: "sso@example.com", Name: "SSO User",
			Groups: []string{"eng"},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer provider.Close()

	verifier, err := oidc.NewVerifier(ctx, oidc.Config{Issuer: provider.Issuer, ClientID: "netp2p", GroupsClaim: "groups"})
	if err != nil {
		t.Fatal(err)
	}

	state := testState()
	state.Settings = model.NetworkSettings{JWTGroupsEnabled: true, DNSDomain: "netp2p.internal"}
	group := newClusterWithConfig(t, state, manager.Config{SSO: verifier})
	address := group.members[0].Address

	token := deviceToken(t, provider.Issuer, "netp2p")
	netClient := newTokenClient(t, 301, address, token)
	waitForPeers(t, netClient, 1)

	snapshot := netClient.Snapshot()
	if len(snapshot.State.Users) != 1 {
		t.Fatalf("users = %d, want 1", len(snapshot.State.Users))
	}
	user := snapshot.State.Users[0]
	if user.ID != "user-sso" || user.Email != "sso@example.com" {
		t.Fatalf("user = %+v", user)
	}
	// The first account to log in owns the network.
	if user.Role != model.RoleOwner {
		t.Fatalf("role = %q, want owner", user.Role)
	}
	if len(user.AutoGroups) != 1 || user.AutoGroups[0] != "jwt-eng" {
		t.Fatalf("auto groups = %v", user.AutoGroups)
	}

	peer := netClient.Self()
	if peer.UserID != "user-sso" {
		t.Fatalf("peer user = %q", peer.UserID)
	}
	if !contains(peer.Groups, "jwt-eng") {
		t.Fatalf("peer groups = %v, want jwt-eng", peer.Groups)
	}
	if peer.LastLogin == "" {
		t.Fatal("peer last login must be recorded")
	}
}

func deviceToken(t *testing.T, issuer, clientID string) string {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	flow, err := oidc.NewDeviceFlow(ctx, oidc.Config{Issuer: issuer, ClientID: clientID})
	if err != nil {
		t.Fatalf("device flow: %v", err)
	}
	flow.Prompt = func(string, string) {}
	token, err := flow.IDToken(ctx)
	if err != nil {
		t.Fatalf("id token: %v", err)
	}
	return token
}

func newTokenClient(t *testing.T, seed int64, managerAddr, token string) *client.Client {
	t.Helper()
	ctx := t.Context()
	node, err := p2p.New(ctx, p2p.Config{IdentitySeed: seed})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = node.Close() })
	sink, err := packet.NewUDPPacketSink("127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = sink.Close() })
	netClient, err := client.New(node, managerAddr, sink)
	if err != nil {
		t.Fatal(err)
	}
	if err := netClient.Login(ctx, networkID, "", token); err != nil {
		t.Fatalf("sso login: %v", err)
	}
	go netClient.ServePackets(ctx)
	go netClient.SyncLoop(ctx)
	return netClient
}

func contains(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}
