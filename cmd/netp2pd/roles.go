package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"time"

	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/netp2p/netp2p/internal/alerts"
	"github.com/netp2p/netp2p/internal/bft"
	"github.com/netp2p/netp2p/internal/config"
	"github.com/netp2p/netp2p/internal/crypto/bls"
	"github.com/netp2p/netp2p/internal/dkg"
	"github.com/netp2p/netp2p/internal/link"
	"github.com/netp2p/netp2p/internal/manager"
	"github.com/netp2p/netp2p/internal/metrics"
	"github.com/netp2p/netp2p/internal/model"
	"github.com/netp2p/netp2p/internal/oidc"
	"github.com/netp2p/netp2p/internal/p2p"
	"github.com/netp2p/netp2p/internal/web"
)

// alertOptions carries the alerting configuration resolved from flags and the
// config file. Alerting is manager-local and independent of certified state.
type alertOptions struct {
	webhook              string
	webhookSecret        string
	interval             time.Duration
	dropCount            uint64
	dropRatePercent      float64
	allowInsecureWebhook bool
}

func runManager(ctx context.Context, dataDir, configPath, listenAddr, webListen, metricsListen string, forwarding, runDKG, rotateKeys bool, alerting alertOptions) error {
	seed, err := config.Load(configPath)
	if err != nil {
		return err
	}
	localIndex := -1
	if managerID := os.Getenv("NETP2P_MANAGER_ID"); managerID != "" {
		for index, candidate := range seed.Managers {
			if candidate.ID == managerID {
				localIndex = index
				break
			}
		}
	} else {
		for index, candidate := range seed.Managers {
			if candidate.Address == listenAddr {
				localIndex = index
				break
			}
		}
	}
	if localIndex < 0 {
		return fmt.Errorf("manager identity not found for address %q", listenAddr)
	}
	local := seed.Managers[localIndex]
	privateKey := bft.SeededPrivateKey(local.KeySeed)
	webrtcListen := local.ListenAddr
	if webrtcListen == "" {
		webrtcListen = "/ip4/0.0.0.0/udp/0/webrtc-direct"
	}
	node, err := p2p.New(ctx, p2p.Config{
		DataDir: dataDir, Listen: []string{listenAddr},
		WebRTCListen: []string{webrtcListen}, IdentitySeed: local.KeySeed,
		EnableRelayService: forwarding,
	})
	if err != nil {
		return err
	}
	defer node.Close()
	engine, err := bft.NewEngine(seed.NetworkState(), seed.Managers, local.ID, privateKey)
	if err != nil {
		return err
	}
	// DKG shares are persisted per epoch; installing the loader lets this
	// manager sign under a DKG-rotated key it generated in an earlier run.
	memberIDs := make([]string, 0, len(seed.Managers))
	for _, manager := range seed.Managers {
		memberIDs = append(memberIDs, manager.ID)
	}
	engine.SetDKGLoader(func(epoch uint64) (*bls.KeySet, bool) {
		return dkg.LoadShare(dataDir, epoch, local.ID, memberIDs, bft.QuorumSize)
	})
	mesh, err := manager.NewCommitteeMesh(node, engine, seed.Managers)
	if err != nil {
		return err
	}
	// Register the DKG handler before the mesh connects so a peer's ceremony
	// stream never arrives at an unregistered protocol.
	var ceremony *dkg.Ceremony
	if runDKG {
		ceremony, err = newDKGCeremony(node, engine, seed, local.ID)
		if err != nil {
			return err
		}
		node.Handle(p2p.DKGProtocol, ceremony.Handle)
	}
	connectContext, cancel := context.WithTimeout(ctx, 10*time.Second)
	err = mesh.Connect(connectContext)
	cancel()
	if err != nil {
		return err
	}
	readyContext, cancel := context.WithTimeout(ctx, 10*time.Second)
	err = mesh.WaitReady(readyContext)
	cancel()
	if err != nil {
		return err
	}
	// A restarting or lagging manager first tries to catch up from peers.
	// If catch-up fails, the height-1 leader still tries genesis so a cold
	// start (all managers fresh) can certify the first state.
	if engine.Height() == 0 {
		catchContext, cancel := context.WithTimeout(ctx, 5*time.Second)
		_ = mesh.CatchUp(catchContext)
		cancel()
		if engine.Leader(1, 0).ID == local.ID {
			if err := submitGenesis(ctx, mesh); err != nil {
				return err
			}
		}
	}
	if runDKG {
		if err := runDKGRotation(ctx, ceremony, engine, mesh, local.ID, dataDir); err != nil {
			return err
		}
	} else if rotateKeys {
		if err := runSeedRotation(ctx, engine, mesh, local.ID); err != nil {
			return err
		}
	}
	// Register control handlers only after genesis so early client logins fail
	// fast and retry instead of racing the genesis transition.
	var sso *oidc.Verifier
	var bootstrapOIDC *web.BootstrapOIDC
	if seed.OIDC.Enabled() {
		verifier, err := oidc.NewVerifier(ctx, seed.OIDC)
		if err != nil {
			return fmt.Errorf("configure sso: %w", err)
		}
		sso = verifier
		authURL, tokenURL, _ := verifier.Endpoint()
		webClientID := seed.OIDC.WebClientID
		if webClientID == "" {
			webClientID = seed.OIDC.ClientID
		}
		bootstrapOIDC = &web.BootstrapOIDC{
			Issuer: seed.OIDC.Issuer, ClientID: webClientID,
			Scopes:                seed.OIDC.ScopesOrDefault(),
			AuthorizationEndpoint: authURL, TokenEndpoint: tokenURL,
		}
		log.Printf("sso enabled with issuer %s", seed.OIDC.Issuer)
	}
	linkGossiper := link.NewGossiper(node, mesh.PeerIDs(), engine.LocalID(), 10*time.Second, 90*time.Second, 1000)
	var collector *metrics.Metrics
	if metricsListen != "" {
		collector = metrics.New()
		if err := startMetricsServer(ctx, metricsListen, collector.Handler()); err != nil {
			return err
		}
	}
	// Alerts are always evaluated; without a webhook they are written to the
	// structured log so an operator still sees a record of every transition.
	webhookSink, err := alerts.NewWebhookSink(alerting.webhook, alerting.webhookSecret, alerting.allowInsecureWebhook)
	if err != nil {
		return err
	}
	alerter := alerts.New(
		alerts.Config{
			Interval: alerting.interval,
			Thresholds: alerts.Thresholds{
				DropCount:       alerting.dropCount,
				DropRatePercent: alerting.dropRatePercent,
			},
		},
		alerts.LogSink{},
		webhookSink,
	)
	if alerting.webhook != "" {
		log.Printf("alerting to webhook %s every %s", alerting.webhook, alerting.interval)
	}
	netManager := manager.New(node, engine, mesh, manager.Config{
		SSO: sso, Links: linkGossiper, Forwarding: forwarding, Metrics: collector, Alerts: alerter,
	})
	manager.RegisterAdminHandler(node, mesh, seed.AdminToken)
	netManager.EnableForwarding(ctx)
	go netManager.RunPresenceGossip(ctx)
	node.Handle(p2p.LinkGossipProtocol, linkGossiper.Handle)
	go linkGossiper.Run(ctx)
	go netManager.RunLinkProbe(ctx)
	go netManager.RunScheduler(ctx)
	go netManager.RunQuotaSettlement(ctx)
	go netManager.RunAlerting(ctx)

	webServer, err := web.NewServer(node, netManager, web.Config{
		AdminToken: seed.AdminToken, Authenticator: netManager, OIDC: bootstrapOIDC,
	})
	if err != nil {
		return fmt.Errorf("create web server: %w", err)
	}
	if err := webServer.StartInsecureBootstrap(webListen); err != nil {
		return fmt.Errorf("start web bootstrap: %w", err)
	}
	go func() {
		if serveErr := webServer.HTTPHost().Serve(); serveErr != nil {
			log.Printf("libp2p http server stopped: %v", serveErr)
		}
	}()
	defer webServer.Stop()

	return runStatus(ctx, node)
}

// startMetricsServer exposes the Prometheus endpoint on a dedicated listener so
// instrumentation never shares the authenticated bootstrap/API port.
func startMetricsServer(ctx context.Context, address string, handler http.Handler) error {
	listener, err := net.Listen("tcp", address)
	if err != nil {
		return fmt.Errorf("listen for metrics on %s: %w", address, err)
	}
	server := &http.Server{Handler: handler, ReadHeaderTimeout: 5 * time.Second}
	go func() {
		<-ctx.Done()
		shutdownContext, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = server.Shutdown(shutdownContext)
	}()
	go func() {
		if serveErr := server.Serve(listener); serveErr != nil && serveErr != http.ErrServerClosed {
			log.Printf("metrics server stopped: %v", serveErr)
		}
	}()
	log.Printf("metrics available on http://%s/metrics", address)
	return nil
}

func submitGenesis(ctx context.Context, mesh *manager.CommitteeMesh) error {
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := mesh.Submit(model.StateTransition{Type: bft.TransitionGenesis}); err == nil {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(500 * time.Millisecond):
		}
	}
	return fmt.Errorf("could not certify genesis state")
}

// newDKGCeremony builds a ceremony over the seed committee. The target epoch is
// the one the rotation will activate.
func newDKGCeremony(node *p2p.Node, engine *bft.Engine, seed config.Seed, localID string) (*dkg.Ceremony, error) {
	members := make([]dkg.Member, 0, len(seed.Managers))
	ids := make([]string, 0, len(seed.Managers))
	for _, manager := range seed.Managers {
		peerID, err := peer.Decode(manager.PeerID)
		if err != nil {
			return nil, fmt.Errorf("invalid committee peer id for %s: %w", manager.ID, err)
		}
		members = append(members, dkg.Member{ID: manager.ID, PeerID: peerID})
		ids = append(ids, manager.ID)
	}
	return dkg.New(node, dkg.Config{
		CeremonyID: dkg.CeremonyID(seed.NetworkID, engine.CommitteeEpoch()+1, ids),
		Threshold:  bft.QuorumSize, Members: members, LocalID: localID,
	})
}

// runDKGRotation runs the Pedersen ceremony, persists this member's share and
// then lets the next-height leader commit the rotation to the joint group key.
func runDKGRotation(ctx context.Context, ceremony *dkg.Ceremony, engine *bft.Engine, mesh *manager.CommitteeMesh, localID, dataDir string) error {
	if ceremony == nil {
		return fmt.Errorf("dkg ceremony was not initialised")
	}
	epoch := engine.CommitteeEpoch() + 1
	result, err := ceremony.Run(ctx)
	if err != nil {
		return fmt.Errorf("dkg ceremony: %w", err)
	}
	if err := dkg.SaveShare(dataDir, epoch, localID, bft.QuorumSize, bft.CommitteeSize, result); err != nil {
		return fmt.Errorf("persist dkg share: %w", err)
	}
	ceremony.MarkSaved()
	if err := ceremony.WaitAll(ctx); err != nil {
		return err
	}
	if engine.Leader(engine.Height()+1, 0).ID != localID {
		return nil
	}
	transition := model.StateTransition{
		Type:            bft.TransitionRotateCommittee,
		CommitteeConfig: &model.CommitteeConfig{GroupPublicKey: append([]byte(nil), result.GroupPublicKey...)},
	}
	if _, err := mesh.Submit(transition); err != nil {
		return fmt.Errorf("submit committee rotation: %w", err)
	}
	return nil
}

// runSeedRotation commits a deterministic seed-derived key rotation. It is the
// non-DKG path used to exercise rotation in development.
func runSeedRotation(ctx context.Context, engine *bft.Engine, mesh *manager.CommitteeMesh, localID string) error {
	if engine.Leader(engine.Height()+1, 0).ID != localID {
		return nil
	}
	if _, err := mesh.Submit(model.StateTransition{Type: bft.TransitionRotateCommittee}); err != nil {
		return fmt.Errorf("submit committee rotation: %w", err)
	}
	return nil
}

func runStatus(ctx context.Context, node *p2p.Node) error {
	encoded, err := json.MarshalIndent(map[string]any{
		"peerID":    node.Host.ID().String(),
		"addresses": node.Addresses(),
	}, "", "  ")
	if err != nil {
		return err
	}
	fmt.Printf("%s\n", encoded)
	<-ctx.Done()
	return nil
}
