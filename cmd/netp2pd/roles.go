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

	"github.com/netp2p/netp2p/internal/bft"
	"github.com/netp2p/netp2p/internal/config"
	"github.com/netp2p/netp2p/internal/link"
	"github.com/netp2p/netp2p/internal/manager"
	"github.com/netp2p/netp2p/internal/metrics"
	"github.com/netp2p/netp2p/internal/model"
	"github.com/netp2p/netp2p/internal/oidc"
	"github.com/netp2p/netp2p/internal/p2p"
	"github.com/netp2p/netp2p/internal/web"
)

func runManager(ctx context.Context, dataDir, configPath, listenAddr, webListen, metricsListen string, forwarding bool) error {
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
	mesh, err := manager.NewCommitteeMesh(node, engine, seed.Managers)
	if err != nil {
		return err
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
	netManager := manager.New(node, engine, mesh, manager.Config{SSO: sso, Links: linkGossiper, Forwarding: forwarding, Metrics: collector})
	manager.RegisterAdminHandler(node, mesh, seed.AdminToken)
	netManager.EnableForwarding(ctx)
	go netManager.RunPresenceGossip(ctx)
	node.Handle(p2p.LinkGossipProtocol, linkGossiper.Handle)
	go linkGossiper.Run(ctx)
	go netManager.RunLinkProbe(ctx)
	go netManager.RunScheduler(ctx)
	go netManager.RunQuotaSettlement(ctx)

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
