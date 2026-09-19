package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/netp2p/netp2p/internal/bft"
	"github.com/netp2p/netp2p/internal/config"
	"github.com/netp2p/netp2p/internal/manager"
	"github.com/netp2p/netp2p/internal/model"
	"github.com/netp2p/netp2p/internal/oidc"
	"github.com/netp2p/netp2p/internal/p2p"
	"github.com/netp2p/netp2p/internal/web"
)

func runManager(ctx context.Context, dataDir, configPath, listenAddr, webListen string) error {
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
	netManager := manager.New(node, engine, mesh, manager.Config{SSO: sso})
	manager.RegisterAdminHandler(node, mesh, seed.AdminToken)
	go netManager.RunPresenceGossip(ctx)

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
