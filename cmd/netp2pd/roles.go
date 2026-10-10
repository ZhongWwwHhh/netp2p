package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"time"

	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
	hostcrypto "github.com/libp2p/go-libp2p/core/crypto"
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
	"github.com/netp2p/netp2p/internal/store"
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

type managerOptions struct {
	dataDir           string
	configPath        string
	manifestPath      string
	managerBundlePath string
	listenAddr        string
	webListen         string
	metricsListen     string
	forwarding        bool
	runDKG            bool
	rotateKeys        bool
	alerting          alertOptions
}

func runManager(ctx context.Context, options managerOptions) error {
	production := options.manifestPath != "" || options.managerBundlePath != ""
	if production && options.configPath != "" {
		return fmt.Errorf("legacy config cannot be combined with manifest and manager bundle")
	}
	if production && options.rotateKeys {
		return fmt.Errorf("production committee rotation must use DKG")
	}
	if production && !options.runDKG {
		return fmt.Errorf("DKG is required for production manager startup")
	}

	var manifest config.NetworkManifest
	var bundle config.ManagerBundle
	var seed config.Seed
	var members []model.CommitteeMember
	var local model.CommitteeMember
	var adminToken string
	var sessionSecret string
	var oidcConfig oidc.Config
	if production {
		loadedManifest, err := config.LoadNetworkManifest(options.manifestPath)
		if err != nil {
			return err
		}
		loadedBundle, err := config.LoadManagerBundle(options.managerBundlePath, loadedManifest)
		if err != nil {
			return err
		}
		manifest, bundle = loadedManifest, loadedBundle
		members = manifest.Managers
		local = members[0]
		for _, candidate := range members {
			if candidate.ID == bundle.ManagerID {
				local = candidate
				break
			}
		}
		adminToken = bundle.AdminToken
		sessionSecret = bundle.SessionSecret
		oidcConfig = manifest.OIDC
	} else {
		if options.configPath == "" {
			return fmt.Errorf("manager config is required")
		}
		loadedSeed, err := config.Load(options.configPath)
		if err != nil {
			return err
		}
		if !loadedSeed.Development {
			return fmt.Errorf("legacy manager seed is not an explicit development fixture")
		}
		seed = loadedSeed
		members = seed.Managers
		localIndex := -1
		if managerID := os.Getenv("NETP2P_MANAGER_ID"); managerID != "" {
			for index, candidate := range members {
				if candidate.ID == managerID {
					localIndex = index
					break
				}
			}
		} else {
			for index, candidate := range members {
				if candidate.Address == options.listenAddr {
					localIndex = index
					break
				}
			}
		}
		if localIndex < 0 {
			return fmt.Errorf("manager identity not found for address %q", options.listenAddr)
		}
		local = members[localIndex]
		adminToken = seed.AdminToken
		sessionSecret = seed.SessionSecret
		oidcConfig = seed.OIDC
	}
	if len(sessionSecret) < 32 {
		return fmt.Errorf("manager session secret must be at least 32 bytes")
	}

	stateStore, err := store.Open(filepath.Join(options.dataDir, "manager.sqlite"))
	if err != nil {
		return fmt.Errorf("open certified state store: %w", err)
	}
	defer stateStore.Close()
	hasLedger, err := stateStore.HasLedger()
	if err != nil {
		return fmt.Errorf("inspect certified ledger: %w", err)
	}
	latest, hasLatest, err := stateStore.LatestSnapshot()
	if err != nil {
		return fmt.Errorf("load latest certified snapshot: %w", err)
	}
	latestCertifiedAt := time.Time{}
	if hasLatest {
		latestCertifiedAt, _, err = stateStore.LatestCertifiedAt()
		if err != nil {
			return fmt.Errorf("load latest certified timestamp: %w", err)
		}
	}
	if hasLedger != hasLatest {
		return fmt.Errorf("certified ledger state is inconsistent")
	}

	var privateKey ed25519.PrivateKey
	webrtcListen := local.ListenAddr
	if webrtcListen == "" {
		webrtcListen = "/ip4/0.0.0.0/udp/0/webrtc-direct"
	}
	p2pConfig := p2p.Config{
		DataDir: options.dataDir, Listen: []string{options.listenAddr},
		WebRTCListen: []string{webrtcListen}, EnableRelayService: options.forwarding,
	}
	if production {
		privateKey, err = stdEd25519PrivateKey(bundle.IdentityKey())
		if err != nil {
			return err
		}
		p2pConfig.Identity = bundle.IdentityKey()
	} else {
		privateKey = bft.SeededPrivateKey(local.KeySeed)
		p2pConfig.IdentitySeed = local.KeySeed
	}
	node, err := p2p.New(ctx, p2pConfig)
	if err != nil {
		return err
	}
	defer node.Close()

	memberIDs := make([]string, 0, len(members))
	for _, manager := range members {
		memberIDs = append(memberIDs, manager.ID)
	}
	var engine *bft.Engine
	var ceremony *dkg.Ceremony
	if production {
		params := manifest.CommitteeParams
		if params == (model.CommitteeParams{}) {
			params = model.DefaultCommitteeParams()
		}
		loadShare := func(epoch uint64) (*bls.KeySet, bool) {
			return dkg.LoadShare(options.dataDir, epoch, local.ID, memberIDs, params.QuorumSize)
		}
		if hasLedger {
			committeeConfig := latest.State.CommitteeConfig
			snapshotParams, err := model.CommitteeParamsFromConfig(committeeConfig)
			if err != nil {
				return fmt.Errorf("restore committee parameters: %w", err)
			}
			if snapshotParams != params {
				return fmt.Errorf("certified committee parameters %+v do not match manifest %+v", snapshotParams, params)
			}
			if committeeConfig.CommitteeEpoch == 0 || len(committeeConfig.GroupPublicKey) == 0 {
				return fmt.Errorf("certified ledger has no DKG committee key")
			}
			keys, ok := loadShare(committeeConfig.CommitteeEpoch)
			if !ok {
				return fmt.Errorf("local DKG share for epoch %d is missing", committeeConfig.CommitteeEpoch)
			}
			if !bytes.Equal(keys.GroupPublicKey, committeeConfig.GroupPublicKey) {
				return fmt.Errorf("local DKG group key does not match certified committee key")
			}
			engine, err = bft.NewEngineWithKeySet(
				manifest.NetworkState(committeeConfig), members, local.ID, privateKey, params,
				keys, committeeConfig.CommitteeEpoch,
			)
		} else {
			if !options.runDKG {
				return fmt.Errorf("DKG is required before genesis")
			}
			if err := connectCommittee(ctx, node, members, local.ID); err != nil {
				return fmt.Errorf("connect committee for DKG: %w", err)
			}
			ceremony, err = newDKGCeremonyForCommittee(node, members, manifest.NetworkID, 1, params.QuorumSize, local.ID)
			if err != nil {
				return err
			}
			node.Handle(p2p.DKGProtocol, ceremony.Handle)
			result, err := ceremony.Run(ctx)
			if err != nil {
				return fmt.Errorf("initial dkg ceremony: %w", err)
			}
			if err := dkg.SaveShare(options.dataDir, 1, local.ID, params.QuorumSize, params.Size, result); err != nil {
				return fmt.Errorf("persist initial dkg share: %w", err)
			}
			ceremony.MarkSaved()
			if err := ceremony.WaitAll(ctx); err != nil {
				return fmt.Errorf("initial dkg readiness barrier: %w", err)
			}
			keys, err := keySetFromDKG(members, local.ID, params, result)
			if err != nil {
				return err
			}
			committeeConfig := params.CommitteeConfig(1, result.GroupPublicKey)
			engine, err = bft.NewEngineWithKeySet(
				manifest.NetworkState(committeeConfig), members, local.ID, privateKey, params, keys, 1,
			)
		}
		if err != nil {
			return err
		}
		engine.SetDKGLoader(loadShare)
	} else {
		engine, err = bft.NewEngine(seed.NetworkState(), members, local.ID, privateKey)
		if err != nil {
			return err
		}
		engine.SetDKGLoader(func(epoch uint64) (*bls.KeySet, bool) {
			return dkg.LoadShare(options.dataDir, epoch, local.ID, memberIDs, engine.CommitteeParams().QuorumSize)
		})
	}

	// Restore before installing the write listener so a replay cannot be
	// recorded as a second decision at the same height.
	if err := stateStore.RestoreEngine(engine); err != nil {
		return fmt.Errorf("restore certified ledger: %w", err)
	}
	stateStore.InstallCommitListener(engine)
	mesh, err := manager.NewCommitteeMesh(node, engine, members)
	if err != nil {
		return err
	}
	if !production && options.runDKG {
		// Register the handler before the mesh connects so a peer's ceremony
		// stream never arrives at an unregistered protocol.
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
		log.Printf("committee connect incomplete: %v", err)
	}
	readyContext, cancel := context.WithTimeout(ctx, 10*time.Second)
	err = mesh.WaitReady(readyContext)
	cancel()
	if err != nil {
		log.Printf("committee readiness incomplete: %v", err)
	}
	degraded := !committeeQuorumAvailable(node, mesh, engine.CommitteeParams())
	if degraded {
		if !hasLedger {
			return fmt.Errorf("quorum unavailable and no certified ledger exists")
		}
		log.Printf("quorum unavailable; manager %s entering degraded read-only mode at height %d", local.ID, engine.Height())
	}
	// A restarting or lagging manager first tries to catch up from peers, even
	// when it has a restored ledger: its height can still be behind a quorum.
	// A no-op catch-up is normal when the committee is already current.
	if !degraded {
		catchContext, cancel := context.WithTimeout(ctx, 5*time.Second)
		_ = mesh.CatchUp(catchContext)
		cancel()
	}
	// If catch-up cannot advance a cold manager, its leader still tries genesis
	// so an all-manager cold start can certify the first state.
	if engine.Height() == 0 {
		if hasLedger {
			return fmt.Errorf("certified ledger exists but did not restore; refusing re-genesis")
		}
		if !degraded && engine.Leader(1, 0).ID == local.ID {
			if err := submitGenesis(ctx, mesh); err != nil {
				return err
			}
		}
	}
	if !degraded {
		if !production && options.runDKG {
			if err := runDKGRotation(ctx, ceremony, engine, mesh, local.ID, options.dataDir); err != nil {
				return err
			}
		} else if !production && options.rotateKeys {
			if err := runSeedRotation(ctx, engine, mesh, local.ID); err != nil {
				return err
			}
		}
	}
	// Register control handlers only after genesis so early client logins fail
	// fast and retry instead of racing the genesis transition.
	var sso *oidc.Verifier
	var bootstrapOIDC *web.BootstrapOIDC
	if oidcConfig.Enabled() {
		verifier, err := oidc.NewVerifier(ctx, oidcConfig)
		if err != nil {
			return fmt.Errorf("configure sso: %w", err)
		}
		sso = verifier
		authURL, tokenURL, _ := verifier.Endpoint()
		webClientID := oidcConfig.WebClientID
		if webClientID == "" {
			webClientID = oidcConfig.ClientID
		}
		bootstrapOIDC = &web.BootstrapOIDC{
			Issuer: oidcConfig.Issuer, ClientID: webClientID,
			Scopes:                oidcConfig.ScopesOrDefault(),
			AuthorizationEndpoint: authURL, TokenEndpoint: tokenURL,
		}
		log.Printf("sso enabled with issuer %s", oidcConfig.Issuer)
	}
	linkGossiper := link.NewGossiper(node, mesh.PeerIDs(), engine.LocalID(), 10*time.Second, 90*time.Second, 1000)
	var collector *metrics.Metrics
	if options.metricsListen != "" {
		collector = metrics.New()
		if err := startMetricsServer(ctx, options.metricsListen, collector.Handler()); err != nil {
			return err
		}
		mesh.SetMetrics(collector)
	}
	// Alerts are always evaluated; without a webhook they are written to the
	// structured log so an operator still sees a record of every transition.
	webhookSink, err := alerts.NewWebhookSink(options.alerting.webhook, options.alerting.webhookSecret, options.alerting.allowInsecureWebhook)
	if err != nil {
		return err
	}
	alerter := alerts.New(
		alerts.Config{
			Interval: options.alerting.interval,
			Thresholds: alerts.Thresholds{
				DropCount:       options.alerting.dropCount,
				DropRatePercent: options.alerting.dropRatePercent,
			},
		},
		alerts.LogSink{},
		webhookSink,
	)
	if options.alerting.webhook != "" {
		log.Printf("alerting to webhook %s every %s", options.alerting.webhook, options.alerting.interval)
	}
	netManager := manager.New(node, engine, mesh, manager.Config{
		SSO: sso, Links: linkGossiper, Forwarding: options.forwarding, Metrics: collector, Alerts: alerter,
		InitialCertifiedAt: latestCertifiedAt,
	})
	manager.RegisterAdminHandler(node, mesh, adminToken)
	netManager.EnableForwarding(ctx)
	go netManager.RunPresenceGossip(ctx)
	node.Handle(p2p.LinkGossipProtocol, linkGossiper.Handle)
	go linkGossiper.Run(ctx)
	go netManager.RunLinkProbe(ctx)
	if !degraded {
		go netManager.RunScheduler(ctx)
		go netManager.RunQuotaSettlement(ctx)
	}
	go netManager.RunAlerting(ctx)

	webServer, err := web.NewServer(node, netManager, web.Config{
		AdminToken: adminToken, SessionSecret: sessionSecret, AuthStore: stateStore,
		Authenticator: netManager, OIDC: bootstrapOIDC,
	})
	if err != nil {
		return fmt.Errorf("create web server: %w", err)
	}
	if err := webServer.StartInsecureBootstrap(options.webListen); err != nil {
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

// committeeQuorumAvailable counts live transport connections to other
// committee members. The local manager counts as one signer.
func committeeQuorumAvailable(node *p2p.Node, mesh *manager.CommitteeMesh, params model.CommitteeParams) bool {
	connected := 1
	for _, peerID := range mesh.PeerIDs() {
		if len(node.Host.Network().ConnsToPeer(peerID)) > 0 {
			connected++
		}
	}
	return connected >= params.QuorumSize
}

func stdEd25519PrivateKey(key hostcrypto.PrivKey) (ed25519.PrivateKey, error) {
	if key == nil {
		return nil, fmt.Errorf("manager private key is missing")
	}
	raw, err := key.Raw()
	if err != nil {
		return nil, fmt.Errorf("decode manager private key: %w", err)
	}
	if len(raw) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("manager private key is not Ed25519")
	}
	return ed25519.PrivateKey(raw), nil
}

func connectCommittee(ctx context.Context, node *p2p.Node, members []model.CommitteeMember, localID string) error {
	connectContext, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	for _, member := range members {
		if member.ID == localID {
			continue
		}
		info, err := peer.AddrInfoFromString(member.Address + "/p2p/" + member.PeerID)
		if err != nil {
			return fmt.Errorf("invalid address for manager %s: %w", member.ID, err)
		}
		if err := node.Host.Connect(connectContext, *info); err != nil {
			return fmt.Errorf("connect manager %s: %w", member.ID, err)
		}
	}
	return nil
}

func keySetFromDKG(
	members []model.CommitteeMember, localID string, params model.CommitteeParams, result *bls.DKGResult,
) (*bls.KeySet, error) {
	sorted := append([]model.CommitteeMember(nil), members...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].ID < sorted[j].ID })
	points := make([]fr.Element, len(sorted))
	localIndex := -1
	for index, member := range sorted {
		points[index] = bls.PointForIdentity(member.ID)
		if member.ID == localID {
			localIndex = index
		}
	}
	if localIndex < 0 {
		return nil, fmt.Errorf("local manager %q is not in the DKG committee", localID)
	}
	return result.KeySet(params.QuorumSize, params.Size, localIndex, points)
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
	return newDKGCeremonyForCommittee(
		node, seed.Managers, seed.NetworkID, engine.CommitteeEpoch()+1, engine.CommitteeParams().QuorumSize, localID,
	)
}

func newDKGCeremonyForCommittee(
	node *p2p.Node, members []model.CommitteeMember, networkID string, epoch uint64, threshold int, localID string,
) (*dkg.Ceremony, error) {
	dkgMembers := make([]dkg.Member, 0, len(members))
	ids := make([]string, 0, len(members))
	for _, manager := range members {
		peerID, err := peer.Decode(manager.PeerID)
		if err != nil {
			return nil, fmt.Errorf("invalid committee peer id for %s: %w", manager.ID, err)
		}
		dkgMembers = append(dkgMembers, dkg.Member{ID: manager.ID, PeerID: peerID})
		ids = append(ids, manager.ID)
	}
	return dkg.New(node, dkg.Config{
		CeremonyID: dkg.CeremonyID(networkID, epoch, ids),
		Threshold:  threshold, Members: dkgMembers, LocalID: localID,
	})
}

// runDKGRotation runs the Pedersen ceremony, persists this member's share and
// then lets the next-height leader commit the rotation to the joint group key.
func runDKGRotation(ctx context.Context, ceremony *dkg.Ceremony, engine *bft.Engine, mesh *manager.CommitteeMesh, localID, dataDir string) error {
	if ceremony == nil {
		return fmt.Errorf("dkg ceremony was not initialised")
	}
	epoch := engine.CommitteeEpoch() + 1
	params := engine.CommitteeParams()
	result, err := ceremony.Run(ctx)
	if err != nil {
		return fmt.Errorf("dkg ceremony: %w", err)
	}
	if err := dkg.SaveShare(dataDir, epoch, localID, params.QuorumSize, params.Size, result); err != nil {
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
