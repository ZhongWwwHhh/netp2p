package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/netp2p/netp2p/internal/bft"
	"github.com/netp2p/netp2p/internal/config"
	"github.com/netp2p/netp2p/internal/dkg"
	"github.com/netp2p/netp2p/internal/manager"
	"github.com/netp2p/netp2p/internal/model"
	"github.com/netp2p/netp2p/internal/p2p"
	"github.com/netp2p/netp2p/internal/store"
	"github.com/netp2p/netp2p/internal/version"
)

func runManagerJoin(args []string) error {
	flags := flag.NewFlagSet("manager join", flag.ContinueOnError)
	bundlePath := flags.String("bundle", "", "candidate manager join bundle JSON")
	dataDir := flags.String("data-dir", "", "manager data directory")
	webListen := flags.String("web-listen", "127.0.0.1:18080", "manager web listen address after activation")
	metricsListen := flags.String("metrics-listen", "0.0.0.0:9101", "manager metrics listen address after activation")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if *bundlePath == "" || *dataDir == "" {
		return fmt.Errorf("--bundle and --data-dir are required")
	}
	bundle, err := config.LoadManagerJoinBundle(*bundlePath)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(*dataDir, 0o700); err != nil {
		return fmt.Errorf("create manager data directory: %w", err)
	}

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	node, err := p2p.New(ctx, p2p.Config{
		DataDir: *dataDir, Listen: []string{bundle.QuicListen},
		WebRTCListen: []string{bundle.ListenAddr}, Identity: bundle.IdentityKey(),
		EnableRelayService: true,
	})
	if err != nil {
		return err
	}
	bootstrap, err := connectTrustManagers(ctx, node, bundle.TrustManagers)
	if err != nil {
		_ = node.Close()
		return err
	}
	member, err := bundle.PublicCommitteeMember()
	if err != nil {
		_ = node.Close()
		return err
	}
	request := model.ManagerJoinRequest{
		ID: bundle.ManagerID, ManagerID: bundle.ManagerID, PeerID: member.PeerID,
		Address: member.Address, ListenAddr: member.ListenAddr, PublicKey: member.PublicKey,
		RequestedAt: time.Now().UTC().Format(time.RFC3339Nano), Status: model.ManagerJoinPending,
	}
	if _, err := manager.SubmitAdmin(ctx, node, bootstrap, bundle.JoinToken, model.StateTransition{
		Type: bft.TransitionSubmitManagerJoin, ManagerJoin: &request,
	}); err != nil {
		_ = node.Close()
		return fmt.Errorf("submit manager join request: %w", err)
	}
	fmt.Printf("Manager %s submitted join request; waiting for administrator approval.\n", bundle.ManagerID)

	approval, err := waitForManagerJoinApproval(ctx, node, bootstrap, bundle)
	if err != nil {
		_ = node.Close()
		return err
	}
	if err := runCandidateDKG(ctx, node, bundle, approval, *dataDir); err != nil {
		_ = node.Close()
		return err
	}
	activation, err := waitForManagerActivation(ctx, node, bootstrap, bundle)
	if err != nil {
		_ = node.Close()
		return err
	}
	manifestPath, managerBundlePath, err := persistActivatedManager(*dataDir, bundle, activation)
	if err != nil {
		_ = node.Close()
		return err
	}
	if err := node.Close(); err != nil {
		return fmt.Errorf("close candidate transport: %w", err)
	}
	fmt.Printf("Manager %s activated at height %d; starting manager role.\n", bundle.ManagerID, activation.Height)
	return runManager(ctx, managerOptions{
		dataDir: *dataDir, manifestPath: manifestPath, managerBundlePath: managerBundlePath,
		listenAddr: bundle.QuicListen, webListen: *webListen, metricsListen: *metricsListen,
		forwarding: true, runDKG: true,
		alerting: alertOptions{interval: 15 * time.Second, dropCount: 100, dropRatePercent: 5},
	})
}

func connectTrustManagers(ctx context.Context, node *p2p.Node, members []model.CommitteeMember) (peer.ID, error) {
	var lastErr error
	var bootstrap peer.ID
	for _, member := range members {
		info, err := peer.AddrInfoFromString(member.Address + "/p2p/" + member.PeerID)
		if err != nil {
			lastErr = err
			continue
		}
		connectContext, cancel := context.WithTimeout(ctx, 10*time.Second)
		err = node.Host.Connect(connectContext, *info)
		cancel()
		if err != nil {
			lastErr = err
			continue
		}
		if bootstrap == "" {
			bootstrap = info.ID
		}
	}
	if bootstrap != "" {
		return bootstrap, nil
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("no trust managers")
	}
	return "", lastErr
}

func queryJoinSnapshot(
	ctx context.Context, node *p2p.Node, bootstrap peer.ID, token, query string,
) (model.SignedSnapshot, error) {
	data, err := manager.QueryAdmin(ctx, node, bootstrap, token, query)
	if err != nil {
		return model.SignedSnapshot{}, err
	}
	var snapshot model.SignedSnapshot
	if err := json.Unmarshal(data, &snapshot); err != nil {
		return model.SignedSnapshot{}, fmt.Errorf("decode manager snapshot: %w", err)
	}
	return snapshot, nil
}

func findManagerJoin(snapshot model.SignedSnapshot, managerID string) *model.ManagerJoinRequest {
	for index := range snapshot.State.ManagerJoins {
		if snapshot.State.ManagerJoins[index].ManagerID == managerID {
			return &snapshot.State.ManagerJoins[index]
		}
	}
	return nil
}

func waitForManagerJoinApproval(
	ctx context.Context, node *p2p.Node, bootstrap peer.ID, bundle config.ManagerJoinBundle,
) (model.SignedSnapshot, error) {
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		snapshot, err := queryJoinSnapshot(ctx, node, bootstrap, bundle.JoinToken, "snapshot")
		if err == nil {
			if request := findManagerJoin(snapshot, bundle.ManagerID); request != nil {
				switch request.Status {
				case model.ManagerJoinApproved:
					return snapshot, nil
				case model.ManagerJoinRejected:
					return model.SignedSnapshot{}, fmt.Errorf("administrator rejected manager %s", bundle.ManagerID)
				}
			}
		}
		select {
		case <-ctx.Done():
			return model.SignedSnapshot{}, ctx.Err()
		case <-ticker.C:
		}
	}
}

func runCandidateDKG(
	ctx context.Context, node *p2p.Node, bundle config.ManagerJoinBundle,
	approval model.SignedSnapshot, dataDir string,
) error {
	target, changed := targetCommitteeFromState(approval.State, approval.Committee)
	if !changed {
		return fmt.Errorf("approved manager join did not change the committee")
	}
	params, err := model.CommitteeParamsForSize(len(target))
	if err != nil {
		return err
	}
	epoch := approval.State.CommitteeConfig.CommitteeEpoch + 1
	ceremony, err := newDKGCeremonyForCommittee(
		node, target, bundle.NetworkID, epoch, params.QuorumSize, bundle.ManagerID,
	)
	if err != nil {
		return err
	}
	node.Handle(p2p.DKGProtocol, ceremony.Handle)
	result, err := ceremony.Run(ctx)
	if err != nil {
		return fmt.Errorf("candidate dkg ceremony: %w", err)
	}
	if err := dkg.SaveShare(dataDir, epoch, bundle.ManagerID, params.QuorumSize, params.Size, result); err != nil {
		return fmt.Errorf("persist candidate dkg share: %w", err)
	}
	ceremony.MarkSaved()
	if err := ceremony.WaitAll(ctx); err != nil {
		return fmt.Errorf("candidate dkg readiness: %w", err)
	}
	return nil
}

func waitForManagerActivation(
	ctx context.Context, node *p2p.Node, bootstrap peer.ID, bundle config.ManagerJoinBundle,
) (model.SignedSnapshot, error) {
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		snapshot, err := queryJoinSnapshot(ctx, node, bootstrap, bundle.JoinToken, "manager-snapshot")
		if err == nil {
			request := findManagerJoin(snapshot, bundle.ManagerID)
			if request != nil && request.Status == model.ManagerJoinActivated &&
				snapshot.Transition.Type == bft.TransitionActivateCommittee {
				return snapshot, nil
			}
		}
		select {
		case <-ctx.Done():
			return model.SignedSnapshot{}, ctx.Err()
		case <-ticker.C:
		}
	}
}

func persistActivatedManager(
	dataDir string, bundle config.ManagerJoinBundle, activation model.SignedSnapshot,
) (string, string, error) {
	params, err := model.CommitteeParamsFromConfig(activation.State.CommitteeConfig)
	if err != nil {
		return "", "", err
	}
	if len(activation.Transition.Committee) != params.Size {
		return "", "", fmt.Errorf("activation committee has %d members, want %d", len(activation.Transition.Committee), params.Size)
	}
	manifest := config.NetworkManifest{
		Version: config.NetworkManifestVersion, NetworkID: activation.State.NetworkID,
		OverlayCIDR: activation.State.OverlayCIDR, ProtocolVersion: version.ProtocolVersion,
		CommitteeParams: params, Managers: activation.Transition.Committee,
		Groups: activation.State.Groups, Policies: activation.State.Policies,
		Routes: activation.State.Routes, Budgets: activation.State.Budgets,
		Nameservers: activation.State.Nameservers, Zones: activation.State.Zones,
		DNSSettings: activation.State.DNSSettings, Settings: activation.State.Settings,
		OIDC: bundle.OIDC, NextIPOffset: activation.State.NextIPOffset,
	}
	if err := manifest.Validate(); err != nil {
		return "", "", fmt.Errorf("validate activated manifest: %w", err)
	}
	managerBundle := config.ManagerBundle{
		Version: config.ManagerBundleVersion, NetworkID: bundle.NetworkID,
		ManagerID: bundle.ManagerID, PrivateKey: bundle.PrivateKey,
		AdminToken: bundle.AdminToken, SessionSecret: bundle.SessionSecret,
	}
	if err := managerBundle.Validate(manifest); err != nil {
		return "", "", fmt.Errorf("validate activated manager bundle: %w", err)
	}
	manifestPath := filepath.Join(dataDir, "network.json")
	managerBundlePath := filepath.Join(dataDir, "manager.json")
	write := func(path string, value any, mode os.FileMode) error {
		encoded, err := json.MarshalIndent(value, "", "  ")
		if err != nil {
			return err
		}
		return os.WriteFile(path, append(encoded, '\n'), mode)
	}
	if err := write(manifestPath, manifest, 0o600); err != nil {
		return "", "", fmt.Errorf("write activated manifest: %w", err)
	}
	if err := write(managerBundlePath, managerBundle, 0o600); err != nil {
		return "", "", fmt.Errorf("write activated manager bundle: %w", err)
	}
	stateStore, err := store.Open(filepath.Join(dataDir, "manager.sqlite"))
	if err != nil {
		return "", "", err
	}
	if err := stateStore.RecordCommit(activation); err != nil {
		_ = stateStore.Close()
		return "", "", fmt.Errorf("record activated snapshot: %w", err)
	}
	if err := stateStore.Close(); err != nil {
		return "", "", err
	}
	return manifestPath, managerBundlePath, nil
}
