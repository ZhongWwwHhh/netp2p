package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"time"

	"github.com/netp2p/netp2p/internal/client"
	"github.com/netp2p/netp2p/internal/config"
	"github.com/netp2p/netp2p/internal/dns"
	"github.com/netp2p/netp2p/internal/oidc"
	"github.com/netp2p/netp2p/internal/p2p"
	"github.com/netp2p/netp2p/internal/packet"
	"github.com/netp2p/netp2p/internal/protocol"
	"github.com/netp2p/netp2p/internal/tun"
)

type clientOptions struct {
	dataDir      string
	listenAddr   string
	managerAddr  string
	networkID    string
	setupKey     string
	packetListen string
	statusFile   string
	tunName      string
	tunMTU       int
	noTun        bool
	dnsListen    string
	dnsManage    bool
	noDNS        bool
	sso          bool
	ssoIssuer    string
	ssoClientID  string
	seedPath     string
}

func runClient(ctx context.Context, options clientOptions) error {
	dataDir := options.dataDir
	p2pConfig := p2p.Config{DataDir: filepath.Join(dataDir, "client"), Listen: []string{options.listenAddr}}
	if options.seedPath != "" {
		seed, err := config.Load(options.seedPath)
		if err != nil {
			return fmt.Errorf("load seed for bootstrap managers: %w", err)
		}
		bootstrapManagers, err := seed.BootstrapAddrInfos()
		if err != nil {
			return err
		}
		p2pConfig.StaticRelays = bootstrapManagers
	}
	node, err := p2p.New(ctx, p2pConfig)
	if err != nil {
		return err
	}
	defer node.Close()

	// Capture the host resolver configuration before taking it over, so the
	// resolver can still forward queries the overlay does not own.
	upstreams := dns.HostUpstreams(dns.DefaultResolvConf)
	sink, tunDevice, err := openClientSink(options)
	if err != nil {
		return err
	}
	defer sink.Close()
	resolver, restoreDNS := startDNS(options, upstreams, tunDevice != nil)
	if restoreDNS != nil {
		defer restoreDNS()
	}
	netClient, err := client.New(node, options.managerAddr, sink,
		client.WithStateDir(filepath.Join(dataDir, "client")))
	if err != nil {
		return err
	}
	defer netClient.Close()
	if resolver != nil {
		netClient.SetDNSResolver(resolver)
		netClient.SetDNSUpstreams(upstreams)
	}
	if err := login(ctx, netClient, options); err != nil {
		return err
	}
	if tunDevice != nil {
		overlayIP := netClient.Self().OverlayIP
		if overlayIP == "" {
			return fmt.Errorf("certified state did not assign an overlay address")
		}
		if err := tunDevice.Configure(overlayIP, options.tunMTU); err != nil {
			return fmt.Errorf("configure tun device %s: %w", tunDevice.Name(), err)
		}
		log.Printf("tun device %s up with overlay address %s", tunDevice.Name(), overlayIP)
		// The login snapshot was applied before the interface existed, so push
		// the allowed routes now.
		netClient.ReconcileRoutes()
	}
	go netClient.SyncLoop(ctx)
	go netClient.RunQuotaReporting(ctx)
	go func() {
		if err := netClient.ServePackets(ctx); err != nil && ctx.Err() == nil {
			log.Printf("packet endpoint stopped: %v", err)
		}
	}()
	status, err := clientStatus(node, netClient, options, tunDevice)
	if err != nil {
		return err
	}
	fmt.Printf("%s\n", status)
	if options.statusFile != "" {
		if err := os.WriteFile(options.statusFile, status, 0o644); err != nil {
			return fmt.Errorf("write status file: %w", err)
		}
		go runStatusWriter(ctx, node, netClient, options, tunDevice)
	}
	<-ctx.Done()
	return nil
}

// clientStatus renders the operator-facing status file. Certified assignments
// are included so tests and operators can see which path the client is using
// without opening the console.
func clientStatus(node *p2p.Node, netClient *client.Client, options clientOptions, tunDevice *tun.Device) ([]byte, error) {
	snapshot := netClient.Snapshot()
	paths := make([]map[string]any, 0, len(snapshot.State.Assignments))
	for _, assignment := range snapshot.State.Assignments {
		if assignment.SourcePeerID != netClient.Self().PeerID {
			continue
		}
		paths = append(paths, map[string]any{
			"destination": assignment.DestinationPeerID,
			"kind":        assignment.Primary.Kind,
			"hops":        assignment.Primary.ManagerHops,
			"rttMs":       assignment.Primary.RTTMilliseconds,
			"lossPct":     assignment.Primary.LossPercent,
		})
	}
	return json.Marshal(map[string]any{
		"peerID": node.Host.ID().String(), "overlayIP": netClient.Self().OverlayIP,
		"height": netClient.SnapshotHeight(), "packetListen": options.packetListen,
		"mode": clientMode(tunDevice), "assignments": paths,
	})
}

func runStatusWriter(ctx context.Context, node *p2p.Node, netClient *client.Client, options clientOptions, tunDevice *tun.Device) {
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			status, err := clientStatus(node, netClient, options, tunDevice)
			if err != nil {
				continue
			}
			_ = os.WriteFile(options.statusFile, status, 0o644)
		}
	}
}

// startDNS brings up the local resolver and optionally points the host at it.
// Failures are warnings: the overlay keeps working without DNS takeover.
func startDNS(options clientOptions, upstreams []string, kernelRouting bool) (*dns.Resolver, func()) {
	if options.noDNS {
		return nil, nil
	}
	resolver := dns.NewResolver(options.dnsListen)
	if err := resolver.ListenAndServe(); err != nil {
		log.Printf("dns resolver disabled: %v", err)
		return nil, nil
	}
	// Seed the upstreams before login: the manager address is usually a dns4
	// name, so taking over resolv.conf before the resolver can forward would
	// deadlock the very first dial.
	resolver.Update(dns.Config{Upstreams: upstreams})
	var resolvConf *dns.ResolvConf
	// Taking over resolv.conf only makes sense when the host network stack
	// actually flows through the overlay, which is what TUN provides.
	if options.dnsManage && kernelRouting {
		takeover, err := dns.Takeover(dns.DefaultResolvConf, resolver.ListenAddr(), upstreams)
		if err != nil {
			log.Printf("dns resolv.conf takeover skipped: %v", err)
		} else {
			resolvConf = takeover
			log.Printf("dns resolver on %s; original resolv.conf saved to %s", resolver.ListenAddr(), takeover.BackupPath())
		}
	}
	return resolver, func() {
		if resolvConf != nil {
			if err := resolvConf.Restore(); err != nil {
				log.Printf("restore resolv.conf: %v", err)
			}
		}
		if err := resolver.Shutdown(); err != nil {
			log.Printf("stop dns resolver: %v", err)
		}
	}
}

func clientMode(tunDevice *tun.Device) string {
	if tunDevice != nil {
		return "tun"
	}
	return "userspace"
}

// openClientSink prefers a TUN device so the host network stack routes real
// traffic into the overlay. Environments without CAP_NET_ADMIN or /dev/net/tun
// fall back to the userspace UDP endpoint rather than failing to start, which
// keeps unprivileged tests and containers working.
func openClientSink(options clientOptions) (packet.PacketSink, *tun.Device, error) {
	if !options.noTun {
		device, err := tun.Open(options.tunName, nil)
		if err == nil {
			return device, device, nil
		}
		log.Printf("tun unavailable (%v); falling back to the userspace packet endpoint", err)
	}
	sink, err := packet.NewUDPPacketSink(options.packetListen)
	if err != nil {
		return nil, nil, fmt.Errorf("open userspace packet endpoint: %w", err)
	}
	return sink, nil, nil
}

// login authenticates to the manager, tolerating managers that are still
// certifying genesis. With SSO it runs the device flow once and re-runs it when
// the certified login lifetime has expired.
func login(ctx context.Context, netClient *client.Client, options clientOptions) error {
	deadline := time.Now().Add(120 * time.Second)
	var token string
	var lastErr error
	for time.Now().Before(deadline) {
		if options.sso && token == "" {
			fresh, err := obtainSSOToken(ctx, options)
			if err != nil {
				return fmt.Errorf("sso device flow: %w", err)
			}
			token = fresh
		}
		lastErr = netClient.Login(ctx, options.networkID, options.setupKey, token)
		if lastErr == nil {
			return nil
		}
		var loginErr *client.LoginError
		if errors.As(lastErr, &loginErr) && loginErr.Code == protocol.CodeLoginExpired && options.sso {
			log.Printf("certified login expired; re-authenticating with the identity provider")
			token = ""
			continue
		}
		log.Printf("login retry: %v", lastErr)
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(time.Second):
		}
	}
	return fmt.Errorf("login: %w", lastErr)
}

func obtainSSOToken(ctx context.Context, options clientOptions) (string, error) {
	if options.ssoIssuer == "" || options.ssoClientID == "" {
		return "", fmt.Errorf("--sso-issuer and --sso-client-id are required with --sso")
	}
	flow, err := oidc.NewDeviceFlow(ctx, oidc.Config{Issuer: options.ssoIssuer, ClientID: options.ssoClientID})
	if err != nil {
		return "", err
	}
	return flow.IDToken(ctx)
}
