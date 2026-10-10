package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/multiformats/go-multiaddr"
	"github.com/netp2p/netp2p/internal/client"
	"github.com/netp2p/netp2p/internal/config"
	"github.com/netp2p/netp2p/internal/dns"
	"github.com/netp2p/netp2p/internal/metrics"
	"github.com/netp2p/netp2p/internal/oidc"
	"github.com/netp2p/netp2p/internal/p2p"
	"github.com/netp2p/netp2p/internal/packet"
	"github.com/netp2p/netp2p/internal/protocol"
	"github.com/netp2p/netp2p/internal/runtimeconfig"
	"github.com/netp2p/netp2p/internal/tun"
)

type clientOptions struct {
	dataDir          string
	listenAddr       string
	managerAddr      string
	networkID        string
	setupKey         string
	packetListen     string
	statusFile       string
	hostname         string
	tunName          string
	tunMTU           int
	noTun            bool
	dnsListen        string
	dnsManage        bool
	noDNS            bool
	sso              bool
	ssoIssuer        string
	ssoClientID      string
	seedPath         string
	trustPath        string
	managerEndpoints []string
	posture          []string
	metricsListen    string
}

func runClient(ctx context.Context, options clientOptions) error {
	dataDir := options.dataDir
	collector, _, err := startClientMetrics(ctx, options)
	if err != nil {
		return err
	}
	p2pConfig := p2p.Config{DataDir: filepath.Join(dataDir, "client"), Listen: []string{options.listenAddr}}
	var seed *config.Seed
	if options.seedPath != "" {
		loaded, err := config.Load(options.seedPath)
		if err != nil {
			return fmt.Errorf("load seed for bootstrap managers: %w", err)
		}
		bootstrapManagers, err := loaded.BootstrapAddrInfos()
		if err != nil {
			return err
		}
		p2pConfig.StaticRelays = bootstrapManagers
		seed = &loaded
	}
	if len(options.managerEndpoints) > 0 {
		bootstrapManagers, err := managerAddrInfos(options.managerEndpoints)
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
	resolver, restoreDNS := startDNS(options, upstreams, tunDevice != nil, collector)
	if restoreDNS != nil {
		defer restoreDNS()
	}
	optionsList := []client.Option{client.WithStateDir(filepath.Join(dataDir, "client"))}
	if seed != nil {
		optionsList = append(optionsList, client.WithManagerFailover(seedManagerEndpoints(*seed)...))
	}
	if len(options.managerEndpoints) > 0 {
		optionsList = append(optionsList, client.WithManagerFailover(options.managerEndpoints...))
	}
	if options.hostname != "" {
		optionsList = append(optionsList, client.WithHostname(options.hostname))
	}
	if len(options.posture) > 0 {
		optionsList = append(optionsList, client.WithPosture(options.posture))
	}
	netClient, err := client.New(node, options.managerAddr, sink, optionsList...)
	if err != nil {
		return err
	}
	defer netClient.Close()
	if resolver != nil {
		netClient.SetDNSResolver(resolver)
		netClient.SetDNSUpstreams(upstreams)
	}
	go runClientMetrics(ctx, netClient, collector)
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
		tunDevice.SetUnderlayHosts(underlayHosts(options))
		netClient.EnableExitForwarding(netClient.Snapshot().State.OverlayCIDR, nil)
		netClient.ReconcileRoutes()
	} else if netClient.Self().IsExitNode {
		log.Printf("this peer is a certified exit node but the userspace packet endpoint cannot forward kernel traffic; exit/subnet routing is disabled")
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
		"state": string(netClient.State()), "manager": netClient.ManagerStatus().ActiveManager.String(),
		"nextAction": netClient.NextAction(),
	})
}

func seedManagerEndpoints(seed config.Seed) []string {
	addresses := make([]string, 0, len(seed.Managers))
	seen := make(map[string]struct{}, len(seed.Managers))
	for _, manager := range seed.Managers {
		if manager.Address == "" || manager.PeerID == "" {
			continue
		}
		address := manager.Address + "/p2p/" + manager.PeerID
		if _, duplicate := seen[address]; duplicate {
			continue
		}
		seen[address] = struct{}{}
		addresses = append(addresses, address)
	}
	return addresses
}

func trustManagerEndpoints(trust config.ClientTrust) []string {
	addresses := make([]string, 0, len(trust.Managers))
	seen := make(map[string]struct{}, len(trust.Managers))
	for _, manager := range trust.Managers {
		if manager.Address == "" || manager.PeerID == "" {
			continue
		}
		address := manager.Address + "/p2p/" + manager.PeerID
		if _, duplicate := seen[address]; duplicate {
			continue
		}
		seen[address] = struct{}{}
		addresses = append(addresses, address)
	}
	return addresses
}

func managerAddrInfos(addresses []string) ([]peer.AddrInfo, error) {
	result := make([]peer.AddrInfo, 0, len(addresses))
	seen := make(map[string]struct{}, len(addresses))
	for _, address := range addresses {
		info, err := peer.AddrInfoFromString(address)
		if err != nil {
			return nil, fmt.Errorf("invalid manager address %q: %w", address, err)
		}
		key := info.ID.String()
		if _, duplicate := seen[key]; duplicate {
			continue
		}
		seen[key] = struct{}{}
		result = append(result, *info)
	}
	return result, nil
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
func startDNS(options clientOptions, upstreams []string, kernelRouting bool, collector *metrics.Metrics) (*dns.Resolver, func()) {
	if options.noDNS {
		return nil, nil
	}
	resolver := dns.NewResolverWithMetrics(options.dnsListen, collector)
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

// clientMetricsListen is shared with semantic runtime-config validation so the
// daemon and CLI reject the same client metrics endpoints.
func clientMetricsListen(address string) (string, error) {
	return runtimeconfig.ClientMetricsListen(address)
}

// startClientMetrics exposes the client's local registry. A separate listener
// avoids exposing diagnostics through the authenticated manager API and avoids
// triggering host firewall prompts on Windows.
func startClientMetrics(ctx context.Context, options clientOptions) (*metrics.Metrics, string, error) {
	address, err := clientMetricsListen(options.metricsListen)
	if err != nil {
		return nil, "", err
	}
	listener, err := net.Listen("tcp", address)
	if err != nil {
		return nil, "", fmt.Errorf("listen for client metrics on %s: %w", address, err)
	}
	collector := metrics.New()
	server := &http.Server{Handler: collector.Handler(), ReadHeaderTimeout: 5 * time.Second}
	go func() {
		<-ctx.Done()
		shutdownContext, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = server.Shutdown(shutdownContext)
	}()
	go func() {
		if serveErr := server.Serve(listener); serveErr != nil && serveErr != http.ErrServerClosed {
			log.Printf("client metrics server stopped: %v", serveErr)
		}
	}()
	boundAddress := listener.Addr().String()
	log.Printf("client metrics available on http://%s/metrics", boundAddress)
	return collector, boundAddress, nil
}

func runClientMetrics(ctx context.Context, netClient *client.Client, collector *metrics.Metrics) {
	updateClientMetrics(netClient.DataPlaneStats(), collector)
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			updateClientMetrics(netClient.DataPlaneStats(), collector)
		}
	}
}

func updateClientMetrics(stats client.DataPlaneStats, collector *metrics.Metrics) {
	collector.ForwardQueueDepth.Set(float64(stats.OutboundQueueDepth))
}

func clientMode(tunDevice *tun.Device) string {
	if tunDevice != nil {
		return "tun"
	}
	return "userspace"
}

// underlayHosts lists the manager addresses that must keep using the physical
// default route while 0.0.0.0/0 is pointed at the overlay. It is a best-effort
// heuristic: only literal addresses and hostnames are returned, and the TUN
// device resolves the gateway itself.
func underlayHosts(options clientOptions) []string {
	hosts := make([]string, 0, 2)
	if options.managerAddr != "" {
		hosts = append(hosts, hostFromMultiaddr(options.managerAddr)...)
	}
	if options.seedPath != "" {
		if seed, err := config.Load(options.seedPath); err == nil {
			for _, manager := range seed.Managers {
				hosts = append(hosts, hostFromMultiaddr(manager.Address)...)
			}
		}
	}
	for _, endpoint := range options.managerEndpoints {
		hosts = append(hosts, hostFromMultiaddr(endpoint)...)
	}
	return dedupeStrings(hosts)
}

// hostFromMultiaddr extracts the /dns4, /dns6, /ip4 or /ip6 component of a
// multiaddr string. It is deliberately forgiving; unparseable input yields nil.
func hostFromMultiaddr(value string) []string {
	addr, err := multiaddr.NewMultiaddr(value)
	if err != nil {
		return nil
	}
	if host, err := addr.ValueForProtocol(multiaddr.P_DNS4); err == nil {
		return []string{host}
	}
	if host, err := addr.ValueForProtocol(multiaddr.P_DNS6); err == nil {
		return []string{host}
	}
	if host, err := addr.ValueForProtocol(multiaddr.P_IP4); err == nil {
		return []string{host}
	}
	if host, err := addr.ValueForProtocol(multiaddr.P_IP6); err == nil {
		return []string{host}
	}
	return nil
}

func dedupeStrings(values []string) []string {
	seen := make(map[string]struct{}, len(values))
	result := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		if _, exists := seen[value]; exists {
			continue
		}
		seen[value] = struct{}{}
		result = append(result, value)
	}
	return result
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
