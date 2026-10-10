package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"time"

	"github.com/netp2p/netp2p/internal/config"
	"github.com/netp2p/netp2p/internal/p2p"
	"github.com/netp2p/netp2p/internal/runtimeconfig"
	"github.com/netp2p/netp2p/internal/tracing"
	"github.com/netp2p/netp2p/internal/version"
)

func main() {
	if len(os.Args) > 1 && os.Args[1] == "manager" {
		if err := runManagerCommand(os.Args[2:]); err != nil {
			log.Fatal(err)
		}
		return
	}
	role := flag.String("role", "", "node, manager, client, admin, doctor, seedgen or daemon")
	dataDir := flag.String("data-dir", "", "libp2p identity and node data directory")
	listen := flag.String("listen", "", "libp2p listen multiaddr")
	webListen := flag.String("web-listen", "", "manager browser bootstrap HTTP address")
	configPath := flag.String("config", "", "manager static JSON seed")
	manifestPath := flag.String("manifest", "", "public network manifest JSON")
	managerBundlePath := flag.String("manager-bundle", "", "per-manager private bundle JSON")
	seedPath := flag.String("seed", "", "path to a seed JSON for client relay/bootstrapping")
	trustPath := flag.String("trust", "", "path to a client trust JSON containing all manager endpoints")
	managerAddr := flag.String("manager", "", "manager libp2p multiaddr")
	setupKey := flag.String("setup-key", "", "client setup key")
	packetListen := flag.String("packet-listen", "", "client userspace UDP packet endpoint")
	tunName := flag.String("tun", "", "client TUN interface name")
	tunMTU := flag.Int("tun-mtu", 0, "client TUN interface MTU")
	noTun := flag.Bool("no-tun", false, "force the userspace UDP packet endpoint instead of TUN")
	dnsListen := flag.String("dns-listen", "", "client local DNS resolver address")
	dnsManage := flag.Bool("dns-manage-resolv-conf", false, "point /etc/resolv.conf at the overlay resolver")
	noDNS := flag.Bool("no-dns", false, "do not start the local DNS resolver")
	dnsDomain := flag.String("dns-domain", "", "overlay DNS domain used for Windows NRPT")
	noForward := flag.Bool("no-forward", false, "disable manager forwarding for certified overlay paths")
	dkgEnabled := flag.Bool("dkg", false, "run a Pedersen DKG ceremony at startup")
	rotateKeys := flag.Bool("rotate-committee-keys", false, "submit a rotate_committee_keys transition at startup")
	sso := flag.Bool("sso", false, "authenticate the client with an OIDC device flow")
	ssoIssuer := flag.String("sso-issuer", "", "OIDC issuer URL used with --sso")
	ssoClientID := flag.String("sso-client-id", "", "OIDC client id used with --sso")
	statusFile := flag.String("status-file", "", "write client status JSON to this path after login")
	hostname := flag.String("hostname", "", "stable client hostname advertised for DNS")
	posture := flag.String("posture", "", "comma-separated posture labels this client advertises at registration")
	networkID := flag.String("network", "", "network id")
	adminToken := flag.String("admin-token", "", "admin auth token from seed")
	adminAction := flag.String("action", "", "admin action")
	adminFile := flag.String("file", "", "JSON record file for upsert actions")
	adminTarget := flag.String("target", "", "target ID for remove actions")
	metricsListen := flag.String("metrics-listen", "", "manager or client Prometheus /metrics address")
	otelEndpoint := flag.String("otel-endpoint", "", "OTLP/HTTP trace endpoint")
	alertWebhook := flag.String("alert-webhook", "", "manager alert webhook URL")
	alertWebhookSecret := flag.String("alert-webhook-secret", "", "bearer token sent to the alert webhook")
	alertAllowInsecure := flag.Bool("allow-insecure-webhook", false, "permit an http alert webhook URL")
	alertInterval := flag.Duration("alert-interval", 0, "manager alert evaluation interval")
	alertDropCount := flag.Uint64("alert-drop-count", 0, "dropped frames in one interval that fire the forward_drops alert")
	alertDropRate := flag.Float64("alert-drop-rate-percent", 0, "dropped share of traffic that fires the forward_drops alert")
	ipcPath := flag.String("ipc-socket", "", "local IPC Unix socket or Windows named pipe")
	configFile := flag.String("config-file", "", "versioned YAML or JSON runtime config; command-line flags override it")
	showVersion := flag.Bool("version", false, "print the release version and exit")
	flag.Parse()
	if *showVersion {
		fmt.Printf("netp2pd %s (protocol %s, %s/%s)\n", version.Version, version.ProtocolVersion, runtime.GOOS, runtime.GOARCH)
		return
	}

	cfg, err := parseRuntimeConfig(*configFile)
	if err != nil {
		log.Fatal(err)
	}
	explicit := make(map[string]bool)
	flag.Visit(func(flagValue *flag.Flag) { explicit[flagValue.Name] = true })
	applyExplicitFlags(&cfg, explicit, flagValues{
		role: role, dataDir: dataDir, listen: listen, webListen: webListen, configPath: configPath,
		manifestPath: manifestPath, managerBundlePath: managerBundlePath,
		seedPath: seedPath, trustPath: trustPath, manager: managerAddr, setupKey: setupKey, packetListen: packetListen,
		tunName: tunName, tunMTU: tunMTU, noTun: noTun, dnsListen: dnsListen, dnsManage: dnsManage,
		noDNS: noDNS, dnsDomain: dnsDomain, noForward: noForward, dkg: dkgEnabled, rotateKeys: rotateKeys,
		sso: sso, ssoIssuer: ssoIssuer, ssoClientID: ssoClientID, statusFile: statusFile, hostname: hostname,
		posture: posture, networkID: networkID, adminToken: adminToken, adminAction: adminAction,
		adminFile: adminFile, adminTarget: adminTarget, metricsListen: metricsListen, otelEndpoint: otelEndpoint,
		alertWebhook: alertWebhook, alertWebhookSecret: alertWebhookSecret, alertAllowInsecure: alertAllowInsecure,
		alertInterval: alertInterval, alertDropCount: alertDropCount, alertDropRate: alertDropRate, ipcPath: ipcPath,
	})
	if err := validateRuntimeConfig(cfg); err != nil && !runtimeconfig.IsUnprovisionedClientError(err) {
		log.Fatal(err)
	}
	if cfg.Role == "client" && cfg.StatusFile == "" {
		cfg.StatusFile = filepath.Join(cfg.DataDir, "status.json")
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	shutdownTracing, err := tracing.Setup(ctx, cfg.Telemetry.OTLPEndpoint, version.ProtocolVersion)
	if err != nil {
		log.Fatalf("configure tracing: %v", err)
	}
	defer func() {
		shutdownContext, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = shutdownTracing(shutdownContext)
	}()

	var daemonState *ipcState
	if cfg.Role == "node" || cfg.Role == "manager" || cfg.Role == "client" || cfg.Role == "daemon" {
		state := newIPCState(ctx, cfg, *configFile, func(clientCtx context.Context, clientCfg runtimeConfig) error {
			options, err := clientOptionsFromRuntimeConfig(clientCfg)
			if err != nil {
				return err
			}
			return runClient(clientCtx, options)
		})
		daemonState = state
		listener, _, err := startIPC(ctx, state)
		if err != nil {
			log.Fatal(err)
		}
		defer listener.Close()
	}

	if cfg.Role == "client" && runtime.GOOS == "windows" && !cfg.NoDNS && cfg.DNSDomain != "" {
		if err := enableNRPT(cfg.DNSDomain, cfg.DNSListen); err != nil {
			log.Printf("configure NRPT: %v", err)
		} else {
			defer func() { _ = disableNRPT(cfg.DNSDomain) }()
		}
	}

	switch cfg.Role {
	case "manager":
		if err := runManager(ctx, managerOptions{
			dataDir: cfg.DataDir, configPath: cfg.ConfigPath, manifestPath: cfg.ManifestPath,
			managerBundlePath: cfg.ManagerBundlePath, listenAddr: cfg.Listen, webListen: cfg.WebListen,
			metricsListen: cfg.MetricsListen, forwarding: !cfg.NoForward, runDKG: cfg.DKG,
			rotateKeys: cfg.RotateCommitteeKey,
			alerting: alertOptions{
				webhook: cfg.Alert.Webhook, webhookSecret: cfg.Alert.WebhookSecret, interval: cfg.Alert.Interval,
				dropCount: cfg.Alert.DropCount, dropRatePercent: cfg.Alert.DropRatePercent,
				allowInsecureWebhook: cfg.Alert.AllowInsecureWebhook,
			},
		}); err != nil {
			log.Fatal(err)
		}
	case "client":
		if daemonState == nil {
			log.Fatal("client supervisor was not initialised")
		}
		if daemonState.unprovisioned() {
			log.Printf("client is not provisioned; waiting for netp2p login")
		} else if !daemonState.startClient() {
			log.Fatal("client supervisor failed to start")
		}
		<-ctx.Done()
		daemonState.stopClient()
	case "admin":
		if err := runAdmin(ctx, cfg.Manager, cfg.AdminToken, cfg.AdminAction, cfg.AdminFile, cfg.AdminTarget); err != nil {
			log.Fatal(err)
		}
	case "seedgen":
		if err := writeSeed(cfg.ConfigPath); err != nil {
			log.Fatal(err)
		}
	case "doctor":
		if err := runDoctor(ctx, doctorOptions{
			dataDir: cfg.DataDir, managerAddr: cfg.Manager, seedPath: cfg.ConfigPath,
			tunName: cfg.TunName, dnsListen: cfg.DNSListen,
		}); err != nil {
			log.Fatal(err)
		}
	case "daemon":
		<-ctx.Done()
		daemonState.stopClient()
	default:
		node, err := p2p.New(ctx, p2p.Config{DataDir: cfg.DataDir, Listen: []string{cfg.Listen}})
		if err != nil {
			log.Fatal(err)
		}
		defer node.Close()
		status, err := json.MarshalIndent(map[string]any{
			"peerID":    node.Host.ID().String(),
			"addresses": node.Addresses(),
			"protocols": []string{
				string(p2p.LoginProtocol), string(p2p.SyncProtocol), string(p2p.StateUpdateProtocol),
				string(p2p.ProbeProtocol), string(p2p.FrameProtocol), string(p2p.QuotaProtocol),
			},
		}, "", "  ")
		if err != nil {
			log.Fatal(err)
		}
		fmt.Printf("%s\n", status)
		<-ctx.Done()
	}
}

func clientOptionsFromRuntimeConfig(cfg runtimeConfig) (clientOptions, error) {
	setupKey := cfg.SetupKey
	if setupKey == "" && cfg.SetupKeyFile != "" {
		raw, err := os.ReadFile(cfg.SetupKeyFile)
		if err != nil {
			return clientOptions{}, fmt.Errorf("read setup key file: %w", err)
		}
		setupKey = strings.TrimSpace(string(raw))
		if setupKey == "" {
			return clientOptions{}, fmt.Errorf("setup key file %s is empty", cfg.SetupKeyFile)
		}
	}
	metricsListen := cfg.MetricsListen
	managerAddr := cfg.Manager
	managerEndpoints := make([]string, 0)
	if cfg.TrustPath != "" {
		trust, err := config.LoadClientTrust(cfg.TrustPath)
		if err != nil {
			return clientOptions{}, fmt.Errorf("load client trust: %w", err)
		}
		if cfg.NetworkID != trust.NetworkID {
			return clientOptions{}, fmt.Errorf("runtime network %q does not match trust network %q", cfg.NetworkID, trust.NetworkID)
		}
		managerEndpoints = trustManagerEndpoints(trust)
		if len(managerEndpoints) == 0 {
			return clientOptions{}, fmt.Errorf("client trust %s has no manager endpoints", cfg.TrustPath)
		}
		if managerAddr == "" {
			managerAddr = managerEndpoints[0]
		} else if !containsString(managerEndpoints, managerAddr) {
			return clientOptions{}, fmt.Errorf("manager %q is not in client trust %s", managerAddr, cfg.TrustPath)
		}
	}
	return clientOptions{
		dataDir: cfg.DataDir, listenAddr: cfg.Listen, managerAddr: managerAddr,
		networkID: cfg.NetworkID, setupKey: setupKey, packetListen: cfg.PacketListen,
		statusFile: cfg.StatusFile, hostname: cfg.Hostname, tunName: cfg.TunName, tunMTU: cfg.TunMTU, noTun: cfg.NoTun,
		posture: cfg.Posture, dnsListen: cfg.DNSListen, dnsManage: cfg.DNSManageResolvConf, noDNS: cfg.NoDNS,
		sso: cfg.SSO, ssoIssuer: cfg.SSOIssuer, ssoClientID: cfg.SSOClientID, seedPath: cfg.SeedPath,
		trustPath: cfg.TrustPath, managerEndpoints: managerEndpoints, metricsListen: metricsListen,
	}, nil
}

func containsString(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}

type flagValues struct {
	role, dataDir, listen, webListen, configPath, manifestPath, managerBundlePath, seedPath, trustPath, manager, setupKey, packetListen *string
	tunName, dnsListen, dnsDomain, ssoIssuer, ssoClientID, statusFile, hostname, posture, networkID                                     *string
	adminToken, adminAction, adminFile, adminTarget, metricsListen, otelEndpoint                                                        *string
	alertWebhook, alertWebhookSecret, ipcPath                                                                                           *string
	tunMTU                                                                                                                              *int
	alertDropCount                                                                                                                      *uint64
	alertDropRate                                                                                                                       *float64
	alertInterval                                                                                                                       *time.Duration
	noTun, dnsManage, noDNS, noForward, dkg, rotateKeys, sso                                                                            *bool
	alertAllowInsecure                                                                                                                  *bool
}

func applyExplicitFlags(cfg *runtimeConfig, explicit map[string]bool, values flagValues) {
	setString := func(name string, target *string, value string) {
		if explicit[name] {
			*target = value
		}
	}
	setBool := func(name string, target *bool, value bool) {
		if explicit[name] {
			*target = value
		}
	}
	setString("role", &cfg.Role, *values.role)
	setString("data-dir", &cfg.DataDir, *values.dataDir)
	setString("listen", &cfg.Listen, *values.listen)
	setString("web-listen", &cfg.WebListen, *values.webListen)
	setString("config", &cfg.ConfigPath, *values.configPath)
	setString("manifest", &cfg.ManifestPath, *values.manifestPath)
	setString("manager-bundle", &cfg.ManagerBundlePath, *values.managerBundlePath)
	setString("seed", &cfg.SeedPath, *values.seedPath)
	setString("trust", &cfg.TrustPath, *values.trustPath)
	setString("manager", &cfg.Manager, *values.manager)
	setString("setup-key", &cfg.SetupKey, *values.setupKey)
	setString("packet-listen", &cfg.PacketListen, *values.packetListen)
	setString("tun", &cfg.TunName, *values.tunName)
	if explicit["tun-mtu"] {
		cfg.TunMTU = *values.tunMTU
	}
	setBool("no-tun", &cfg.NoTun, *values.noTun)
	setString("dns-listen", &cfg.DNSListen, *values.dnsListen)
	setBool("dns-manage-resolv-conf", &cfg.DNSManageResolvConf, *values.dnsManage)
	setBool("no-dns", &cfg.NoDNS, *values.noDNS)
	setString("dns-domain", &cfg.DNSDomain, *values.dnsDomain)
	setBool("no-forward", &cfg.NoForward, *values.noForward)
	setBool("dkg", &cfg.DKG, *values.dkg)
	setBool("rotate-committee-keys", &cfg.RotateCommitteeKey, *values.rotateKeys)
	setBool("sso", &cfg.SSO, *values.sso)
	setString("sso-issuer", &cfg.SSOIssuer, *values.ssoIssuer)
	setString("sso-client-id", &cfg.SSOClientID, *values.ssoClientID)
	setString("status-file", &cfg.StatusFile, *values.statusFile)
	setString("hostname", &cfg.Hostname, *values.hostname)
	if explicit["posture"] {
		cfg.Posture = strings.Split(*values.posture, ",")
	}
	setString("network", &cfg.NetworkID, *values.networkID)
	setString("admin-token", &cfg.AdminToken, *values.adminToken)
	setString("action", &cfg.AdminAction, *values.adminAction)
	setString("file", &cfg.AdminFile, *values.adminFile)
	setString("target", &cfg.AdminTarget, *values.adminTarget)
	setString("metrics-listen", &cfg.MetricsListen, *values.metricsListen)
	if explicit["otel-endpoint"] {
		cfg.Telemetry.OTLPEndpoint = *values.otelEndpoint
	}
	setString("alert-webhook", &cfg.Alert.Webhook, *values.alertWebhook)
	setString("alert-webhook-secret", &cfg.Alert.WebhookSecret, *values.alertWebhookSecret)
	setBool("allow-insecure-webhook", &cfg.Alert.AllowInsecureWebhook, *values.alertAllowInsecure)
	if explicit["alert-interval"] {
		cfg.Alert.Interval = *values.alertInterval
	}
	if explicit["alert-drop-count"] {
		cfg.Alert.DropCount = uint64(*values.alertDropCount)
	}
	if explicit["alert-drop-rate-percent"] {
		cfg.Alert.DropRatePercent = *values.alertDropRate
	}
	setString("ipc-socket", &cfg.IPC.Path, *values.ipcPath)
}
