package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/netp2p/netp2p/internal/p2p"
)

func main() {
	role := flag.String("role", "node", "node, manager, client, admin, doctor or seedgen")
	dataDir := flag.String("data-dir", ".netp2p", "libp2p identity and node data directory")
	listen := flag.String("listen", "/ip4/0.0.0.0/udp/0/quic-v1", "libp2p listen multiaddr")
	webListen := flag.String("web-listen", "0.0.0.0:8080", "manager browser bootstrap HTTP address")
	configPath := flag.String("config", "", "manager static JSON seed")
	seedPath := flag.String("seed", "", "path to a seed JSON for client relay/bootstrapping (optional)")
	managerAddr := flag.String("manager", "", "manager libp2p multiaddr")
	setupKey := flag.String("setup-key", "", "client setup key")
	packetListen := flag.String("packet-listen", "127.0.0.1:51820", "client userspace UDP packet endpoint")
	tunName := flag.String("tun", "netp2p0", "client TUN interface name (Linux)")
	tunMTU := flag.Int("tun-mtu", 1280, "client TUN interface MTU")
	noTun := flag.Bool("no-tun", false, "force the userspace UDP packet endpoint instead of TUN")
	dnsListen := flag.String("dns-listen", "127.0.0.1:53", "client local DNS resolver address")
	dnsManage := flag.Bool("dns-manage-resolv-conf", true, "point /etc/resolv.conf at the overlay resolver (TUN mode only)")
	noDNS := flag.Bool("no-dns", false, "do not start the local DNS resolver")
	noForward := flag.Bool("no-forward", false, "disable manager forwarding for certified overlay paths")
	dkgEnabled := flag.Bool("dkg", false, "run a Pedersen DKG ceremony at startup and rotate the committee to a distributed group key (all managers must enable it)")
	rotateKeys := flag.Bool("rotate-committee-keys", false, "submit a rotate_committee_keys transition at startup (uses a DKG key when --dkg is set)")
	sso := flag.Bool("sso", false, "authenticate the client with an OIDC device flow")
	ssoIssuer := flag.String("sso-issuer", "", "OIDC issuer URL used with --sso")
	ssoClientID := flag.String("sso-client-id", "", "OIDC client id used with --sso")
	statusFile := flag.String("status-file", "", "write client status JSON to this path after login")
	hostname := flag.String("hostname", "", "stable client hostname advertised for DNS (defaults to the OS hostname)")
	posture := flag.String("posture", "", "comma-separated posture labels this client advertises at registration")
	networkID := flag.String("network", "netp2p-test", "network id")
	adminToken := flag.String("admin-token", "", "admin auth token from seed")
	adminAction := flag.String("action", "", "admin action: upsert-group, remove-group, upsert-policy, remove-policy, update-peer, upsert-route, remove-route, upsert-budget, remove-budget, upsert-setup-key, remove-setup-key, upsert-nameserver, remove-nameserver, upsert-zone, remove-zone, update-dns-settings, update-committee, rotate-committee-keys")
	adminFile := flag.String("file", "", "JSON record file for upsert actions or target ID for remove actions")
	adminTarget := flag.String("target", "", "target ID for remove actions")
	metricsListen := flag.String("metrics-listen", "", "manager Prometheus /metrics address (empty disables metrics)")
	alertWebhook := flag.String("alert-webhook", "", "manager alert webhook URL (empty logs only)")
	alertWebhookSecret := flag.String("alert-webhook-secret", "", "bearer token sent to the alert webhook")
	alertAllowInsecure := flag.Bool("allow-insecure-webhook", false, "permit an http alert webhook URL (unsafe)")
	alertInterval := flag.Duration("alert-interval", 15*time.Second, "manager alert evaluation interval")
	alertDropCount := flag.Uint64("alert-drop-count", 100, "dropped frames in one interval that fire the forward_drops alert")
	alertDropRatePercent := flag.Float64("alert-drop-rate-percent", 5, "dropped share of traffic that fires the forward_drops alert")
	configFile := flag.String("config-file", "", "YAML or JSON runtime config; command-line flags override it")
	flag.Parse()
	if err := applyRuntimeConfig(*configFile); err != nil {
		log.Fatal(err)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	switch *role {
	case "manager":
		if *configPath == "" {
			log.Fatal("--config is required for manager role")
		}
		if err := runManager(ctx, *dataDir, *configPath, *listen, *webListen, *metricsListen, !*noForward, *dkgEnabled, *rotateKeys, alertOptions{
			webhook: *alertWebhook, webhookSecret: *alertWebhookSecret, interval: *alertInterval,
			dropCount: *alertDropCount, dropRatePercent: *alertDropRatePercent,
			allowInsecureWebhook: *alertAllowInsecure,
		}); err != nil {
			log.Fatal(err)
		}
		return
	case "client":
		if *managerAddr == "" {
			log.Fatal("--manager is required for client role")
		}
		if *setupKey == "" && !*sso {
			log.Fatal("--setup-key or --sso is required for client role")
		}
		if err := runClient(ctx, clientOptions{
			dataDir: *dataDir, listenAddr: *listen, managerAddr: *managerAddr,
			networkID: *networkID, setupKey: *setupKey, packetListen: *packetListen,
			statusFile: *statusFile, hostname: *hostname, tunName: *tunName, tunMTU: *tunMTU, noTun: *noTun,
			posture:   strings.Split(*posture, ","),
			dnsListen: *dnsListen, dnsManage: *dnsManage, noDNS: *noDNS,
			sso: *sso, ssoIssuer: *ssoIssuer, ssoClientID: *ssoClientID,
			seedPath: *seedPath,
		}); err != nil {
			log.Fatal(err)
		}
		return
	case "admin":
		if *managerAddr == "" || *adminToken == "" || *adminAction == "" {
			log.Fatal("--manager, --admin-token and --action are required for admin role")
		}
		if err := runAdmin(ctx, *managerAddr, *adminToken, *adminAction, *adminFile, *adminTarget); err != nil {
			log.Fatal(err)
		}
		return
	case "seedgen":
		if err := writeSeed(*configPath); err != nil {
			log.Fatal(err)
		}
		return
	case "doctor":
		if err := runDoctor(ctx, doctorOptions{
			dataDir: *dataDir, managerAddr: *managerAddr, seedPath: *configPath,
			tunName: *tunName, dnsListen: *dnsListen,
		}); err != nil {
			log.Fatal(err)
		}
		return
	}

	node, err := p2p.New(ctx, p2p.Config{DataDir: *dataDir, Listen: []string{*listen}})
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
