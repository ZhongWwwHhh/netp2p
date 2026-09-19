package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"time"

	"github.com/netp2p/netp2p/internal/client"
	"github.com/netp2p/netp2p/internal/dns"
	"github.com/netp2p/netp2p/internal/p2p"
	"github.com/netp2p/netp2p/internal/packet"
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
}

func runClient(ctx context.Context, options clientOptions) error {
	dataDir := options.dataDir
	node, err := p2p.New(ctx, p2p.Config{DataDir: filepath.Join(dataDir, "client"), Listen: []string{options.listenAddr}})
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
	netClient, err := client.New(node, options.managerAddr, sink)
	if err != nil {
		return err
	}
	if resolver != nil {
		netClient.SetDNSResolver(resolver)
		netClient.SetDNSUpstreams(upstreams)
	}
	if err := loginWithRetry(ctx, netClient, options.networkID, options.setupKey); err != nil {
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
	go func() {
		if err := netClient.ServePackets(ctx); err != nil && ctx.Err() == nil {
			log.Printf("packet endpoint stopped: %v", err)
		}
	}()
	status, err := json.Marshal(map[string]any{
		"peerID": node.Host.ID().String(), "overlayIP": netClient.Self().OverlayIP,
		"height": netClient.SnapshotHeight(), "packetListen": options.packetListen,
		"mode": clientMode(tunDevice),
	})
	if err != nil {
		return err
	}
	fmt.Printf("%s\n", status)
	if options.statusFile != "" {
		if err := os.WriteFile(options.statusFile, status, 0o644); err != nil {
			return fmt.Errorf("write status file: %w", err)
		}
	}
	<-ctx.Done()
	return nil
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

// loginWithRetry tolerates managers that are still certifying genesis; early
// attempts fail fast until the control handlers are registered.
func loginWithRetry(ctx context.Context, netClient *client.Client, networkID, setupKey string) error {
	deadline := time.Now().Add(60 * time.Second)
	var lastErr error
	for time.Now().Before(deadline) {
		if lastErr = netClient.Login(ctx, networkID, setupKey); lastErr == nil {
			return nil
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
