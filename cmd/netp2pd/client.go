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
}

func runClient(ctx context.Context, options clientOptions) error {
	dataDir := options.dataDir
	node, err := p2p.New(ctx, p2p.Config{DataDir: filepath.Join(dataDir, "client"), Listen: []string{options.listenAddr}})
	if err != nil {
		return err
	}
	defer node.Close()
	sink, tunDevice, err := openClientSink(options)
	if err != nil {
		return err
	}
	defer sink.Close()
	netClient, err := client.New(node, options.managerAddr, sink)
	if err != nil {
		return err
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
