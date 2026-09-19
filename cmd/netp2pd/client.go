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
)

func runClient(ctx context.Context, dataDir, listenAddr, managerAddr, networkID, setupKey, packetListen, statusFile string) error {
	node, err := p2p.New(ctx, p2p.Config{DataDir: filepath.Join(dataDir, "client"), Listen: []string{listenAddr}})
	if err != nil {
		return err
	}
	defer node.Close()
	sink, err := packet.NewUDPPacketSink(packetListen)
	if err != nil {
		return fmt.Errorf("open userspace packet endpoint: %w", err)
	}
	defer sink.Close()
	netClient, err := client.New(node, managerAddr, sink)
	if err != nil {
		return err
	}
	if err := loginWithRetry(ctx, netClient, networkID, setupKey); err != nil {
		return err
	}
	go netClient.SyncLoop(ctx)
	go func() {
		if err := netClient.ServePackets(ctx); err != nil && ctx.Err() == nil {
			log.Printf("packet endpoint stopped: %v", err)
		}
	}()
	status, err := json.Marshal(map[string]any{
		"peerID": node.Host.ID().String(), "overlayIP": netClient.Self().OverlayIP, "height": netClient.SnapshotHeight(), "packetListen": packetListen,
	})
	if err != nil {
		return err
	}
	fmt.Printf("%s\n", status)
	if statusFile != "" {
		if err := os.WriteFile(statusFile, status, 0o644); err != nil {
			return fmt.Errorf("write status file: %w", err)
		}
	}
	<-ctx.Done()
	return nil
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
