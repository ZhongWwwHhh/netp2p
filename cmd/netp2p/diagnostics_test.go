package main

import (
	"errors"
	"github.com/netp2p/netp2p/internal/runtimeconfig"
	"net"
	"strings"
	"testing"
)

func TestAggregateNetcheckErrorsReportsEveryFailure(t *testing.T) {
	if err := aggregateNetcheckErrors([]error{nil, nil}); err != nil {
		t.Fatalf("successful checks returned %v", err)
	}

	err := aggregateNetcheckErrors([]error{
		errors.New("daemon unavailable"),
		nil,
		errors.New("tun permission denied"),
	})
	if err == nil {
		t.Fatal("expected an aggregate error")
	}
	message := err.Error()
	if !strings.Contains(message, "netcheck failed (2 checks)") ||
		!strings.Contains(message, "daemon unavailable") ||
		!strings.Contains(message, "tun permission denied") {
		t.Fatalf("aggregate error did not include all failures: %v", err)
	}
}

func TestNetcheckChecksUseLiveManagerAndTUNStatus(t *testing.T) {
	cfg := runtimeconfig.Config{NoDNS: true, NoTun: true, PacketListen: "127.0.0.1:0"}
	status := map[string]any{
		"state": "running", "mode": "tun", "manager": "active-manager",
		"managerFailover": map[string]any{"configured": float64(3), "activeIndex": float64(1)},
	}
	checks := netcheckChecks(status, cfg, nil)
	if err := aggregateNetcheckErrors(checkErrors(checks)); err != nil {
		t.Fatalf("live status netcheck failed: %v", err)
	}
	details := map[string]string{}
	for _, check := range checks {
		details[check.name] = check.detail
	}
	if details["manager"] != "active-manager" {
		t.Fatalf("manager check = %q, want live daemon manager", details["manager"])
	}
	if details["manager failover"] != "3 configured" {
		t.Fatalf("manager failover check = %q, want 3 configured", details["manager failover"])
	}
	if details["packet endpoint"] != "active TUN data path" {
		t.Fatalf("packet endpoint check = %q, want active TUN data path", details["packet endpoint"])
	}
}

func TestNetcheckChecksPreserveExplicitUserspaceEndpoint(t *testing.T) {
	listener, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	cfg := runtimeconfig.Config{NoDNS: true, NoTun: true, PacketListen: listener.LocalAddr().String()}
	status := map[string]any{"state": "ready", "mode": "userspace", "manager": "active-manager"}
	checks := netcheckChecks(status, cfg, nil)
	if err := aggregateNetcheckErrors(checkErrors(checks)); err != nil {
		t.Fatalf("userspace netcheck failed: %v", err)
	}
	var found bool
	for _, check := range checks {
		if check.name == "packet endpoint" {
			found = true
			if check.detail != cfg.PacketListen || check.err != nil {
				t.Fatalf("packet endpoint check = %+v", check)
			}
		}
	}
	if !found {
		t.Fatal("packet endpoint check missing")
	}
}
