package main

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/netp2p/netp2p/internal/config"
	"github.com/netp2p/netp2p/internal/p2p"
	"github.com/netp2p/netp2p/internal/tun"
	"github.com/netp2p/netp2p/internal/version"
)

// doctorCheck is one self-test result. A failure means the node cannot do the
// thing the check covers; a warning means it will fall back.
type doctorCheck struct {
	name    string
	ok      bool
	detail  string
	warning bool
}

// runDoctor performs preflight checks so an operator can find environment
// problems (missing TUN device, unprivileged DNS takeover, unreachable
// committee) before starting a node. It returns an error if any hard check
// fails; warnings are reported but do not fail the command.
func runDoctor(ctx context.Context, options doctorOptions) error {
	checks := make([]doctorCheck, 0, 6)
	checks = append(checks, doctorCheck{
		name:   "protocol",
		ok:     true,
		detail: fmt.Sprintf("wire protocol %s (manager and client must match)", version.ProtocolVersion),
	})
	checks = append(checks, checkClock())
	checks = append(checks, checkTUN(options.tunName))
	checks = append(checks, checkDNS(options.dnsListen))
	if options.seedPath != "" {
		checks = append(checks, checkSeed(options.seedPath))
	}
	if options.managerAddr != "" {
		checks = append(checks, checkManager(ctx, options))
	}

	failed := false
	for _, check := range checks {
		switch {
		case !check.ok && !check.warning:
			failed = true
			fmt.Printf("FAIL  %-12s %s\n", check.name, check.detail)
		case !check.ok:
			fmt.Printf("WARN  %-12s %s\n", check.name, check.detail)
		default:
			fmt.Printf("ok    %-12s %s\n", check.name, check.detail)
		}
	}
	if failed {
		return fmt.Errorf("doctor found blocking problems")
	}
	return nil
}

func checkClock() doctorCheck {
	now := time.Now()
	if now.Year() < 2024 {
		return doctorCheck{name: "clock", ok: false, warning: true,
			detail: fmt.Sprintf("system clock reads %s; certificate freshness and login expiration depend on it", now.Format(time.RFC3339))}
	}
	return doctorCheck{name: "clock", ok: true, detail: now.UTC().Format(time.RFC3339)}
}

func checkTUN(name string) doctorCheck {
	device, err := tun.Open(name, nil)
	if err != nil {
		return doctorCheck{name: "tun", ok: false, warning: true,
			detail: fmt.Sprintf("TUN device %q unavailable (%v); run with --no-tun to use the userspace endpoint", name, err)}
	}
	_ = device.Close()
	return doctorCheck{name: "tun", ok: true, detail: fmt.Sprintf("TUN device %q is available", name)}
}

func checkDNS(listen string) doctorCheck {
	if os.Geteuid() != 0 {
		return doctorCheck{name: "dns", ok: false, warning: true,
			detail: fmt.Sprintf("not running as root; %s and /etc/resolv.conf takeover will be skipped", listen)}
	}
	return doctorCheck{name: "dns", ok: true, detail: fmt.Sprintf("resolver can bind %s and manage /etc/resolv.conf", listen)}
}

func checkSeed(path string) doctorCheck {
	seed, err := config.Load(path)
	if err != nil {
		return doctorCheck{name: "seed", ok: false, detail: err.Error()}
	}
	managers := make([]string, 0, len(seed.Managers))
	for _, member := range seed.Managers {
		managers = append(managers, member.ID)
	}
	return doctorCheck{name: "seed", ok: true,
		detail: fmt.Sprintf("network %s with %d committee members: %v", seed.NetworkID, len(managers), managers)}
}

func checkManager(ctx context.Context, options doctorOptions) doctorCheck {
	info, err := peer.AddrInfoFromString(options.managerAddr)
	if err != nil {
		return doctorCheck{name: "manager", ok: false, detail: fmt.Sprintf("invalid --manager multiaddr: %v", err)}
	}
	node, err := p2p.New(ctx, p2p.Config{DataDir: options.dataDir})
	if err != nil {
		return doctorCheck{name: "manager", ok: false, detail: fmt.Sprintf("create probe host: %v", err)}
	}
	defer node.Close()
	connectContext, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if err := node.Host.Connect(connectContext, *info); err != nil {
		return doctorCheck{name: "manager", ok: false, detail: fmt.Sprintf("cannot reach %s: %v", info.ID, err)}
	}
	return doctorCheck{name: "manager", ok: true, detail: fmt.Sprintf("connected to %s", info.ID)}
}

type doctorOptions struct {
	dataDir     string
	managerAddr string
	seedPath    string
	tunName     string
	dnsListen   string
}
