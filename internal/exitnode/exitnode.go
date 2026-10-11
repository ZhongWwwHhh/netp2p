// Package exitnode installs the kernel forwarding state that turns an overlay
// client into a subnet/exit gateway.
//
// Traffic is injected into the local network stack through the TUN device; the
// kernel performs forwarding, SNAT and connection tracking. This package only
// owns the enabling state: IP forwarding plus the managed iptables NAT and
// FORWARD rules that permit and masquerade overlay traffic.
package exitnode

import (
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"

	"github.com/netp2p/netp2p/internal/tun"
)

// ErrUnsupported reports that this platform has no exit-node implementation.
var ErrUnsupported = errors.New("exit nodes are supported on Linux only")

// defaultForwardingPath is the Linux sysctl file toggled to enable routing.
const defaultForwardingPath = "/proc/sys/net/ipv4/ip_forward"

const (
	forwardChain = "NETP2P_FORWARD"
	snatChain    = "NETP2P_SNAT"
)

// Route is one certified destination this node forwards for.
type Route struct {
	ID          string
	Destination string // CIDR, for example 10.10.0.0/16 or 0.0.0.0/0
	Masquerade  bool
}

// Reconciler maintains the managed forwarding rules for a set of routes. It is
// idempotent: calling Reconcile repeatedly with the same set issues no new
// commands.
type Reconciler struct {
	overlayCIDR string
	run         tun.Runner
	forwarding  forwardingState
	// forwardingPath is the sysctl file used to toggle IP forwarding. It is a
	// field so tests can point at a temp file instead of the real /proc.
	forwardingPath string

	mu       sync.Mutex
	closed   bool
	chains   bool
	enabled  bool
	current  map[string]Route
	commands []string // audit trail for diagnostics and tests
}

// New builds a Reconciler for an overlay CIDR (the source range to masquerade).
// run executes iptables/sysctl commands; nil uses the real runner.
func New(overlayCIDR string, run tun.Runner) *Reconciler {
	if run == nil {
		run = tun.RunCommand
	}
	return &Reconciler{
		overlayCIDR:    overlayCIDR,
		run:            run,
		current:        make(map[string]Route),
		forwardingPath: defaultForwardingPath,
	}
}

// Commands returns the commands issued so far, for tests and diagnostics.
func (reconciler *Reconciler) Commands() []string {
	reconciler.mu.Lock()
	defer reconciler.mu.Unlock()
	return append([]string(nil), reconciler.commands...)
}

// Reconcile installs rules for routes and removes rules for routes no longer
// advertised.
func (reconciler *Reconciler) Reconcile(routes []Route) error {
	reconciler.mu.Lock()
	if reconciler.closed {
		reconciler.mu.Unlock()
		return fmt.Errorf("exit node reconciler is closed")
	}
	desired := make(map[string]Route, len(routes))
	for _, route := range routes {
		if route.Destination == "" {
			continue
		}
		desired[route.Destination] = route
	}
	current := reconciler.current
	reconciler.current = make(map[string]Route, len(desired))
	reconciler.mu.Unlock()

	if len(desired) > 0 {
		reconciler.mu.Lock()
		reconciler.enabled = true
		reconciler.mu.Unlock()
		if err := reconciler.ensureChains(); err != nil {
			return err
		}
		if err := reconciler.forwarding.enable(reconciler); err != nil {
			return err
		}
	}

	var firstError error
	record := func(err error) {
		if err != nil && firstError == nil {
			firstError = err
		}
	}

	added := make([]string, 0)
	for destination := range desired {
		if _, exists := current[destination]; exists {
			reconciler.mu.Lock()
			reconciler.current[destination] = desired[destination]
			reconciler.mu.Unlock()
			continue
		}
		added = append(added, destination)
	}
	sort.Strings(added)
	for _, destination := range added {
		if err := reconciler.install(desired[destination]); err != nil {
			record(err)
			continue
		}
		reconciler.mu.Lock()
		reconciler.current[destination] = desired[destination]
		reconciler.mu.Unlock()
	}

	removed := make([]string, 0)
	for destination := range current {
		if _, exists := desired[destination]; !exists {
			removed = append(removed, destination)
		}
	}
	sort.Strings(removed)
	for _, destination := range removed {
		record(reconciler.remove(current[destination]))
	}

	reconciler.mu.Lock()
	managedState := len(current) > 0 || reconciler.chains
	reconciler.mu.Unlock()
	if len(desired) == 0 && managedState {
		record(reconciler.removeChains())
		reconciler.mu.Lock()
		reconciler.chains = false
		reconciler.mu.Unlock()
		record(reconciler.forwarding.disable(reconciler))
	}
	return firstError
}

// Close removes every managed rule and restores the original forwarding sysctl.
func (reconciler *Reconciler) Close() error {
	reconciler.mu.Lock()
	if reconciler.closed || !reconciler.enabled {
		reconciler.closed = true
		reconciler.mu.Unlock()
		return nil
	}
	reconciler.closed = true
	routes := reconciler.current
	reconciler.current = make(map[string]Route)
	reconciler.mu.Unlock()
	var firstError error
	record := func(err error) {
		if err != nil && firstError == nil {
			firstError = err
		}
	}
	for _, route := range routes {
		record(reconciler.remove(route))
	}
	record(reconciler.removeChains())
	record(reconciler.forwarding.disable(reconciler))
	return firstError
}

func (reconciler *Reconciler) install(route Route) error {
	if route.Masquerade {
		if err := reconciler.exec("iptables", "-t", "nat", "-C", snatChain,
			"-s", reconciler.overlayCIDR, "-d", route.Destination, "-j", "MASQUERADE"); err != nil {
			if err := reconciler.exec("iptables", "-t", "nat", "-A", snatChain,
				"-s", reconciler.overlayCIDR, "-d", route.Destination, "-j", "MASQUERADE"); err != nil {
				return err
			}
		}
	}
	if err := reconciler.exec("iptables", "-C", forwardChain,
		"-s", reconciler.overlayCIDR, "-d", route.Destination, "-j", "ACCEPT"); err != nil {
		if err := reconciler.exec("iptables", "-A", forwardChain,
			"-s", reconciler.overlayCIDR, "-d", route.Destination, "-j", "ACCEPT"); err != nil {
			return err
		}
	}
	if err := reconciler.exec("iptables", "-C", forwardChain,
		"-d", reconciler.overlayCIDR, "-s", route.Destination,
		"-m", "conntrack", "--ctstate", "ESTABLISHED,RELATED", "-j", "ACCEPT"); err != nil {
		return reconciler.exec("iptables", "-A", forwardChain,
			"-d", reconciler.overlayCIDR, "-s", route.Destination,
			"-m", "conntrack", "--ctstate", "ESTABLISHED,RELATED", "-j", "ACCEPT")
	}
	return nil
}

func (reconciler *Reconciler) remove(route Route) error {
	var firstError error
	if route.Masquerade {
		if err := reconciler.exec("iptables", "-t", "nat", "-D", snatChain,
			"-s", reconciler.overlayCIDR, "-d", route.Destination, "-j", "MASQUERADE"); err != nil {
			firstError = err
		}
	}
	if err := reconciler.exec("iptables", "-D", forwardChain,
		"-s", reconciler.overlayCIDR, "-d", route.Destination, "-j", "ACCEPT"); err != nil && firstError == nil {
		firstError = err
	}
	if err := reconciler.exec("iptables", "-D", forwardChain,
		"-d", reconciler.overlayCIDR, "-s", route.Destination,
		"-m", "conntrack", "--ctstate", "ESTABLISHED,RELATED", "-j", "ACCEPT"); err != nil && firstError == nil {
		firstError = err
	}
	return firstError
}

func (reconciler *Reconciler) ensureChains() error {
	reconciler.mu.Lock()
	initialized := reconciler.chains
	reconciler.chains = true
	reconciler.mu.Unlock()
	if initialized {
		return nil
	}
	// A previous process may have crashed after creating the chains. Removing
	// only named NetP2P chains recovers without touching operator rules.
	_ = reconciler.removeChains()
	if err := reconciler.exec("iptables", "-N", forwardChain); err != nil {
		return err
	}
	if err := reconciler.exec("iptables", "-N", snatChain); err != nil {
		return err
	}
	if err := reconciler.exec("iptables", "-C", "FORWARD", "-s", reconciler.overlayCIDR,
		"-j", forwardChain); err != nil {
		if err := reconciler.exec("iptables", "-I", "FORWARD", "1", "-s", reconciler.overlayCIDR,
			"-j", forwardChain); err != nil {
			return err
		}
	}
	if err := reconciler.exec("iptables", "-t", "nat", "-C", "POSTROUTING",
		"-s", reconciler.overlayCIDR, "-j", snatChain); err != nil {
		if err := reconciler.exec("iptables", "-t", "nat", "-I", "POSTROUTING", "1",
			"-s", reconciler.overlayCIDR, "-j", snatChain); err != nil {
			return err
		}
	}
	reconciler.mu.Lock()
	reconciler.chains = true
	reconciler.mu.Unlock()
	return nil
}

func (reconciler *Reconciler) removeChains() error {
	var firstError error
	record := func(err error) {
		if err != nil && firstError == nil {
			firstError = err
		}
	}
	record(reconciler.exec("iptables", "-D", "FORWARD", "-s", reconciler.overlayCIDR, "-j", forwardChain))
	record(reconciler.exec("iptables", "-F", forwardChain))
	record(reconciler.exec("iptables", "-X", forwardChain))
	record(reconciler.exec("iptables", "-t", "nat", "-D", "POSTROUTING",
		"-s", reconciler.overlayCIDR, "-j", snatChain))
	record(reconciler.exec("iptables", "-t", "nat", "-F", snatChain))
	record(reconciler.exec("iptables", "-t", "nat", "-X", snatChain))
	return firstError
}

func (reconciler *Reconciler) exec(name string, args ...string) error {
	line := strings.Join(append([]string{name}, args...), " ")
	reconciler.record(line)
	return reconciler.run(name, args...)
}

// record appends an audit line without executing it, for state the reconciler
// changes directly (for example writing a /proc/sys file).
func (reconciler *Reconciler) record(line string) {
	reconciler.mu.Lock()
	reconciler.commands = append(reconciler.commands, line)
	reconciler.mu.Unlock()
}
