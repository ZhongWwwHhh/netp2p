//go:build linux

package exitnode

import (
	"fmt"
	"os"
	"strings"
	"sync"
	"testing"
)

// tempForwardingFile returns a writable stand-in for the ip_forward sysctl so
// the reconciler can be tested without root.
func tempForwardingFile(tb testing.TB) string {
	tb.Helper()
	path := tb.TempDir() + "/ip_forward"
	if err := os.WriteFile(path, []byte("0"), 0o644); err != nil {
		tb.Fatal(err)
	}
	return path
}

// recordingRunner simulates iptables rule membership so the -C/-A/-D protocol
// behaves the way the real CLI does: -C fails when a rule is absent.
type recordingRunner struct {
	mu       sync.Mutex
	commands []string
	rules    map[string]struct{}
}

func (runner *recordingRunner) run(name string, args ...string) error {
	line := strings.Join(append([]string{name}, args...), " ")
	runner.mu.Lock()
	defer runner.mu.Unlock()
	if runner.rules == nil {
		runner.rules = make(map[string]struct{})
	}
	runner.commands = append(runner.commands, line)
	// Find the rule verb (-C/-A/-D); the spec is everything around it, keyed by
	// table+chain+verb-less arguments so a later -D removes the -A'd rule.
	for index, arg := range args {
		if arg != "-C" && arg != "-A" && arg != "-D" {
			continue
		}
		spec := strings.Join(append(append([]string{}, args[:index]...), args[index+1:]...), " ")
		switch arg {
		case "-C":
			if _, ok := runner.rules[spec]; !ok {
				return fmt.Errorf("rule does not exist")
			}
		case "-A":
			runner.rules[spec] = struct{}{}
		case "-D":
			if _, ok := runner.rules[spec]; !ok {
				return fmt.Errorf("rule does not exist")
			}
			delete(runner.rules, spec)
		}
		break
	}
	return nil
}

func (runner *recordingRunner) lines() []string {
	runner.mu.Lock()
	defer runner.mu.Unlock()
	return append([]string(nil), runner.commands...)
}

func TestReconcileInstallsMasqueradeForwardingRules(t *testing.T) {
	runner := &recordingRunner{}
	reconciler := New("100.64.0.0/24", runner.run)
	reconciler.forwardingPath = tempForwardingFile(t)

	if err := reconciler.Reconcile([]Route{{ID: "subnet", Destination: "10.10.0.0/16", Masquerade: true}}); err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	joined := strings.Join(reconciler.Commands(), "\n")
	for _, want := range []string{
		"net.ipv4.ip_forward=1",
		"iptables -t nat -A POSTROUTING -s 100.64.0.0/24 -d 10.10.0.0/16 -j MASQUERADE",
		"iptables -A FORWARD -s 100.64.0.0/24 -d 10.10.0.0/16 -j ACCEPT",
	} {
		if !strings.Contains(joined, want) {
			t.Fatalf("missing %q in commands:\n%s", want, joined)
		}
	}
}

func TestReconcileIsIdempotent(t *testing.T) {
	runner := &recordingRunner{}
	reconciler := New("100.64.0.0/24", runner.run)
	reconciler.forwardingPath = tempForwardingFile(t)
	route := Route{ID: "subnet", Destination: "10.10.0.0/16", Masquerade: true}
	if err := reconciler.Reconcile([]Route{route}); err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	before := len(runner.lines())
	if err := reconciler.Reconcile([]Route{route}); err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	if len(runner.lines()) != before {
		t.Fatalf("idempotent reconcile ran extra commands: %v", runner.lines()[before:])
	}
}

func TestReconcileRemovesRulesAndRestoresForwarding(t *testing.T) {
	runner := &recordingRunner{}
	reconciler := New("100.64.0.0/24", runner.run)
	reconciler.forwardingPath = tempForwardingFile(t)
	if err := reconciler.Reconcile([]Route{{ID: "subnet", Destination: "10.10.0.0/16", Masquerade: true}}); err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	if err := reconciler.Reconcile(nil); err != nil {
		t.Fatalf("reconcile empty: %v", err)
	}
	joined := strings.Join(reconciler.Commands(), "\n")
	for _, want := range []string{
		"iptables -t nat -D POSTROUTING -s 100.64.0.0/24 -d 10.10.0.0/16 -j MASQUERADE",
		"iptables -D FORWARD -s 100.64.0.0/24 -d 10.10.0.0/16 -j ACCEPT",
		"net.ipv4.ip_forward=",
	} {
		if !strings.Contains(joined, want) {
			t.Fatalf("missing %q in commands:\n%s", want, joined)
		}
	}
}

func TestReconcileWithoutMasqueradeSkipsNAT(t *testing.T) {
	runner := &recordingRunner{}
	reconciler := New("100.64.0.0/24", runner.run)
	reconciler.forwardingPath = tempForwardingFile(t)
	if err := reconciler.Reconcile([]Route{{ID: "subnet", Destination: "10.10.0.0/16", Masquerade: false}}); err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	joined := strings.Join(runner.lines(), "\n")
	if strings.Contains(joined, "MASQUERADE") {
		t.Fatalf("non-masquerade route installed NAT: %s", joined)
	}
	if !strings.Contains(joined, "-j ACCEPT") {
		t.Fatalf("expected a FORWARD accept rule: %s", joined)
	}
}
