package tun

import (
	"io"
	"net"
	"strings"
	"sync"
	"testing"
)

// recordingRunner captures the ip commands the device would run.
type recordingRunner struct {
	mu       sync.Mutex
	commands []string
	fail     map[string]error
}

func (runner *recordingRunner) run(name string, args ...string) error {
	line := strings.Join(append([]string{name}, args...), " ")
	runner.mu.Lock()
	runner.commands = append(runner.commands, line)
	err := runner.fail[line]
	runner.mu.Unlock()
	return err
}

func (runner *recordingRunner) lines() []string {
	runner.mu.Lock()
	defer runner.mu.Unlock()
	return append([]string(nil), runner.commands...)
}

// linkDevice builds a Device around one end of an in-memory full-duplex pipe so
// packet IO can be tested without creating a real interface. The returned
// connection is the far end a peer would appear on.
func linkDevice(t *testing.T, runner Runner) (*Device, net.Conn) {
	t.Helper()
	deviceSide, peerSide := net.Pipe()
	device := &Device{file: deviceSide, name: "netp2p0", run: runner, routes: make(map[string]struct{})}
	t.Cleanup(func() { _ = peerSide.Close() })
	return device, peerSide
}

func TestConfigureBringsDeviceUpWithOverlayAddress(t *testing.T) {
	runner := &recordingRunner{fail: map[string]error{}}
	device, _ := linkDevice(t, runner.run)

	if err := device.Configure("100.64.0.7", 0); err != nil {
		t.Fatalf("configure: %v", err)
	}
	want := []string{
		"ip link set dev netp2p0 up",
		"ip addr replace 100.64.0.7/32 dev netp2p0",
		"ip link set dev netp2p0 mtu 1280",
	}
	got := runner.lines()
	if len(got) != len(want) {
		t.Fatalf("commands = %v, want %v", got, want)
	}
	for index := range want {
		if got[index] != want[index] {
			t.Fatalf("command %d = %q, want %q", index, got[index], want[index])
		}
	}
}

func TestConfigureHonoursRequestedMTU(t *testing.T) {
	runner := &recordingRunner{fail: map[string]error{}}
	device, _ := linkDevice(t, runner.run)
	if err := device.Configure("100.64.0.7", 1400); err != nil {
		t.Fatalf("configure: %v", err)
	}
	last := runner.lines()[len(runner.lines())-1]
	if !strings.Contains(last, "mtu 1400") {
		t.Fatalf("mtu command = %q, want 1400", last)
	}
}

func TestConfigureRequiresAddress(t *testing.T) {
	runner := &recordingRunner{fail: map[string]error{}}
	device, _ := linkDevice(t, runner.run)
	if err := device.Configure("", 0); err == nil {
		t.Fatal("expected an empty address to be rejected")
	}
	if len(runner.lines()) != 0 {
		t.Fatalf("no commands should run, got %v", runner.lines())
	}
}

func TestReconcileNetworksInstallsAndRemoves(t *testing.T) {
	runner := &recordingRunner{fail: map[string]error{}}
	device, _ := linkDevice(t, runner.run)

	if err := device.ReconcileNetworks([]string{"10.10.0.0/16", "192.168.0.0/24"}); err != nil {
		t.Fatalf("reconcile networks: %v", err)
	}
	if got := device.Networks(); len(got) != 2 {
		t.Fatalf("networks = %v, want two entries", got)
	}

	if err := device.ReconcileNetworks([]string{"10.10.0.0/16"}); err != nil {
		t.Fatalf("reconcile networks: %v", err)
	}
	lines := runner.lines()
	last := lines[len(lines)-1]
	if last != "ip route del 192.168.0.0/24 dev netp2p0" {
		t.Fatalf("last command = %q, want stale network removal", last)
	}
	if got := device.Networks(); len(got) != 1 || got[0] != "10.10.0.0/16" {
		t.Fatalf("networks = %v, want only 10.10.0.0/16", got)
	}
}

func TestReconcileNetworksPinsUnderlayForDefaultRoute(t *testing.T) {
	runner := &recordingRunner{fail: map[string]error{}}
	device, _ := linkDevice(t, runner.run)
	device.output = func(name string, args ...string) (string, error) {
		return "default via 192.0.2.1 dev eth0 proto dhcp src 192.0.2.10 metric 100\n", nil
	}
	device.SetUnderlayHosts([]string{"198.51.100.7"})

	if err := device.ReconcileNetworks([]string{"0.0.0.0/0"}); err != nil {
		t.Fatalf("reconcile networks: %v", err)
	}
	lines := runner.lines()
	wantPin := "ip route replace 198.51.100.7/32 via 192.0.2.1"
	found := false
	for _, line := range lines {
		if line == wantPin {
			found = true
		}
	}
	if !found {
		t.Fatalf("underlay pin not installed; commands = %v", lines)
	}

	// Dropping the default route removes the pin.
	if err := device.ReconcileNetworks(nil); err != nil {
		t.Fatalf("reconcile networks: %v", err)
	}
	lines = runner.lines()
	last := lines[len(lines)-1]
	if last != "ip route del 198.51.100.7/32" {
		t.Fatalf("last command = %q, want underlay pin removal", last)
	}
}

func TestReconcileRoutesAddsAndRemoves(t *testing.T) {
	runner := &recordingRunner{fail: map[string]error{}}
	device, _ := linkDevice(t, runner.run)

	if err := device.ReconcileRoutes([]string{"100.64.0.2", "100.64.0.3"}); err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	if got := device.Routes(); len(got) != 2 {
		t.Fatalf("routes = %v, want two entries", got)
	}

	// Re-applying the same set must not re-issue commands.
	before := len(runner.lines())
	if err := device.ReconcileRoutes([]string{"100.64.0.3", "100.64.0.2"}); err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	if len(runner.lines()) != before {
		t.Fatalf("idempotent reconcile ran extra commands: %v", runner.lines()[before:])
	}

	// Dropping a peer removes exactly its route.
	if err := device.ReconcileRoutes([]string{"100.64.0.2"}); err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	last := runner.lines()[len(runner.lines())-1]
	if last != "ip route del 100.64.0.3/32 dev netp2p0" {
		t.Fatalf("last command = %q, want the stale route removal", last)
	}
	if got := device.Routes(); len(got) != 1 || got[0] != "100.64.0.2" {
		t.Fatalf("routes = %v, want only 100.64.0.2", got)
	}
}

func TestReconcileRoutesIgnoresEmptyEntries(t *testing.T) {
	runner := &recordingRunner{fail: map[string]error{}}
	device, _ := linkDevice(t, runner.run)
	if err := device.ReconcileRoutes([]string{"", "100.64.0.2", ""}); err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	if got := device.Routes(); len(got) != 1 {
		t.Fatalf("routes = %v, want one entry", got)
	}
}

func TestReconcileRoutesReportsFailureButKeepsOthers(t *testing.T) {
	runner := &recordingRunner{fail: map[string]error{
		"ip route replace 100.64.0.2/32 dev netp2p0": io.ErrClosedPipe,
	}}
	device, _ := linkDevice(t, runner.run)

	err := device.ReconcileRoutes([]string{"100.64.0.2", "100.64.0.3"})
	if err == nil {
		t.Fatal("expected the failing route to be reported")
	}
	// The failure must not stop the remaining route from being installed.
	if got := device.Routes(); len(got) != 1 || got[0] != "100.64.0.3" {
		t.Fatalf("routes = %v, want only the successful route", got)
	}
}

func TestReadPacketReturnsExactLength(t *testing.T) {
	runner := &recordingRunner{fail: map[string]error{}}
	device, peer := linkDevice(t, runner.run)
	go func() {
		_, _ = peer.Write([]byte{1, 2, 3})
	}()
	got, err := device.ReadPacket()
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if len(got) != 3 {
		t.Fatalf("packet length = %d, want 3", len(got))
	}
	if string(got) != string([]byte{1, 2, 3}) {
		t.Fatalf("read %v, want [1 2 3]", got)
	}
}

// WritePacket injects into the device, which a reader on the peer end observes.
func TestWritePacketReachesTheStack(t *testing.T) {
	runner := &recordingRunner{fail: map[string]error{}}
	device, peer := linkDevice(t, runner.run)

	payload := []byte{0x45, 0x00, 0x00, 0x14, 0xde, 0xad}
	go func() {
		if err := device.WritePacket(payload); err != nil {
			t.Errorf("write: %v", err)
		}
	}()
	got := make([]byte, len(payload))
	if _, err := io.ReadFull(peer, got); err != nil {
		t.Fatalf("read back: %v", err)
	}
	if string(got) != string(payload) {
		t.Fatalf("injected %v, want %v", got, payload)
	}
}

func TestWritePacketRejectsInvalidSize(t *testing.T) {
	runner := &recordingRunner{fail: map[string]error{}}
	device, _ := linkDevice(t, runner.run)
	if err := device.WritePacket(nil); err == nil {
		t.Fatal("empty packet must be rejected")
	}
	if err := device.WritePacket(make([]byte, 70000)); err == nil {
		t.Fatal("oversized packet must be rejected")
	}
}

func TestReconcileRoutesAfterCloseFails(t *testing.T) {
	runner := &recordingRunner{fail: map[string]error{}}
	device, _ := linkDevice(t, runner.run)
	if err := device.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	if err := device.ReconcileRoutes([]string{"100.64.0.2"}); err == nil {
		t.Fatal("expected reconcile on a closed device to fail")
	}
}
