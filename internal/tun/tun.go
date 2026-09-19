// Package tun attaches an overlay peer to the operating system network stack
// through a TUN device.
//
// TUN is only the operating system attachment point: packets read from the
// device still travel to remote peers over libp2p streams. Creating the device
// and configuring it requires CAP_NET_ADMIN, so callers must be able to fall
// back to the userspace packet endpoint.
package tun

import (
	"errors"
	"fmt"
	"io"
	"os/exec"
	"sort"
	"strings"
	"sync"

	"github.com/netp2p/netp2p/internal/packet"
)

// ErrUnsupported reports that this platform has no TUN implementation.
var ErrUnsupported = errors.New("tun devices are not supported on this platform")

// DefaultMTU matches NetBird's interface MTU. QUIC carries the overlay, and a
// 1280-byte MTU keeps overlay packets inside a single libp2p frame without
// fragmentation on typical paths.
const DefaultMTU = 1280

// Runner executes an external command. It exists so route reconciliation can be
// tested without touching the host network.
type Runner func(name string, args ...string) error

// RunCommand executes a command and returns its combined output on failure.
func RunCommand(name string, args ...string) error {
	output, err := exec.Command(name, args...).CombinedOutput()
	if err != nil {
		message := strings.TrimSpace(string(output))
		if message == "" {
			return fmt.Errorf("%s %s: %w", name, strings.Join(args, " "), err)
		}
		return fmt.Errorf("%s %s: %w: %s", name, strings.Join(args, " "), err, message)
	}
	return nil
}

// Device is a TUN network interface carrying overlay IPv4 packets.
type Device struct {
	file   io.ReadWriteCloser
	name   string
	run    Runner
	closed bool

	mu     sync.Mutex
	routes map[string]struct{}
}

// Name returns the interface name, which the kernel may have adjusted when the
// requested name was taken.
func (device *Device) Name() string { return device.name }

// ReadPacket reads one IPv4 packet from the device.
func (device *Device) ReadPacket() ([]byte, error) {
	buffer := make([]byte, packet.MaxPacketSize)
	read, err := device.file.Read(buffer)
	if err != nil {
		return nil, err
	}
	result := make([]byte, read)
	copy(result, buffer[:read])
	return result, nil
}

// WritePacket injects one IPv4 packet into the local network stack.
func (device *Device) WritePacket(payload []byte) error {
	if len(payload) == 0 || len(payload) > packet.MaxPacketSize {
		return fmt.Errorf("invalid packet size %d", len(payload))
	}
	_, err := device.file.Write(payload)
	return err
}

func (device *Device) Close() error {
	device.mu.Lock()
	if device.closed {
		device.mu.Unlock()
		return nil
	}
	device.closed = true
	device.mu.Unlock()
	return device.file.Close()
}

// Configure brings the interface up with the peer's overlay address.
func (device *Device) Configure(address string, mtu int) error {
	if address == "" {
		return fmt.Errorf("overlay address is required")
	}
	if mtu <= 0 {
		mtu = DefaultMTU
	}
	if err := device.run("ip", "link", "set", "dev", device.name, "up"); err != nil {
		return err
	}
	// "replace" is idempotent, so reconfiguring on reconnect cannot fail with
	// an address-already-exists error.
	if err := device.run("ip", "addr", "replace", address+"/32", "dev", device.name); err != nil {
		return err
	}
	return device.run("ip", "link", "set", "dev", device.name, "mtu", fmt.Sprint(mtu))
}

// ReconcileRoutes makes the interface's /32 routes match exactly the peers the
// policy currently allows, adding new ones and removing stale ones. Only routes
// this device installed are ever removed.
func (device *Device) ReconcileRoutes(overlayIPs []string) error {
	desired := make(map[string]struct{}, len(overlayIPs))
	for _, address := range overlayIPs {
		if address == "" {
			continue
		}
		desired[address] = struct{}{}
	}

	device.mu.Lock()
	if device.closed {
		device.mu.Unlock()
		return fmt.Errorf("tun device is closed")
	}
	current := device.routes
	device.routes = make(map[string]struct{}, len(desired))
	device.mu.Unlock()

	var firstError error
	record := func(err error) {
		if err != nil && firstError == nil {
			firstError = err
		}
	}

	added := make([]string, 0, len(desired))
	for address := range desired {
		if _, exists := current[address]; exists {
			// Already routed; keep it without re-running ip.
			device.mu.Lock()
			device.routes[address] = struct{}{}
			device.mu.Unlock()
			continue
		}
		added = append(added, address)
	}
	sort.Strings(added)
	for _, address := range added {
		if err := device.run("ip", "route", "replace", address+"/32", "dev", device.name); err != nil {
			record(err)
			continue
		}
		device.mu.Lock()
		device.routes[address] = struct{}{}
		device.mu.Unlock()
	}

	removed := make([]string, 0)
	for address := range current {
		if _, exists := desired[address]; !exists {
			removed = append(removed, address)
		}
	}
	sort.Strings(removed)
	for _, address := range removed {
		// A route may already be gone if the interface was recreated; a failure
		// here must not prevent the remaining removals.
		record(device.run("ip", "route", "del", address+"/32", "dev", device.name))
	}
	return firstError
}

// Routes reports the routes the device currently believes it installed. It
// exists for tests and diagnostics.
func (device *Device) Routes() []string {
	device.mu.Lock()
	defer device.mu.Unlock()
	result := make([]string, 0, len(device.routes))
	for address := range device.routes {
		result = append(result, address)
	}
	sort.Strings(result)
	return result
}

// Open creates a TUN device with the requested name and returns a sink that can
// be used as the client's packet endpoint.
func Open(name string, run Runner) (*Device, error) {
	if run == nil {
		run = RunCommand
	}
	file, actualName, err := openDevice(name)
	if err != nil {
		return nil, err
	}
	return &Device{file: file, name: actualName, run: run, routes: make(map[string]struct{})}, nil
}
