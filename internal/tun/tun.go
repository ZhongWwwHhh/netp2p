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

// OutputRunner executes an external command and returns its stdout. It is used
// to discover the current default route before taking over 0.0.0.0/0.
type OutputRunner func(name string, args ...string) (string, error)

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

// RunCommandOutput executes a command and returns its stdout. It is the
// discovery counterpart to RunCommand.
func RunCommandOutput(name string, args ...string) (string, error) {
	output, err := exec.Command(name, args...).Output()
	if err != nil {
		return "", err
	}
	return string(output), nil
}

// Device is a TUN network interface carrying overlay IPv4 packets.
type Device struct {
	file   io.ReadWriteCloser
	name   string
	run    Runner
	output OutputRunner
	config RouteConfigurator
	closed bool

	mu       sync.Mutex
	routes   map[string]struct{}
	networks map[string]struct{}
	pinned   map[string]struct{}

	underlayHosts []string
	defaultRoute  string
	hostRoutes    map[string]string
}

// configurator returns the platform route configurator, defaulting to the
// platform implementation built from the runner and output hooks.
func (device *Device) configurator() RouteConfigurator {
	if device.config != nil {
		return device.config
	}
	return platformConfigurator(device.run, device.output)
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
	routes := copySet(device.routes)
	networks := copySet(device.networks)
	pinned := copySet(device.pinned)
	defaultRoute := device.defaultRoute
	hostRoutes := copyStringMap(device.hostRoutes)
	device.mu.Unlock()
	cleanupErr := device.cleanupManagedRoutes(routes, networks, pinned, defaultRoute, hostRoutes)
	closeErr := device.file.Close()
	if cleanupErr != nil {
		return cleanupErr
	}
	return closeErr
}

// Configure brings the interface up with the peer's overlay address.
func (device *Device) Configure(address string, mtu int) error {
	if address == "" {
		return fmt.Errorf("overlay address is required")
	}
	if mtu <= 0 {
		mtu = DefaultMTU
	}
	config := device.configurator()
	if err := config.SetUp(device.name); err != nil {
		return err
	}
	if err := config.AddAddress(device.name, address); err != nil {
		return err
	}
	return config.SetMTU(device.name, mtu)
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
		if err := device.configurator().AddRoute(device.name, address+"/32"); err != nil {
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
		record(device.configurator().DelRoute(device.name, address+"/32"))
	}
	return firstError
}

// SetUnderlayHosts records the manager/IdP destinations that must keep using
// the physical default route even while 0.0.0.0/0 is pointed at the overlay.
func (device *Device) SetUnderlayHosts(hosts []string) {
	device.mu.Lock()
	device.underlayHosts = append([]string(nil), hosts...)
	device.mu.Unlock()
}

// ReconcileNetworks installs a route for each certified subnet/exit CIDR and
// removes routes that are no longer advertised. Installing 0.0.0.0/0 also pins
// the recorded underlay hosts to the original default gateway so the tunnel
// itself keeps working.
func (device *Device) ReconcileNetworks(cidrs []string) error {
	desired := make(map[string]struct{}, len(cidrs))
	capturesDefault := false
	for _, cidr := range cidrs {
		cidr = strings.TrimSpace(cidr)
		if cidr == "" {
			continue
		}
		desired[cidr] = struct{}{}
		if cidr == "0.0.0.0/0" {
			capturesDefault = true
		}
	}

	device.mu.Lock()
	if device.closed {
		device.mu.Unlock()
		return fmt.Errorf("tun device is closed")
	}
	current := device.networks
	device.networks = make(map[string]struct{}, len(desired))
	pinned := device.pinned
	device.pinned = make(map[string]struct{})
	hosts := append([]string(nil), device.underlayHosts...)
	if device.hostRoutes == nil {
		device.hostRoutes = make(map[string]string)
	}
	hostRoutes := device.hostRoutes
	defaultRoute := device.defaultRoute
	if capturesDefault {
		if state, ok := device.configurator().(routeStateConfigurator); ok && defaultRoute == "" {
			defaultRoute = state.DefaultRoute()
			device.defaultRoute = defaultRoute
		}
	}
	device.mu.Unlock()

	var firstError error
	record := func(err error) {
		if err != nil && firstError == nil {
			firstError = err
		}
	}

	if capturesDefault {
		device.pinUnderlay(hosts, pinned, hostRoutes, record)
	}

	added := make([]string, 0, len(desired))
	for cidr := range desired {
		if _, exists := current[cidr]; exists {
			device.mu.Lock()
			device.networks[cidr] = struct{}{}
			device.mu.Unlock()
			continue
		}
		added = append(added, cidr)
	}
	sort.Slice(added, func(i, j int) bool {
		// Install more specific prefixes before 0.0.0.0/0 so the default route
		// never briefly swallows overlay traffic.
		if (added[i] == "0.0.0.0/0") != (added[j] == "0.0.0.0/0") {
			return added[j] == "0.0.0.0/0"
		}
		return added[i] < added[j]
	})
	for _, cidr := range added {
		if err := device.configurator().AddRoute(device.name, cidr); err != nil {
			record(err)
			continue
		}
		device.mu.Lock()
		device.networks[cidr] = struct{}{}
		device.mu.Unlock()
	}

	removed := make([]string, 0)
	for cidr := range current {
		if _, exists := desired[cidr]; !exists {
			removed = append(removed, cidr)
		}
	}
	sort.Strings(removed)
	for _, cidr := range removed {
		record(device.configurator().DelRoute(device.name, cidr))
	}
	if !capturesDefault {
		if _, hadDefault := current["0.0.0.0/0"]; hadDefault {
			// Leaving exit mode: drop the underlay pins we installed, once the
			// overlay default route is gone.
			for host := range pinned {
				record(device.configurator().DelHostRoute(host))
			}
			record(device.restoreCapturedRoutes(defaultRoute, hostRoutes))
			device.mu.Lock()
			device.defaultRoute = ""
			device.hostRoutes = make(map[string]string)
			device.mu.Unlock()
		}
	}
	return firstError
}

// pinUnderlay installs host routes in the managed table so the manager control
// stream survives a 0.0.0.0/0 overlay route.
func (device *Device) pinUnderlay(hosts []string, previous map[string]struct{}, hostRoutes map[string]string, record func(error)) {
	for host := range previous {
		if !containsString(hosts, host) {
			record(device.configurator().DelHostRoute(host))
		}
	}
	if len(hosts) == 0 {
		return
	}
	gateway := device.defaultGateway()
	if gateway == "" {
		return
	}
	state, hasState := device.configurator().(routeStateConfigurator)
	for _, host := range hosts {
		host = strings.TrimSpace(host)
		if host == "" {
			continue
		}
		if hasState {
			if _, saved := hostRoutes[host]; !saved {
				hostRoutes[host] = state.HostRoute(host)
			}
		}
		if err := device.configurator().AddHostRoute(device.name, host, gateway); err != nil {
			record(err)
			continue
		}
		device.mu.Lock()
		device.pinned[host] = struct{}{}
		device.mu.Unlock()
	}
}

func (device *Device) cleanupManagedRoutes(routes, networks, pinned map[string]struct{}, defaultRoute string, hostRoutes map[string]string) error {
	var firstError error
	record := func(err error) {
		if err != nil && firstError == nil {
			firstError = err
		}
	}
	for host := range pinned {
		record(device.configurator().DelHostRoute(host))
	}
	for cidr := range networks {
		record(device.configurator().DelRoute(device.name, cidr))
	}
	for address := range routes {
		record(device.configurator().DelRoute(device.name, address+"/32"))
	}
	record(device.restoreCapturedRoutes(defaultRoute, hostRoutes))
	return firstError
}

func (device *Device) restoreCapturedRoutes(defaultRoute string, hostRoutes map[string]string) error {
	state, ok := device.configurator().(routeStateConfigurator)
	if !ok || defaultRoute == "" && len(hostRoutes) == 0 {
		return nil
	}
	var firstError error
	record := func(err error) {
		if err != nil && firstError == nil {
			firstError = err
		}
	}
	if defaultRoute != "" {
		record(state.RestoreDefaultRoute(defaultRoute))
	}
	for host, route := range hostRoutes {
		record(state.RestoreHostRoute(host, route))
	}
	return firstError
}

func copySet(values map[string]struct{}) map[string]struct{} {
	result := make(map[string]struct{}, len(values))
	for value := range values {
		result[value] = struct{}{}
	}
	return result
}

func copyStringMap(values map[string]string) map[string]string {
	result := make(map[string]string, len(values))
	for key, value := range values {
		result[key] = value
	}
	return result
}

func containsString(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}

// defaultGateway reads "ip route show default" and returns the first gateway.
func (device *Device) defaultGateway() string {
	return device.configurator().DefaultGateway()
}

// Networks reports the CIDR routes the device currently believes it installed.
func (device *Device) Networks() []string {
	device.mu.Lock()
	defer device.mu.Unlock()
	result := make([]string, 0, len(device.networks))
	for cidr := range device.networks {
		result = append(result, cidr)
	}
	sort.Strings(result)
	return result
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
	return &Device{
		file: file, name: actualName, run: run, output: RunCommandOutput,
		routes: make(map[string]struct{}), networks: make(map[string]struct{}),
		pinned: make(map[string]struct{}), hostRoutes: make(map[string]string),
	}, nil
}
