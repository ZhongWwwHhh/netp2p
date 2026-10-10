package tun

import (
	"fmt"
	"strconv"
	"strings"
)

// The table and rule preference are deliberately tied together and kept far
// from the well-known tables operators normally customize.
const (
	managedRouteTable     = 20048
	managedRulePreference = 20048
)

func splitFields(line string) []string { return strings.Fields(line) }

func splitLines(text string) []string { return strings.Split(text, "\n") }

// RouteConfigurator applies interface addressing and routing for one platform.
// The Linux implementation shells out to iproute2; other platforms use their
// native tools. Keeping it behind an interface lets Device stay platform
// agnostic and keeps the command sequences unit-testable.
type RouteConfigurator interface {
	SetUp(name string) error
	AddAddress(name, address string) error
	SetMTU(name string, mtu int) error
	AddRoute(name, cidr string) error
	DelRoute(name, cidr string) error
	AddHostRoute(name, host, gateway string) error
	DelHostRoute(host string) error
	DefaultGateway() string
}

// routeStateConfigurator exposes exact route state on platforms that support
// non-destructive default takeover. Linux is the platform where the old
// default-route replacement was destructive.
type routeStateConfigurator interface {
	DefaultRoute() string
	HostRoute(host string) string
	RestoreDefaultRoute(route string) error
	RestoreHostRoute(host, route string) error
}

// ipConfigurator is the iproute2 implementation shared by Linux and any host
// that provides the ip command.
type ipConfigurator struct {
	run    Runner
	output OutputRunner
}

func (config ipConfigurator) SetUp(name string) error {
	return config.run("ip", "link", "set", "dev", name, "up")
}

func (config ipConfigurator) AddAddress(name, address string) error {
	// "replace" is idempotent, so reconfiguring on reconnect cannot fail with
	// an address-already-exists error.
	return config.run("ip", "addr", "replace", address+"/32", "dev", name)
}

func (config ipConfigurator) SetMTU(name string, mtu int) error {
	return config.run("ip", "link", "set", "dev", name, "mtu", fmt.Sprint(mtu))
}

func (config ipConfigurator) AddRoute(name, cidr string) error {
	if cidr == "0.0.0.0/0" {
		return config.addManagedDefault(name)
	}
	return config.run("ip", "route", "replace", cidr, "dev", name)
}

func (config ipConfigurator) DelRoute(name, cidr string) error {
	if cidr == "0.0.0.0/0" {
		return config.deleteManagedDefault(name)
	}
	return config.run("ip", "route", "del", cidr, "dev", name)
}

func (config ipConfigurator) AddHostRoute(name, host, gateway string) error {
	// Preserve an existing host route exactly inside the managed table. Merely
	// rewriting it through the default gateway would change on-link semantics.
	if existing := config.HostRoute(host); existing != "" {
		fields := splitFields(existing)
		if len(fields) > 0 && (fields[0] == host || fields[0] == host+"/32") {
			return config.run("ip", append(append([]string{"route", "replace"}, fields...),
				"table", strconv.Itoa(managedRouteTable))...)
		}
	}
	return config.run("ip", "route", "replace", host+"/32", "via", gateway,
		"table", strconv.Itoa(managedRouteTable))
}

func (config ipConfigurator) DelHostRoute(host string) error {
	return config.run("ip", "route", "del", host+"/32", "table", strconv.Itoa(managedRouteTable))
}

// DefaultGateway reads "ip route show default" and returns the first gateway.
func (config ipConfigurator) DefaultGateway() string {
	if config.output == nil {
		return ""
	}
	out, err := config.output("ip", "route", "show", "default")
	if err != nil {
		return ""
	}
	fields := strings.Fields(out)
	for index, field := range fields {
		if field == "via" && index+1 < len(fields) {
			return fields[index+1]
		}
	}
	return ""
}

// DefaultRoute returns the exact first main-table default route, including
// gateway, device, protocol, source, and metric fields.
func (config ipConfigurator) DefaultRoute() string {
	if config.output == nil {
		return ""
	}
	out, err := config.output("ip", "route", "show", "default")
	if err != nil {
		return ""
	}
	for _, line := range splitLines(out) {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "default ") || line == "default" {
			return line
		}
	}
	return ""
}

// HostRoute returns the exact current main-table route for one host.
func (config ipConfigurator) HostRoute(host string) string {
	if config.output == nil {
		return ""
	}
	out, err := config.output("ip", "route", "show", host)
	if err != nil {
		return ""
	}
	line := strings.TrimSpace(splitLines(out)[0])
	if line == "" || strings.HasPrefix(line, "Error") {
		return ""
	}
	return line
}

// RestoreDefaultRoute reinstates an exact saved route. With dedicated-table
// takeover this is normally a no-op because the original route was never
// replaced, but it repairs the host if another actor changed it while NetP2P
// was responsible for cleanup.
func (config ipConfigurator) RestoreDefaultRoute(route string) error {
	if route == "" {
		return nil
	}
	fields := splitFields(route)
	if len(fields) == 0 || fields[0] != "default" {
		return fmt.Errorf("invalid saved default route %q", route)
	}
	return config.run("ip", append([]string{"route", "replace"}, fields...)...)
}

// RestoreHostRoute reinstates a saved host route, or removes the host route
// when no route existed before takeover.
func (config ipConfigurator) RestoreHostRoute(host, route string) error {
	if route == "" {
		return config.run("ip", "route", "del", host+"/32")
	}
	fields := splitFields(route)
	if len(fields) == 0 || fields[0] != host && fields[0] != host+"/32" {
		return fmt.Errorf("invalid saved host route %q for %s", route, host)
	}
	return config.run("ip", append([]string{"route", "replace"}, fields...)...)
}

func (config ipConfigurator) addManagedDefault(name string) error {
	table := strconv.Itoa(managedRouteTable)
	// A crashed predecessor may have left host pins in the dedicated table.
	// Flushing only this table recovers them without touching the main table.
	if err := config.run("ip", "route", "flush", "table", table); err != nil {
		return err
	}
	if err := config.run("ip", "route", "replace", "default", "dev", name, "table", table); err != nil {
		return err
	}
	exists, err := config.managedRuleExists()
	if err != nil {
		return err
	}
	if exists {
		return nil
	}
	return config.run("ip", "rule", "add", "pref", strconv.Itoa(managedRulePreference),
		"lookup", table)
}

func (config ipConfigurator) deleteManagedDefault(name string) error {
	table := strconv.Itoa(managedRouteTable)
	routeErr := config.run("ip", "route", "del", "default", "dev", name, "table", table)
	ruleErr := config.run("ip", "rule", "del", "pref", strconv.Itoa(managedRulePreference),
		"lookup", table)
	if routeErr != nil && ruleErr != nil {
		return routeErr
	}
	return nil
}

func (config ipConfigurator) managedRuleExists() (bool, error) {
	if config.output == nil {
		return false, fmt.Errorf("ip rule discovery is unavailable")
	}
	out, err := config.output("ip", "rule", "show")
	if err != nil {
		return false, err
	}
	want := strconv.Itoa(managedRulePreference)
	lookup := strconv.Itoa(managedRouteTable)
	for _, line := range splitLines(out) {
		fields := splitFields(line)
		hasPreference := false
		hasLookup := false
		for index, field := range fields {
			if (field == want || field == want+":") && (index == 0 || fields[index-1] == "pref") {
				hasPreference = true
			}
			if field == lookup && index > 0 && fields[index-1] == "lookup" {
				hasLookup = true
			}
		}
		if hasPreference && hasLookup {
			return true, nil
		}
	}
	return false, nil
}
