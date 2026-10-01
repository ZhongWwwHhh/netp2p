package tun

import (
	"fmt"
	"strings"
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
	return config.run("ip", "route", "replace", cidr, "dev", name)
}

func (config ipConfigurator) DelRoute(name, cidr string) error {
	return config.run("ip", "route", "del", cidr, "dev", name)
}

func (config ipConfigurator) AddHostRoute(name, host, gateway string) error {
	return config.run("ip", "route", "replace", host+"/32", "via", gateway)
}

func (config ipConfigurator) DelHostRoute(host string) error {
	return config.run("ip", "route", "del", host+"/32")
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
