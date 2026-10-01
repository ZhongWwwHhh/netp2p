//go:build windows

package tun

import "fmt"

// windowsConfigurator drives the Wintun interface with netsh and route.
type windowsConfigurator struct {
	run    Runner
	output OutputRunner
}

func platformConfigurator(run Runner, output OutputRunner) RouteConfigurator {
	return windowsConfigurator{run: run, output: output}
}

func (config windowsConfigurator) SetUp(name string) error {
	return config.run("netsh", "interface", "set", "interface", "name="+name, "admin=enable")
}

func (config windowsConfigurator) AddAddress(name, address string) error {
	return config.run("netsh", "interface", "ipv4", "set", "address",
		"name="+name, "source=static", "addr="+address, "mask=255.255.255.255")
}

func (config windowsConfigurator) SetMTU(name string, mtu int) error {
	return config.run("netsh", "interface", "ipv4", "set", "subinterface", name,
		"mtu="+fmt.Sprint(mtu), "store=persistent")
}

func (config windowsConfigurator) AddRoute(name, cidr string) error {
	return config.run("netsh", "interface", "ipv4", "add", "route", "prefix="+cidr, "interface="+name)
}

func (config windowsConfigurator) DelRoute(name, cidr string) error {
	return config.run("netsh", "interface", "ipv4", "delete", "route", "prefix="+cidr, "interface="+name)
}

func (config windowsConfigurator) AddHostRoute(name, host, gateway string) error {
	return config.run("netsh", "interface", "ipv4", "add", "route",
		"prefix="+host+"/32", "interface="+name, "nexthop="+gateway)
}

func (config windowsConfigurator) DelHostRoute(host string) error {
	return config.run("route", "delete", host)
}

// DefaultGateway is best-effort on Windows; netsh output parsing is not
// implemented, so exit-mode underlay pinning relies on routes already present.
func (config windowsConfigurator) DefaultGateway() string {
	return ""
}
