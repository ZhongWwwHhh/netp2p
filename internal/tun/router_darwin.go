//go:build darwin

package tun

import "fmt"

// darwinConfigurator drives the utun interface with ifconfig and route.
type darwinConfigurator struct {
	run    Runner
	output OutputRunner
}

func platformConfigurator(run Runner, output OutputRunner) RouteConfigurator {
	return darwinConfigurator{run: run, output: output}
}

func (config darwinConfigurator) SetUp(name string) error {
	return config.run("ifconfig", name, "up")
}

func (config darwinConfigurator) AddAddress(name, address string) error {
	return config.run("ifconfig", name, "inet", address, address)
}

func (config darwinConfigurator) SetMTU(name string, mtu int) error {
	return config.run("ifconfig", name, "mtu", fmt.Sprint(mtu))
}

func (config darwinConfigurator) AddRoute(name, cidr string) error {
	return config.run("route", "-n", "add", "-net", cidr, "-interface", name)
}

func (config darwinConfigurator) DelRoute(name, cidr string) error {
	return config.run("route", "-n", "delete", "-net", cidr, "-interface", name)
}

func (config darwinConfigurator) AddHostRoute(name, host, gateway string) error {
	return config.run("route", "-n", "add", "-host", host, "-gateway", gateway)
}

func (config darwinConfigurator) DelHostRoute(host string) error {
	return config.run("route", "-n", "delete", "-host", host)
}

// DefaultGateway reads "route -n get default" and returns the gateway line.
func (config darwinConfigurator) DefaultGateway() string {
	if config.output == nil {
		return ""
	}
	out, err := config.output("route", "-n", "get", "default")
	if err != nil {
		return ""
	}
	for _, line := range splitLines(out) {
		fields := splitFields(line)
		if len(fields) >= 2 && fields[0] == "gateway:" {
			return fields[1]
		}
	}
	return ""
}
