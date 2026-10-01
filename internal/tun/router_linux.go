//go:build linux

package tun

// platformConfigurator returns the iproute2 configurator on Linux.
func platformConfigurator(run Runner, output OutputRunner) RouteConfigurator {
	return ipConfigurator{run: run, output: output}
}
