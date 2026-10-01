//go:build !linux && !darwin && !windows

package tun

// platformConfigurator falls back to iproute2-style commands on platforms
// without a dedicated implementation.
func platformConfigurator(run Runner, output OutputRunner) RouteConfigurator {
	return ipConfigurator{run: run, output: output}
}
