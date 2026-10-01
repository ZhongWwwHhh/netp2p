//go:build windows

package tun

import "testing"

func TestWindowsConfiguratorCommandSequence(t *testing.T) {
	runner := &recordingRunner{fail: map[string]error{}}
	config := windowsConfigurator{run: runner.run, output: func(string, ...string) (string, error) { return "", nil }}
	if err := config.SetUp("netp2p0"); err != nil {
		t.Fatal(err)
	}
	if err := config.AddAddress("netp2p0", "100.64.0.7"); err != nil {
		t.Fatal(err)
	}
	if err := config.SetMTU("netp2p0", 1280); err != nil {
		t.Fatal(err)
	}
	if err := config.AddRoute("netp2p0", "10.10.0.0/16"); err != nil {
		t.Fatal(err)
	}
	if err := config.DelRoute("netp2p0", "10.10.0.0/16"); err != nil {
		t.Fatal(err)
	}
	if err := config.AddHostRoute("netp2p0", "198.51.100.7", "192.0.2.1"); err != nil {
		t.Fatal(err)
	}
	if err := config.DelHostRoute("198.51.100.7"); err != nil {
		t.Fatal(err)
	}
}
