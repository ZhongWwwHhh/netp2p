//go:build darwin

package tun

import "testing"

func TestDarwinConfiguratorCommandSequence(t *testing.T) {
	runner := &recordingRunner{fail: map[string]error{}}
	config := darwinConfigurator{run: runner.run, output: func(string, ...string) (string, error) {
		return "   gateway: 192.0.2.1\n", nil
	}}
	if err := config.SetUp("utun4"); err != nil {
		t.Fatal(err)
	}
	if err := config.AddAddress("utun4", "100.64.0.7"); err != nil {
		t.Fatal(err)
	}
	if err := config.SetMTU("utun4", 1280); err != nil {
		t.Fatal(err)
	}
	if err := config.AddRoute("utun4", "10.10.0.0/16"); err != nil {
		t.Fatal(err)
	}
	if err := config.DelRoute("utun4", "10.10.0.0/16"); err != nil {
		t.Fatal(err)
	}
	if err := config.AddHostRoute("utun4", "198.51.100.7", "192.0.2.1"); err != nil {
		t.Fatal(err)
	}
	if err := config.DelHostRoute("198.51.100.7"); err != nil {
		t.Fatal(err)
	}
	if gateway := config.DefaultGateway(); gateway != "192.0.2.1" {
		t.Fatalf("gateway = %q", gateway)
	}
}
