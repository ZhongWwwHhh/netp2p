package tun

import "testing"

func TestIPConfiguratorCommandSequence(t *testing.T) {
	runner := &recordingRunner{fail: map[string]error{}}
	config := ipConfigurator{run: runner.run, output: func(string, ...string) (string, error) {
		return "default via 192.0.2.1 dev eth0\n", nil
	}}
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
	if gateway := config.DefaultGateway(); gateway != "192.0.2.1" {
		t.Fatalf("gateway = %q", gateway)
	}
	want := []string{
		"ip link set dev netp2p0 up",
		"ip addr replace 100.64.0.7/32 dev netp2p0",
		"ip link set dev netp2p0 mtu 1280",
		"ip route replace 10.10.0.0/16 dev netp2p0",
		"ip route del 10.10.0.0/16 dev netp2p0",
		"ip route replace 198.51.100.7/32 via 192.0.2.1",
		"ip route del 198.51.100.7/32",
	}
	got := runner.lines()
	if len(got) != len(want) {
		t.Fatalf("commands = %v, want %v", got, want)
	}
	for index := range want {
		if got[index] != want[index] {
			t.Fatalf("command %d = %q, want %q", index, got[index], want[index])
		}
	}
}
