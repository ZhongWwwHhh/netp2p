package client

import "testing"

func TestHostnameOverride(t *testing.T) {
	client := &Client{}
	if got := client.Hostname(); got == "" {
		t.Fatal("hostname fallback must not be empty")
	}

	client = &Client{hostname: "netp2p-node"}
	if got := client.Hostname(); got != "netp2p-node" {
		t.Fatalf("Hostname() = %q, want netp2p-node", got)
	}
}
