package client

import (
	"path/filepath"

	"github.com/netp2p/netp2p/internal/exitnode"
	"github.com/netp2p/netp2p/internal/tun"
)

// Option customizes the client at construction time.
type Option func(*Client)

// WithStateDir enables local persistence. It stores the last validated snapshot
// and local identity in state.json, and the last-known-good path/admission
// conclusions in paths.json. An empty directory disables persistence, which is
// the default when no option is passed.
func WithStateDir(dir string) Option {
	return func(client *Client) {
		if dir == "" {
			return
		}
		client.pathStore = loadPathStore(filepath.Join(dir, "paths.json"), defaultPathTTL)
		client.stateStore = loadClientStateStore(filepath.Join(dir, "state.json"))
	}
}

// WithManagerFailover adds additional manager endpoints. The endpoint passed
// to New remains the first candidate; this option appends the seed committee's
// addresses so a client can continue after one manager becomes unavailable.
func WithManagerFailover(addresses ...string) Option {
	return func(client *Client) {
		for _, address := range addresses {
			if address != "" {
				client.managerAddresses = append(client.managerAddresses, address)
			}
		}
	}
}

// WithHostname overrides the stable peer name sent during login. It is useful
// in containers and long-lived deployments where the OS hostname is ephemeral.
func WithHostname(hostname string) Option {
	return func(client *Client) {
		client.hostname = hostname
	}
}

// WithPosture sets the declarative capability labels this peer advertises at
// registration. Empty labels are ignored.
func WithPosture(labels []string) Option {
	cleaned := make([]string, 0, len(labels))
	for _, label := range labels {
		if label != "" {
			cleaned = append(cleaned, label)
		}
	}
	return func(client *Client) {
		client.posture = cleaned
	}
}

// WithExitForwarding enables subnet/exit gateway duties for this client. The
// overlay CIDR is the source range that gets masqueraded; run executes the
// iptables/sysctl commands (nil uses the real runner).
func WithExitForwarding(overlayCIDR string, run tun.Runner) Option {
	return func(client *Client) {
		if overlayCIDR == "" {
			return
		}
		client.exitReconciler = exitnode.New(overlayCIDR, run)
		client.exitNodeEnabled = true
	}
}

// EnableExitForwarding turns on subnet/exit gateway duties after construction,
// once the certified overlay CIDR is known. It is a no-op for an empty CIDR.
func (client *Client) EnableExitForwarding(overlayCIDR string, run tun.Runner) {
	if overlayCIDR == "" {
		return
	}
	client.mu.Lock()
	client.exitReconciler = exitnode.New(overlayCIDR, run)
	client.exitNodeEnabled = true
	client.mu.Unlock()
	client.reconcileExitNode()
}

// Close releases persistence resources, flushing pending state to disk.
func (client *Client) Close() {
	if client.pathStore != nil {
		client.pathStore.close()
	}
	if client.stateStore != nil {
		state := client.persistedStateForClose()
		// Do not overwrite another local identity's state with an empty record.
		if state.LocalPeerID == client.stateStore.data.LocalPeerID || state.Snapshot.Height > 0 {
			_ = client.stateStore.save(state)
		}
	}
	if client.exitReconciler != nil {
		_ = client.exitReconciler.Close()
	}
}
