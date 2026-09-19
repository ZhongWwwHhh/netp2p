package client

import (
	"github.com/netp2p/netp2p/internal/dns"
	"github.com/netp2p/netp2p/internal/model"
)

// DNSUpdater receives the certified DNS view every time a snapshot is applied.
// The concrete implementation is the local resolver in internal/dns.
type DNSUpdater interface {
	Update(dns.Config)
}

// SetDNSResolver attaches a resolver that tracks certified state.
func (client *Client) SetDNSResolver(updater DNSUpdater) {
	client.mu.Lock()
	client.dnsUpdater = updater
	client.mu.Unlock()
}

// SetDNSUpstreams records the host's original resolvers. They are used when no
// certified nameserver matches a query.
func (client *Client) SetDNSUpstreams(upstreams []string) {
	client.mu.Lock()
	client.dnsUpstreams = append([]string(nil), upstreams...)
	client.mu.Unlock()
}

// publishDNS pushes the current certified state to the resolver. It is a no-op
// when no resolver has been attached, so userspace-only clients stay unaffected.
func (client *Client) publishDNS() {
	client.mu.RLock()
	updater := client.dnsUpdater
	state := client.snapshot.State
	self := client.self
	upstreams := append([]string(nil), client.dnsUpstreams...)
	client.mu.RUnlock()
	if updater == nil {
		return
	}
	updater.Update(buildDNSConfig(state, self, upstreams))
}

// buildDNSConfig reduces certified state to the subset this peer should honour.
// Zones and nameservers are scoped by group membership, matching how the rest
// of the access model works.
func buildDNSConfig(state model.NetworkState, self model.PeerRecord, upstreams []string) dns.Config {
	config := dns.Config{
		Domain:      state.Settings.DNSDomain,
		Peers:       dns.PeerLabels(state),
		Upstreams:   upstreams,
		Disabled:    dnsDisabledFor(state, self),
		Nameservers: make([]model.Nameserver, 0, len(state.Nameservers)),
		Zones:       make([]model.DNSZone, 0, len(state.Zones)),
	}
	for _, nameserver := range state.Nameservers {
		if appliesToPeer(nameserver.Groups, self) {
			config.Nameservers = append(config.Nameservers, nameserver)
		}
	}
	for _, zone := range state.Zones {
		if appliesToPeer(zone.Groups, self) {
			config.Zones = append(config.Zones, zone)
		}
	}
	return config
}

// dnsDisabledFor reports whether the peer's groups turn off overlay DNS.
func dnsDisabledFor(state model.NetworkState, self model.PeerRecord) bool {
	if !state.DNSSettings.Disabled {
		return false
	}
	if len(state.DNSSettings.Groups) == 0 {
		return true
	}
	return intersects(state.DNSSettings.Groups, self.Groups)
}

// appliesToPeer reports whether a group scoped object applies to the peer. An
// empty scope applies to everyone.
func appliesToPeer(scope []string, self model.PeerRecord) bool {
	if len(scope) == 0 {
		return true
	}
	return intersects(scope, self.Groups)
}

func intersects(left, right []string) bool {
	for _, a := range left {
		for _, b := range right {
			if a == b {
				return true
			}
		}
	}
	return false
}
