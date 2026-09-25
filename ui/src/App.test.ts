import { describe, expect, it } from 'vitest';
import { multiaddr } from '@multiformats/multiaddr';
import { bitrateLabel, bytesLabel, percent, relativeTime, shortPeerId } from './lib/format';
import { normalizePresence, normalizeSnapshot } from './lib/normalize';
import { httpResource, joinProtocolPath } from './lib/paths';
import { QuorumSize } from './lib/quorum';
import { defaultPath, routeTitle, routes } from './lib/router.svelte';
import type { Presence, Snapshot, StateTransition } from './lib/types';
import { verifySnapshot } from './lib/verifier';

const emptyState = {
  networkId: 'net',
  overlayCidr: '100.64.0.0/24',
  peers: [],
  users: [],
  groups: [],
  policies: [],
  routes: [],
  budgets: [],
  setupKeys: [],
  nameservers: [],
  zones: [],
  dnsSettings: { disabled: false, groups: [] },
  settings: {},
  assignments: [],
  nextIpOffset: 1,
};

function committee(size: number) {
  return Array.from({ length: size }, (_, index) => ({
    id: `manager-${index + 1}`,
    peerId: `peer-${index + 1}`,
    address: `/dns4/manager-${index + 1}/udp/4001/quic-v1`,
    publicKey: 'AAAA',
  }));
}

function baseSnapshot(): Snapshot {
  return {
    epoch: 1,
    height: 1,
    stateHash: 'hash',
    state: { ...emptyState },
    committee: committee(4),
    qc: {
      height: 1,
      round: 0,
      stateHash: 'hash',
      transitionHash: 'transition',
      signers: ['manager-1', 'manager-2', 'manager-3'],
      signatures: ['a', 'b', 'c'],
    },
    transition: { type: 'upsert_group', group: { id: 'g' } },
    leaderId: 'manager-2',
  };
}

describe('protocol path construction', () => {
  it('joins the advertised base path with an endpoint regardless of slashes', () => {
    expect(joinProtocolPath('/netp2p/web-api/1.0.0/', '/api/v1/snapshot'))
      .toBe('/netp2p/web-api/1.0.0/api/v1/snapshot');
    expect(joinProtocolPath('/netp2p/web-api/1.0.0', 'api/v1/snapshot'))
      .toBe('/netp2p/web-api/1.0.0/api/v1/snapshot');
  });

  it('encodes the full path into the http-path tuple', () => {
    const address = multiaddr('/ip4/127.0.0.1/udp/4101/webrtc-direct');
    const resource = httpResource(address, '/netp2p/web-api/1.0.0/api/v1/snapshot');
    expect(resource.toString()).toContain(
      '/http-path/netp2p%2Fweb-api%2F1.0.0%2Fapi%2Fv1%2Fsnapshot',
    );
  });
});

describe('snapshot normalization', () => {
  it('turns null collections into arrays', () => {
    const snapshot = baseSnapshot();
    const withNulls = {
      ...snapshot,
      state: { ...emptyState, peers: null, routes: null, budgets: null, nameservers: null, zones: null, dnsSettings: null },
    } as unknown as Snapshot;
    const normalized = normalizeSnapshot(withNulls);
    expect(normalized.state.peers).toEqual([]);
    expect(normalized.state.routes).toEqual([]);
    expect(normalized.state.nameservers).toEqual([]);
    expect(normalized.state.zones).toEqual([]);
    expect(normalized.state.dnsSettings.groups).toEqual([]);
  });

  it('normalizes user and settings collections', () => {
    const snapshot = baseSnapshot();
    const withNulls = {
      ...snapshot,
      state: { ...emptyState, users: null, settings: null },
    } as unknown as Snapshot;
    const normalized = normalizeSnapshot(withNulls);
    expect(normalized.state.users).toEqual([]);
    expect(normalized.state.settings).toEqual({});
  });

  it('turns null presence into an empty list', () => {
    expect(normalizePresence(null)).toEqual([]);
    expect(normalizePresence([{ peerId: 'p', online: true } as Presence])).toHaveLength(1);
  });
});

describe('routing table', () => {
  it('has a dedicated page for every sidebar entry', () => {
    for (const route of routes) {
      expect(route.path.startsWith('/')).toBe(true);
      expect(route.group.length).toBeGreaterThan(0);
    }
  });

  it('falls back to a real page for unknown paths', () => {
    expect(routes.some((route) => route.path === defaultPath)).toBe(true);
    expect(routeTitle(defaultPath)).toBe('Peers');
    expect(routeTitle('/nope')).toBe('Console');
  });

  it('exposes the SSO users page', () => {
    expect(routes.some((route) => route.path === '/users')).toBe(true);
  });
});

describe('formatting', () => {
  it('renders human readable sizes, rates and recency', () => {
    expect(bytesLabel(0)).toBe('0 B');
    expect(bytesLabel(2048)).toBe('2.0 KB');
    expect(bitrateLabel(0)).toBe('unlimited');
    expect(bitrateLabel(1_500_000)).toBe('1.5 Mbps');
    expect(percent(50, 100)).toBe(50);
    expect(percent(1, 0)).toBe(0);
    expect(relativeTime(undefined)).toBe('never');
    expect(relativeTime(Date.now())).toBe('just now');
    expect(shortPeerId('1234567890abcdef', 6)).toBe('123456…');
  });
});

describe('transition payload shapes', () => {
  it('builds the DNS and resource transitions the API expects', () => {
    const transitions: StateTransition[] = [
      { type: 'upsert_nameserver', nameserver: { id: 'ns', name: 'ns', groups: [], servers: ['1.1.1.1'], enabled: true } },
      { type: 'remove_nameserver', targetId: 'ns' },
      { type: 'upsert_zone', zone: { id: 'z', domain: 'internal', records: [], enabled: true } },
      { type: 'remove_zone', targetId: 'z' },
      { type: 'update_dns_settings', dnsSettings: { disabled: true, groups: [] } },
      { type: 'upsert_route', route: { id: 'r', destination: '10.0.0.0/8', routingGroup: 'g', distributionGroups: [], metric: 1 } },
      { type: 'upsert_budget', budget: { id: 'b', subjectType: 'group', subjectId: 'g', dailyBytes: 0, monthlyBytes: 0, peakBps: 0, relayCostLimit: 0, onExhausted: 'block', usedDailyBytes: 0, usedMonthlyBytes: 0 } },
      { type: 'remove_setup_key', targetId: 'k' },
    ];
    expect(transitions.map((transition) => transition.type)).toContain('update_dns_settings');
    expect(JSON.parse(JSON.stringify(transitions[0]))).toHaveProperty('nameserver.id', 'ns');
  });
});

describe('snapshot verifier', () => {
  it('accepts a well-formed quorum of known signers', () => {
    expect(verifySnapshot(baseSnapshot())).toBe(true);
    expect(QuorumSize).toBe(3);
  });

  it('rejects a sub-quorum or unknown signers', () => {
    const weak = baseSnapshot();
    weak.qc.signers = ['manager-1'];
    weak.qc.signatures = ['a'];
    expect(verifySnapshot(weak)).toBe(false);

    const foreign = baseSnapshot();
    foreign.qc.signers = ['manager-1', 'manager-2', 'ghost'];
    expect(verifySnapshot(foreign)).toBe(false);
  });

  it('does not throw on malformed input', () => {
    expect(verifySnapshot(null)).toBe(false);
    expect(verifySnapshot({} as Snapshot)).toBe(false);
  });
});
