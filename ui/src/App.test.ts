import { describe, expect, it } from 'vitest';
import { multiaddr } from '@multiformats/multiaddr';
import { normalizeSnapshot } from './lib/normalize';
import { httpResource, joinProtocolPath } from './lib/paths';
import type { Snapshot } from './lib/types';
import { QUORUM, verifySnapshot } from './lib/verifier';

const emptyState = {
  networkId: 'net',
  overlayCidr: '100.64.0.0/24',
  peers: [],
  groups: [],
  policies: [],
  routes: [],
  budgets: [],
  setupKeys: [],
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
      signers: ['manager-1', 'manager-2', 'manager-3'],
      signatures: ['a', 'b', 'c'],
    },
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
      state: { ...emptyState, peers: null, routes: null, budgets: null },
    } as unknown as Snapshot;
    const normalized = normalizeSnapshot(withNulls);
    expect(normalized.state.peers).toEqual([]);
    expect(normalized.state.routes).toEqual([]);
    expect(normalized.state.budgets).toEqual([]);
    expect(normalized.state.groups).toEqual([]);
  });
});

describe('snapshot verifier', () => {
  it('accepts a well-formed quorum of known signers', () => {
    expect(verifySnapshot(baseSnapshot())).toBe(true);
    expect(QUORUM).toBe(3);
  });

  it('rejects quorum below 2f+1', () => {
    const snapshot = baseSnapshot();
    snapshot.qc.signers = ['manager-1'];
    snapshot.qc.signatures = ['a'];
    expect(verifySnapshot(snapshot)).toBe(false);
  });

  it('rejects signatures from unknown committee members', () => {
    const snapshot = baseSnapshot();
    snapshot.qc.signers = ['manager-1', 'manager-2', 'ghost'];
    snapshot.qc.signatures = ['a', 'b', 'c'];
    expect(verifySnapshot(snapshot)).toBe(false);
  });

  it('does not throw on malformed input', () => {
    expect(verifySnapshot(null)).toBe(false);
    expect(verifySnapshot({} as Snapshot)).toBe(false);
  });
});
