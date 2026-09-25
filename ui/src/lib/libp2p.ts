import { createLibp2p } from 'libp2p';
import { circuitRelayTransport } from '@libp2p/circuit-relay-v2';
import { identify } from '@libp2p/identify';
import { http } from '@libp2p/http';
import { webRTCDirect } from '@libp2p/webrtc';
import { multiaddr } from '@multiformats/multiaddr';
import { normalizePresence, normalizeSnapshot } from './normalize';
import { httpResource, joinProtocolPath, resolveProtocolBasePath } from './paths';
import type {
  ActivityEntry, AuditEvent, Bootstrap, Diagnostics, Presence, SessionInfo, Snapshot, StateTransition, User,
} from './types';

export async function createConsoleNode() {
  return createLibp2p({
    transports: [webRTCDirect(), circuitRelayTransport()],
    connectionGater: { denyDialMultiaddr: () => false },
    services: { identify: identify(), http: http() },
  });
}

export async function apiClient(bootstrap: Bootstrap) {
  const node = await createConsoleNode();
  try {
    const transport = node.services.http;
    const hostname = globalThis.location.hostname;
    const addresses = bootstrap.webrtcAddresses
      .map((address) => multiaddr(address))
      .filter((address) => {
        const value = address.toString();
        return !value.includes('/ip4/127.0.0.1/');
      })
      .map((address) => {
        const value = address.toString();
        if (!value.startsWith('/ip4/')) return address;
        return multiaddr(value.replace(/^\/ip4\/[^/]+\//, `/ip4/${hostname}/`));
      });
    let token = '';
    // The well-known metadata advertises the protocol *base* path
    // (e.g. `/netp2p/web-api/1.0.0/`); concrete endpoints must be appended to
    // it so the manager's ServeMux routes to the protocol handler.
    const basePath = await resolveProtocolBasePath(transport, addresses, bootstrap.apiProtocol);
    const request = async (path: string, init: { method?: string; body?: string } = {}) => {
      const resource = addresses.map((address) => httpResource(address, joinProtocolPath(basePath, path)));
      const response = await transport.fetch(resource, {
        method: init.method ?? 'GET',
        body: init.body,
        headers: { authorization: `Bearer ${token}` },
      });
      const text = await response.text();
      const body = text ? JSON.parse(text) : null;
      if (!response.ok) {
        throw new Error((body as { error?: string } | null)?.error ?? `HTTP ${response.status}`);
      }
      return body;
    };
    const snapshot = (body: unknown) => normalizeSnapshot(body as Snapshot);
    return {
      peerId: node.peerId,
      setToken: (value: string) => { token = value; },
      stop: async () => { await node.stop(); },
      snapshot: () => request('/api/v1/snapshot').then(snapshot),
      snapshotAt: (height: number) => request(`/api/v1/snapshot?height=${height}`).then(snapshot),
      transition: (transition: StateTransition) => request('/api/v1/transitions', {
        method: 'POST',
        body: JSON.stringify({ transition }),
      }).then(snapshot),
      presence: () => request('/api/v1/presence').then((body) =>
        normalizePresence((body as { observations?: Presence[] } | null)?.observations)),
      session: () => request('/api/v1/session') as Promise<SessionInfo>,
      users: () => request('/api/v1/users').then((body) =>
        ((body as { users?: User[] } | null)?.users ?? [])),
      activity: (limit = 100) => request(`/api/v1/activity?limit=${limit}`).then((body) =>
        ((body as { entries?: ActivityEntry[] } | null)?.entries ?? []).map(snapshot)),
      events: (limit = 200) => request(`/api/v1/events?limit=${limit}`).then((body) =>
        ((body as { events?: AuditEvent[] } | null)?.events ?? [])),
      diagnostics: () => request('/api/v1/diagnostics') as Promise<Diagnostics>,
    };
  } catch (caught) {
    try {
      await node.stop();
    } catch {
      // ignore shutdown errors while surfacing the original failure
    }
    throw caught;
  }
}
