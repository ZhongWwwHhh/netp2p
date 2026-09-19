import { multiaddr, type Multiaddr } from '@multiformats/multiaddr';

/**
 * Joins the protocol base path advertised in the peer's well-known metadata
 * with a concrete endpoint, tolerating trailing/leading slashes in either side.
 */
export function joinProtocolPath(basePath: string, endpoint: string): string {
  const base = basePath.replace(/\/+$/, '');
  const suffix = endpoint.startsWith('/') ? endpoint : `/${endpoint}`;
  const joined = `${base}${suffix}`;
  return joined.startsWith('/') ? joined : `/${joined}`;
}

/**
 * Encodes an HTTP path into the libp2p `/http-path/<encoded>` tuple so the
 * request is routed to the protocol handler with the full path intact.
 */
export function httpResource(address: Multiaddr | string, path: string): Multiaddr {
  const target = typeof address === 'string' ? multiaddr(address) : address;
  return target.encapsulate(`/http-path/${encodeURIComponent(path.replace(/^\//, ''))}`);
}

interface ProtocolPathResolver {
  getProtocolPath?(resource: Multiaddr[], protocol: string): Promise<string>;
}

/**
 * Resolves the base path the server mounted this protocol on. The js-libp2p
 * `@libp2p/http` service exposes `getProtocolPath` at runtime but does not
 * declare it on the public interface, so probe for it and fall back to the
 * protocol id advertised in the bootstrap payload.
 */
export async function resolveProtocolBasePath(
  transport: unknown,
  addresses: Multiaddr[],
  protocol: string,
): Promise<string> {
  const resolver = transport as ProtocolPathResolver;
  if (typeof resolver?.getProtocolPath === 'function') {
    try {
      return await resolver.getProtocolPath(addresses, protocol);
    } catch {
      // Fall through to the advertised protocol id.
    }
  }
  return protocol;
}
