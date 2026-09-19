import { apiClient, type ApiClient } from '../api';
import type { Bootstrap, Identity, Operation, SessionInfo } from '../types';

// Single source of truth for the browser's libp2p connection to a manager.
// Every authenticated page reads certified state through this client.
export const session = $state<{
  bootstrap: Bootstrap | null;
  client: ApiClient | null;
  token: string;
  identity: Identity | null;
  permissions: Record<string, Operation[]>;
  connecting: boolean;
  error: string;
  loadError: string;
}>({
  bootstrap: null,
  client: null,
  token: '',
  identity: null,
  permissions: {},
  connecting: false,
  error: '',
  loadError: '',
});

export async function loadBootstrap(): Promise<void> {
  if (session.bootstrap) return;
  try {
    const response = await fetch('/api/bootstrap');
    if (!response.ok) throw new Error(`bootstrap failed: ${response.status}`);
    session.bootstrap = await response.json();
  } catch (caught) {
    session.loadError = caught instanceof Error ? caught.message : String(caught);
  }
}

export async function connect(token: string): Promise<boolean> {
  if (!session.bootstrap) return false;
  session.connecting = true;
  session.error = '';
  let next: ApiClient | null = null;
  try {
    if (session.client) {
      await session.client.stop();
      session.client = null;
    }
    next = await apiClient(session.bootstrap);
    next.setToken(token);
    const info: SessionInfo = await next.session();
    session.client = next;
    session.token = token;
    session.identity = info.identity;
    session.permissions = info.permissions ?? {};
    return true;
  } catch (caught) {
    session.error = caught instanceof Error ? caught.message : String(caught);
    if (next) await next.stop().catch(() => undefined);
    session.client = null;
    return false;
  } finally {
    session.connecting = false;
  }
}

export async function disconnect(): Promise<void> {
  if (session.client) {
    await session.client.stop().catch(() => undefined);
  }
  session.client = null;
  session.token = '';
  session.identity = null;
  session.permissions = {};
}

// can reports whether the current identity may perform the operation. The
// server enforces the same matrix, so this only drives UI affordances.
export function can(module: string, operation: Operation): boolean {
  return session.permissions[module]?.includes(operation) ?? false;
}
