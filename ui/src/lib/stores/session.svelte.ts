import { apiClient, type ApiClient } from '../api';
import type { AuthStatus, Bootstrap, Identity, LoginResponse, Operation, SessionInfo } from '../types';

// Single source of truth for the browser's libp2p connection to a manager.
// Every authenticated page reads certified state through this client.
export const session = $state<{
  bootstrap: Bootstrap | null;
  authStatus: AuthStatus | null;
  client: ApiClient | null;
  token: string;
  identity: Identity | null;
  permissions: Record<string, Operation[]>;
  connecting: boolean;
  error: string;
  loadError: string;
}>({
  bootstrap: null,
  authStatus: null,
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

export async function loadAuthStatus(): Promise<void> {
  try {
    const response = await fetch('/api/v1/auth/status');
    if (!response.ok) throw new Error(`auth status failed: ${response.status}`);
    session.authStatus = await response.json();
  } catch (caught) {
    session.loadError = caught instanceof Error ? caught.message : String(caught);
  }
}

export async function resumeSession(): Promise<boolean> {
  try {
    const response = await fetch('/api/v1/auth/session', { credentials: 'same-origin' });
    if (!response.ok) return false;
    const payload = await response.json() as LoginResponse;
    if (!payload.sessionToken) return false;
    return await connect(payload.sessionToken);
  } catch {
    return false;
  }
}

async function postAuth(path: string, body: unknown): Promise<LoginResponse | null> {
  const response = await fetch(path, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify(body),
    credentials: 'same-origin',
  });
  const payload = await response.json().catch(() => null);
  if (!response.ok) {
    throw new Error((payload as { error?: string } | null)?.error ?? `HTTP ${response.status}`);
  }
  return payload as LoginResponse;
}

export async function loginLocal(email: string, password: string): Promise<LoginResponse | null> {
  session.connecting = true;
  session.error = '';
  try {
    return await postAuth('/api/v1/auth/login', { email, password });
  } catch (caught) {
    session.error = caught instanceof Error ? caught.message : String(caught);
    return null;
  } finally {
    session.connecting = false;
  }
}

export async function bootstrapOwner(
  email: string,
  name: string,
  password: string,
): Promise<LoginResponse | null> {
  session.connecting = true;
  session.error = '';
  try {
    const result = await postAuth('/api/v1/bootstrap/owner', { email, name, password });
    session.authStatus = { needsOwner: false, localLogin: true };
    return result;
  } catch (caught) {
    session.error = caught instanceof Error ? caught.message : String(caught);
    return null;
  } finally {
    session.connecting = false;
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

export async function logout(): Promise<void> {
  if (session.token) {
    await fetch('/api/v1/auth/logout', {
      method: 'POST',
      headers: { authorization: `Bearer ${session.token}` },
      credentials: 'same-origin',
    }).catch(() => undefined);
  }
  await disconnect();
}

// can reports whether the current identity may perform the operation. The
// server enforces the same matrix, so this only drives UI affordances.
export function can(module: string, operation: Operation): boolean {
  return session.permissions[module]?.includes(operation) ?? false;
}
