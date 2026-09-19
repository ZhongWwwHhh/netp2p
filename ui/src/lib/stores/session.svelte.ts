import { apiClient, type ApiClient } from '../api';
import type { Bootstrap } from '../types';

// Single source of truth for the browser's libp2p connection to a manager.
// Every authenticated page reads certified state through this client.
export const session = $state<{
  bootstrap: Bootstrap | null;
  client: ApiClient | null;
  token: string;
  connecting: boolean;
  error: string;
  loadError: string;
}>({
  bootstrap: null,
  client: null,
  token: '',
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
    session.client = next;
    session.token = token;
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
}
