import { session } from './session.svelte';
import type { Presence, Snapshot, StateTransition } from '../types';

// Certified state is the authoritative view. Writes replace it with the
// snapshot returned by the committee, so the UI never shows uncommitted state.
export const network = $state<{
  snapshot: Snapshot | null;
  presence: Presence[];
  activity: Snapshot[];
  loading: boolean;
  error: string;
  lastRefresh: number;
}>({
  snapshot: null,
  presence: [],
  activity: [],
  loading: false,
  error: '',
  lastRefresh: 0,
});

export async function refresh(): Promise<void> {
  const client = session.client;
  if (!client) return;
  network.loading = true;
  network.error = '';
  try {
    network.snapshot = await client.snapshot();
    network.lastRefresh = Date.now();
  } catch (caught) {
    network.error = caught instanceof Error ? caught.message : String(caught);
  } finally {
    network.loading = false;
  }
}

// Presence is observed, not certified, so a failure here must not blank the
// page or surface as a hard error.
export async function refreshPresence(): Promise<void> {
  const client = session.client;
  if (!client) return;
  try {
    network.presence = await client.presence();
  } catch {
    network.presence = [];
  }
}

export async function refreshActivity(limit = 100): Promise<void> {
  const client = session.client;
  if (!client) return;
  network.loading = true;
  network.error = '';
  try {
    network.activity = await client.activity(limit);
  } catch (caught) {
    network.error = caught instanceof Error ? caught.message : String(caught);
  } finally {
    network.loading = false;
  }
}

export async function submit(transition: StateTransition): Promise<boolean> {
  const client = session.client;
  if (!client) return false;
  network.loading = true;
  network.error = '';
  try {
    network.snapshot = await client.transition(transition);
    network.lastRefresh = Date.now();
    return true;
  } catch (caught) {
    network.error = caught instanceof Error ? caught.message : String(caught);
    return false;
  } finally {
    network.loading = false;
  }
}

// reset clears cached state so a new manager connection cannot show stale data.
export function reset() {
  network.snapshot = null;
  network.presence = [];
  network.activity = [];
  network.error = '';
  network.lastRefresh = 0;
}

export function presenceFor(peerId: string): Presence | undefined {
  return network.presence.find((observation) => observation.peerId === peerId);
}
