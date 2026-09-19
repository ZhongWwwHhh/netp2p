import { apiClient } from './libp2p';
import type { ActivityEntry, Bootstrap, Presence, Snapshot, StateTransition } from './types';

export { apiClient };

export interface ApiClient {
  peerId: { toString(): string };
  setToken(value: string): void;
  stop(): Promise<void>;
  snapshot(): Promise<Snapshot>;
  snapshotAt(height: number): Promise<Snapshot>;
  transition(transition: StateTransition): Promise<Snapshot>;
  presence(): Promise<Presence[]>;
  activity(limit?: number): Promise<ActivityEntry[]>;
}
