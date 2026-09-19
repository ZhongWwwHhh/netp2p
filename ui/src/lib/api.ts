import { apiClient } from './libp2p';
import type { ActivityEntry, Bootstrap, Presence, SessionInfo, Snapshot, StateTransition, User } from './types';

export { apiClient };

export interface ApiClient {
  peerId: { toString(): string };
  setToken(value: string): void;
  stop(): Promise<void>;
  snapshot(): Promise<Snapshot>;
  snapshotAt(height: number): Promise<Snapshot>;
  transition(transition: StateTransition): Promise<Snapshot>;
  presence(): Promise<Presence[]>;
  session(): Promise<SessionInfo>;
  users(): Promise<User[]>;
  activity(limit?: number): Promise<ActivityEntry[]>;
}
