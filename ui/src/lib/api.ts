import { apiClient } from './libp2p';
import type { Bootstrap, Snapshot, StateTransition } from './types';

export { apiClient };

export interface ApiClient {
  peerId: { toString(): string };
  setToken(value: string): void;
  stop(): Promise<void>;
  snapshot(): Promise<Snapshot>;
  transition(transition: StateTransition): Promise<Snapshot>;
}
