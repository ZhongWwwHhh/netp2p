import { apiClient } from './libp2p';
import type {
  ActivityEntry, AdmissionReport, Alert, AuditEvent, Bootstrap, Budget, Diagnostics, Presence, RouteAssignment,
  SessionInfo, SetupKeyCreateInput, SetupKeyCreation, Snapshot, StateTransition, User,
} from './types';

export { apiClient };

export interface AssignmentsView {
  assignments: RouteAssignment[];
  admissions: Record<string, Record<string, AdmissionReport>>;
}

export interface ApiClient {
  peerId: { toString(): string };
  setToken(value: string): void;
  stop(): Promise<void>;
  snapshot(): Promise<Snapshot>;
  snapshotAt(height: number): Promise<Snapshot>;
  transition(transition: StateTransition): Promise<Snapshot>;
  createSetupKey(input: SetupKeyCreateInput): Promise<SetupKeyCreation>;
  presence(): Promise<Presence[]>;
  session(): Promise<SessionInfo>;
  users(): Promise<User[]>;
  activity(limit?: number): Promise<ActivityEntry[]>;
  events(limit?: number): Promise<AuditEvent[]>;
  diagnostics(): Promise<Diagnostics>;
  assignments(): Promise<AssignmentsView>;
  quota(): Promise<Budget[]>;
  alerts(): Promise<Alert[]>;
}
