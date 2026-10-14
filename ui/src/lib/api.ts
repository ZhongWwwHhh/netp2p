import { apiClient } from './http';
import type {
  ActivityEntry, AdmissionReport, Alert, AuditEvent, Bootstrap, Budget, Diagnostics, Presence, RouteAssignment,
  DemandSample, EdgeTelemetry, FECDiagnostics, ManagerCapacityStatus, PathFamily, RoutingDomain, RoutingEpoch,
  RoutingStatus, SessionInfo, SetupKeyCreateInput, SetupKeyCreation, Snapshot, StateTransition, User,
} from './types';

export { apiClient };

export interface AssignmentsView {
  assignments: RouteAssignment[];
  admissions: Record<string, Record<string, AdmissionReport>>;
}

export interface ApiClient {
  setToken(value: string): void;
  stop(): Promise<void>;
  snapshot(): Promise<Snapshot>;
  snapshotAt(height: number): Promise<Snapshot>;
  transition(transition: StateTransition): Promise<Snapshot>;
  createSetupKey(input: SetupKeyCreateInput): Promise<SetupKeyCreation>;
  presence(): Promise<Presence[]>;
  session(): Promise<SessionInfo>;
  users(): Promise<User[]>;
  updateCredentials(userId: string, input: { email?: string; password?: string }): Promise<User>;
  activity(limit?: number): Promise<ActivityEntry[]>;
  events(limit?: number): Promise<AuditEvent[]>;
  diagnostics(): Promise<Diagnostics>;
  assignments(): Promise<AssignmentsView>;
  routingStatus(): Promise<RoutingStatus>;
  routingDomains(): Promise<RoutingDomain[]>;
  pathFamilies(): Promise<PathFamily[]>;
  routingTelemetry(): Promise<EdgeTelemetry[]>;
  routingDemand(): Promise<DemandSample[]>;
  routingEpoch(): Promise<RoutingEpoch | null>;
  routingFec(): Promise<FECDiagnostics>;
  managerCapacity(): Promise<ManagerCapacityStatus[]>;
  quota(): Promise<Budget[]>;
  alerts(): Promise<Alert[]>;
}
