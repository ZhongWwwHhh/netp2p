import { normalizePresence, normalizeRoutingStatus, normalizeSnapshot } from './normalize';
import type {
  ActivityEntry, AdmissionReport, Alert, AuditEvent, Budget, Diagnostics, Presence, RouteAssignment,
  DemandSample, EdgeTelemetry, FECDiagnostics, ManagerCapacityStatus, PathFamily, RoutingDomain, RoutingEpoch,
  RoutingStatus, SessionInfo, SetupKeyCreateInput, SetupKeyCreation, Snapshot, StateTransition, User,
} from './types';

export async function apiClient() {
  let token = '';
  const request = async (path: string, init: { method?: string; body?: string } = {}) => {
    const headers: Record<string, string> = {};
    if (token) headers.authorization = `Bearer ${token}`;
    if (init.body !== undefined) headers['content-type'] = 'application/json';
    const response = await fetch(path, {
      method: init.method ?? 'GET',
      body: init.body,
      headers,
      credentials: 'same-origin',
    });
    const text = await response.text();
    const body = text ? JSON.parse(text) : null;
    if (!response.ok) {
      throw new Error((body as { error?: string } | null)?.error ?? `HTTP ${response.status}`);
    }
    return body;
  };
  const snapshot = (body: unknown) => normalizeSnapshot(body as Snapshot);
  return {
    setToken: (value: string) => { token = value; },
    stop: async () => undefined,
    snapshot: () => request('/api/v1/snapshot').then(snapshot),
    snapshotAt: (height: number) => request(`/api/v1/snapshot?height=${height}`).then(snapshot),
    transition: (transition: StateTransition) => request('/api/v1/transitions', {
      method: 'POST',
      body: JSON.stringify({ transition }),
    }).then(snapshot),
    createSetupKey: async (input: SetupKeyCreateInput): Promise<SetupKeyCreation> => {
      const body = await request('/api/v1/setup-keys', {
        method: 'POST',
        body: JSON.stringify(input),
      }) as { token?: string; snapshot?: Snapshot };
      if (!body.token || !body.snapshot) throw new Error('manager did not return a one-time setup key');
      return { token: body.token, snapshot: normalizeSnapshot(body.snapshot) };
    },
    presence: () => request('/api/v1/presence').then((body) =>
      normalizePresence((body as { observations?: Presence[] } | null)?.observations)),
    session: () => request('/api/v1/session') as Promise<SessionInfo>,
    users: () => request('/api/v1/users').then((body) =>
      ((body as { users?: User[] } | null)?.users ?? [])),
    updateCredentials: async (userId: string, input: { email?: string; password?: string }) =>
      request(`/api/v1/users/${encodeURIComponent(userId)}/credentials`, {
        method: 'POST',
        body: JSON.stringify(input),
      }) as Promise<User>,
    activity: (limit = 100) => request(`/api/v1/activity?limit=${limit}`).then((body) =>
      ((body as { entries?: ActivityEntry[] } | null)?.entries ?? []).map(snapshot)),
    events: (limit = 200) => request(`/api/v1/events?limit=${limit}`).then((body) =>
      ((body as { events?: AuditEvent[] } | null)?.events ?? [])),
    diagnostics: () => request('/api/v1/diagnostics') as Promise<Diagnostics>,
    assignments: () => request('/api/v1/assignments').then((body) => {
      const payload = body as { assignments?: RouteAssignment[]; admissions?: Record<string, Record<string, AdmissionReport>> } | null;
      return { assignments: payload?.assignments ?? [], admissions: payload?.admissions ?? {} };
    }),
    routingStatus: () => request('/api/v1/routing/status').then((body) =>
      normalizeRoutingStatus((body as { routing?: RoutingStatus } | null)?.routing)),
    routingDomains: () => request('/api/v1/routing/domains').then((body) =>
      ((body as { domains?: RoutingDomain[] } | null)?.domains ?? [])),
    pathFamilies: () => request('/api/v1/routing/path-families').then((body) =>
      ((body as { pathFamilies?: PathFamily[] } | null)?.pathFamilies ?? [])),
    routingTelemetry: () => request('/api/v1/routing/telemetry').then((body) =>
      ((body as { telemetry?: EdgeTelemetry[] } | null)?.telemetry ?? [])),
    routingDemand: () => request('/api/v1/routing/demand').then((body) =>
      ((body as { demand?: DemandSample[] } | null)?.demand ?? [])),
    routingEpoch: () => request('/api/v1/routing/epoch/current').then((body) =>
      ((body as { epoch?: RoutingEpoch | null } | null)?.epoch ?? null)),
    routingFec: () => request('/api/v1/routing/fec').then((body) =>
      ((body as { fec?: FECDiagnostics } | null)?.fec ?? { enabled: false, defaultCodec: '', maxRedundancyPercent: 0, classes: [] })),
    managerCapacity: () => request('/api/v1/managers/capacity').then((body) =>
      ((body as { managers?: ManagerCapacityStatus[] } | null)?.managers ?? [])),
    quota: () => request('/api/v1/quota').then((body) =>
      ((body as { usage?: Budget[] } | null)?.usage ?? [])),
    alerts: () => request('/api/v1/alerts').then((body) =>
      ((body as { alerts?: Alert[] } | null)?.alerts ?? [])),
  };
}
