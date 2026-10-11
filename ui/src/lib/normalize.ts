import type { Presence, RoutingStatus, Snapshot } from './types';

function asArray<T>(value: readonly T[] | null | undefined): T[] {
  return Array.isArray(value) ? [...value] : [];
}

/**
 * Defensive boundary normalization. The manager serializes empty collections as
 * `[]`, but older snapshots may still contain `null`; every page must only ever
 * see arrays so rendering never throws.
 */
export function normalizeSnapshot(snapshot: Snapshot): Snapshot {
  return {
    ...snapshot,
    committee: asArray(snapshot.committee),
    state: {
      ...snapshot.state,
      peers: asArray(snapshot.state?.peers),
      users: asArray(snapshot.state?.users),
      groups: asArray(snapshot.state?.groups),
      policies: asArray(snapshot.state?.policies),
      routes: asArray(snapshot.state?.routes),
      budgets: asArray(snapshot.state?.budgets),
      setupKeys: asArray(snapshot.state?.setupKeys),
      nameservers: asArray(snapshot.state?.nameservers),
      zones: asArray(snapshot.state?.zones),
      dnsSettings: { disabled: snapshot.state?.dnsSettings?.disabled ?? false, groups: asArray(snapshot.state?.dnsSettings?.groups) },
      settings: snapshot.state?.settings ?? {},
      pathFamilies: asArray(snapshot.state?.pathFamilies),
      routingDomains: asArray(snapshot.state?.routingDomains),
      managerJoins: asArray(snapshot.state?.managerJoins),
    },
  };
}

export function normalizePresence(observations: readonly Presence[] | null | undefined): Presence[] {
  return asArray(observations);
}

export function normalizeRoutingStatus(status: RoutingStatus | null | undefined): RoutingStatus {
  const empty = {
    networkId: '',
    snapshotHeight: 0,
    generatedAt: '',
    mode: 'unavailable',
    supportedFlowClasses: [],
    domains: [],
    pathFamilies: [],
    epoch: null,
    managerCapacity: [],
    telemetry: [],
    demand: [],
    fec: { enabled: false, defaultCodec: '', maxRedundancyPercent: 0, classes: [] },
    problems: [],
  } as RoutingStatus;
  if (!status) return empty;
  return {
    ...empty,
    ...status,
    supportedFlowClasses: asArray(status.supportedFlowClasses),
    domains: asArray(status.domains),
    pathFamilies: asArray(status.pathFamilies),
    managerCapacity: asArray(status.managerCapacity),
    telemetry: asArray(status.telemetry),
    demand: asArray(status.demand),
    problems: asArray(status.problems),
    fec: {
      ...empty.fec,
      ...status.fec,
      classes: asArray(status.fec?.classes),
    },
    epoch: status.epoch ?? null,
  };
}
