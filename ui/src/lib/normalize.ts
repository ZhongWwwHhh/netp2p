import type { Presence, Snapshot } from './types';

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
      groups: asArray(snapshot.state?.groups),
      policies: asArray(snapshot.state?.policies),
      routes: asArray(snapshot.state?.routes),
      budgets: asArray(snapshot.state?.budgets),
      setupKeys: asArray(snapshot.state?.setupKeys),
      nameservers: asArray(snapshot.state?.nameservers),
      zones: asArray(snapshot.state?.zones),
      dnsSettings: { disabled: snapshot.state?.dnsSettings?.disabled ?? false, groups: asArray(snapshot.state?.dnsSettings?.groups) },
    },
  };
}

export function normalizePresence(observations: readonly Presence[] | null | undefined): Presence[] {
  return asArray(observations);
}
