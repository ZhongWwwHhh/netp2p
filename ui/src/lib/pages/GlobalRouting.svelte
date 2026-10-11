<script lang="ts">
  import Badge from '../components/Badge.svelte';
  import DataTable from '../components/DataTable.svelte';
  import PageHeader from '../components/PageHeader.svelte';
  import ProgressBar from '../components/ProgressBar.svelte';
  import Skeleton from '../components/Skeleton.svelte';
  import { bitrateLabel, bytesLabel, percent, relativeTime, shortPeerId } from '../format';
  import { session } from '../stores/session.svelte';
  import type {
    DemandSample, EdgeTelemetry, FECClassDiagnostics, FlowClass, ManagerCapacityStatus, PathAllocation,
    PathFamily, RoutingDomain, RoutingStatus,
  } from '../types';

  let status = $state<RoutingStatus | null>(null);
  let loading = $state(false);
  let error = $state('');
  let query = $state('');
  let flowClassFilter = $state<FlowClass | ''>('');
  let pathKindFilter = $state('');

  async function load() {
    const client = session.client;
    if (!client) return;
    loading = true;
    error = '';
    try {
      status = await client.routingStatus();
    } catch (caught) {
      error = caught instanceof Error ? caught.message : String(caught);
    } finally {
      loading = false;
    }
  }

  $effect(() => {
    void load();
  });

  const needle = $derived(query.trim().toLowerCase());
  const domains = $derived((status?.domains ?? []).filter((domain) =>
    matches(domain.key.sourceManagerId, domain.key.sourceGroupId, domain.key.destinationScope, domain.id) &&
    (!flowClassFilter || domain.key.flowClass === flowClassFilter)));
  const pathFamilies = $derived((status?.pathFamilies ?? []).filter((family) =>
    matches(family.id, family.kind, ...(family.managerHops ?? [])) &&
    (!pathKindFilter || family.kind === pathKindFilter) &&
    (!flowClassFilter || family.flowClasses.includes(flowClassFilter))));
  const managerCapacity = $derived((status?.managerCapacity ?? []).filter((manager) =>
    matches(manager.managerId, manager.state, manager.countMode)));
  const telemetry = $derived((status?.telemetry ?? []).filter((edge) =>
    matches(edge.edgeId, edge.managerId, edge.source)));
  const demand = $derived((status?.demand ?? []).filter((sample) =>
    matches(sample.peerId, sample.sourceGroupId, sample.destinationScope, sample.pathId) &&
    (!flowClassFilter || sample.flowClass === flowClassFilter)));
  const fecClasses = $derived((status?.fec.classes ?? []).filter((entry) =>
    matches(entry.flowClass, entry.lastError ?? '') &&
    (!flowClassFilter || entry.flowClass === flowClassFilter)));
  const allocations = $derived((status?.epoch?.allocations ?? []).filter((allocation) =>
    matches(allocation.key.sourceManagerId, allocation.key.sourceGroupId, allocation.key.destinationScope) &&
    (!flowClassFilter || allocation.key.flowClass === flowClassFilter)));

  function matches(...values: string[]): boolean {
    return !needle || values.join(' ').toLowerCase().includes(needle);
  }

  function flowTone(flowClass: string): 'sky' | 'emerald' | 'amber' | 'rose' | 'slate' {
    if (flowClass === 'realtime') return 'rose';
    if (flowClass === 'throughput') return 'emerald';
    if (flowClass === 'cost') return 'amber';
    if (flowClass === 'reliability') return 'sky';
    return 'slate';
  }

  function kindTone(kind: string): 'emerald' | 'sky' | 'slate' {
    if (kind === 'direct') return 'emerald';
    if (kind === 'via_manager') return 'sky';
    return 'slate';
  }

  function capacityTone(state: string): 'emerald' | 'amber' | 'rose' | 'slate' {
    if (state === 'exhausted' || state === 'projected-exhaustion') return 'rose';
    if (state === 'pressure') return 'amber';
    if (state === 'normal') return 'emerald';
    return 'slate';
  }

  function durationLabel(seconds: number): string {
    if (!seconds) return 'unknown';
    if (seconds < 3600) return `${Math.round(seconds / 60)} min`;
    if (seconds < 86400) return `${Math.round(seconds / 3600)} h`;
    return `${Math.round(seconds / 86400)} d`;
  }

  function timestampLabel(value: string): string {
    const timestamp = new Date(value).getTime();
    return Number.isNaN(timestamp) ? 'unknown' : new Date(timestamp).toLocaleString();
  }

  function allocationLabel(allocation: PathAllocation): string {
    return `${allocation.key.sourceManagerId}/${allocation.key.sourceGroupId} -> ${allocation.key.destinationScope}`;
  }
</script>

<div class="space-y-5">
  <PageHeader
    title="Global Routing"
    shown={domains.length}
    total={status?.domains.length ?? 0}
    subtitle="Routing domains, path families, epochs, capacity, telemetry, demand and FEC."
  >
    {#snippet actions()}
      <button class="btn-secondary" onclick={() => void load()} disabled={loading}>
        {loading ? 'Refreshing…' : 'Refresh'}
      </button>
    {/snippet}
  </PageHeader>

  {#if error}
    <p class="rounded-xl border border-rose-200 bg-rose-50 p-3 text-sm text-rose-700">{error}</p>
  {/if}

  <div class="surface p-4">
    <div class="grid gap-3 md:grid-cols-4">
      <label class="space-y-1">
        <span class="label">Search</span>
        <input class="input" bind:value={query} placeholder="manager, group, scope, path" />
      </label>
      <label class="space-y-1">
        <span class="label">Flow class</span>
        <select class="input" bind:value={flowClassFilter}>
          <option value="">all</option>
          {#each status?.supportedFlowClasses ?? [] as flowClass (flowClass)}
            <option value={flowClass}>{flowClass}</option>
          {/each}
        </select>
      </label>
      <label class="space-y-1">
        <span class="label">Path kind</span>
        <select class="input" bind:value={pathKindFilter}>
          <option value="">all</option>
          <option value="direct">direct</option>
          <option value="via_manager">via manager</option>
          <option value="multi_hop">multi-hop</option>
        </select>
      </label>
      <div class="flex items-end">
        <Badge tone={status?.mode === 'runtime' ? 'emerald' : 'amber'} label={status?.mode ?? 'unavailable'} />
      </div>
    </div>
  </div>

  {#if !status}
    <div class="surface"><Skeleton rows={6} /></div>
  {:else}
    <div class="grid gap-4 md:grid-cols-4">
      <div class="surface p-4">
        <p class="text-xs uppercase tracking-wide text-slate-500">Routing epoch</p>
        <p class="mt-1 text-2xl font-semibold text-slate-900">{status.epoch ? `v${status.epoch.version}` : 'none'}</p>
        <p class="text-xs text-slate-500">
          {status.epoch ? `${status.epoch.signatureVerified ? 'verified' : 'unverified'} · height ${status.epoch.snapshotHeight}` : 'runtime producer unavailable'}
        </p>
      </div>
      <div class="surface p-4">
        <p class="text-xs uppercase tracking-wide text-slate-500">Path families</p>
        <p class="mt-1 text-2xl font-semibold text-slate-900">{pathFamilies.length}</p>
        <p class="text-xs text-slate-500">{status.pathFamilies.length} total</p>
      </div>
      <div class="surface p-4">
        <p class="text-xs uppercase tracking-wide text-slate-500">Demand samples</p>
        <p class="mt-1 text-2xl font-semibold text-slate-900">{demand.length}</p>
        <p class="text-xs text-slate-500">{status.demand.length} total</p>
      </div>
      <div class="surface p-4">
        <p class="text-xs uppercase tracking-wide text-slate-500">FEC recovered</p>
        <p class="mt-1 text-2xl font-semibold text-slate-900">
          {status.fec.classes.reduce((total, entry) => total + entry.recoveredPackets, 0).toLocaleString()}
        </p>
        <p class="text-xs text-slate-500">{status.fec.enabled ? status.fec.defaultCodec || 'enabled' : 'disabled'}</p>
      </div>
    </div>

    <section class="surface">
      <div class="border-b border-slate-200 p-4">
        <h2 class="text-sm font-semibold text-slate-900">Routing domains</h2>
      </div>
      <DataTable
        rows={domains}
        columns={[
          { key: 'domain', label: 'Domain' },
          { key: 'flow', label: 'Flow class' },
          { key: 'families', label: 'Path families', align: 'right' },
          { key: 'policies', label: 'Policies' },
          { key: 'admission', label: 'Admission' },
        ]}
        rowKey={(domain: RoutingDomain) => domain.id}
        emptyTitle="No routing domains"
        emptyHint="No domain matches the current filters."
      >
        {#snippet cell(domain: RoutingDomain, key: string)}
          {#if key === 'domain'}
            <span class="font-medium text-slate-900">{domain.key.sourceGroupId} → {domain.key.destinationScope}</span>
            <div class="font-mono text-xs text-slate-400">{domain.key.sourceManagerId}</div>
          {:else if key === 'flow'}
            <Badge tone={flowTone(domain.key.flowClass)} label={domain.key.flowClass} />
          {:else if key === 'families'}
            <span class="text-sm text-slate-600">{domain.pathFamilyIds.length}</span>
          {:else if key === 'policies'}
            <div class="flex flex-wrap gap-1">
              {#each domain.policyIds as policyId (policyId)}<Badge tone="slate" label={policyId} />{/each}
            </div>
          {:else if key === 'admission'}
            <Badge tone={domain.requiresAdmission ? 'amber' : 'emerald'} label={domain.requiresAdmission ? 'required' : 'not required'} />
          {/if}
        {/snippet}
      </DataTable>
    </section>

    <section class="surface">
      <div class="border-b border-slate-200 p-4">
        <h2 class="text-sm font-semibold text-slate-900">Path families</h2>
      </div>
      <DataTable
        rows={pathFamilies}
        columns={[
          { key: 'id', label: 'Family' },
          { key: 'kind', label: 'Kind' },
          { key: 'hops', label: 'Manager hops' },
          { key: 'classes', label: 'Flow classes' },
          { key: 'limits', label: 'Limits' },
        ]}
        rowKey={(family: PathFamily) => family.id}
        emptyTitle="No path families"
        emptyHint="No certified family matches the current filters."
      >
        {#snippet cell(family: PathFamily, key: string)}
          {#if key === 'id'}
            <span class="font-mono text-xs text-slate-700">{family.id}</span>
          {:else if key === 'kind'}
            <Badge tone={kindTone(family.kind)} label={family.kind} />
          {:else if key === 'hops'}
            <span class="font-mono text-xs text-slate-500">{(family.managerHops ?? []).join(' → ') || 'peer edge'}</span>
          {:else if key === 'classes'}
            <div class="flex flex-wrap gap-1">
              {#each family.flowClasses as flowClass (flowClass)}<Badge tone={flowTone(flowClass)} label={flowClass} />{/each}
            </div>
          {:else if key === 'limits'}
            <span class="text-xs text-slate-500">
              {family.maxRttMilliseconds.toFixed(0)} ms · jitter {family.maxJitterMilliseconds.toFixed(1)} ms · {family.maxLossPercent.toFixed(1)}% loss · {family.minBandwidthMbps.toFixed(0)} Mbps
            </span>
          {/if}
        {/snippet}
      </DataTable>
    </section>

    <section class="surface">
      <div class="border-b border-slate-200 p-4">
        <h2 class="text-sm font-semibold text-slate-900">Routing epoch</h2>
      </div>
      {#if status.epoch}
        <div class="p-4">
          <div class="flex flex-wrap gap-2">
            <Badge tone={status.epoch.signatureVerified ? 'emerald' : 'rose'} label={status.epoch.signatureVerified ? 'signature verified' : 'signature unverified'} />
            <Badge tone={status.epoch.thresholdSigned ? 'emerald' : 'amber'} label={status.epoch.thresholdSigned ? 'threshold signed' : 'single signer'} />
            <Badge tone="slate" label={`manager ${status.epoch.managerId}`} />
            <Badge tone="slate" label={`expires ${timestampLabel(status.epoch.expiresAt)}`} />
          </div>
          <div class="mt-3">
            <DataTable
              rows={allocations}
              columns={[
                { key: 'domain', label: 'Domain' },
                { key: 'flow', label: 'Flow class' },
                { key: 'paths', label: 'Weights' },
              ]}
              rowKey={(allocation: PathAllocation) => allocationLabel(allocation)}
              emptyTitle="No allocations"
            >
              {#snippet cell(allocation: PathAllocation, key: string)}
                {#if key === 'domain'}
                  <span class="font-mono text-xs text-slate-600">{allocationLabel(allocation)}</span>
                {:else if key === 'flow'}
                  <Badge tone={flowTone(allocation.key.flowClass)} label={allocation.key.flowClass} />
                {:else if key === 'paths'}
                  <div class="flex flex-wrap gap-1">
                    {#each allocation.paths as path (path.pathId)}
                      <span class="code">{path.pathId} {(path.weight * 100).toFixed(0)}%</span>
                    {/each}
                  </div>
                {/if}
              {/snippet}
            </DataTable>
          </div>
        </div>
      {:else}
        <p class="p-4 text-sm text-slate-500">No runtime routing epoch is available.</p>
      {/if}
    </section>

    <section class="surface">
      <div class="border-b border-slate-200 p-4">
        <h2 class="text-sm font-semibold text-slate-900">Manager capacity</h2>
      </div>
      <DataTable
        rows={managerCapacity}
        columns={[
          { key: 'manager', label: 'Manager' },
          { key: 'monthly', label: 'Monthly usage' },
          { key: 'pressure', label: 'Pressure' },
          { key: 'exhaustion', label: 'Projected exhaustion' },
          { key: 'state', label: 'State' },
        ]}
        rowKey={(manager: ManagerCapacityStatus) => manager.managerId}
        emptyTitle="No manager capacity records"
      >
        {#snippet cell(manager: ManagerCapacityStatus, key: string)}
          {#if key === 'manager'}
            <span class="font-medium text-slate-900">{manager.managerId}</span>
            <div class="text-xs text-slate-500">{manager.countMode || 'unconfigured'}</div>
          {:else if key === 'monthly'}
            <span class="text-sm text-slate-600">
              {bytesLabel(manager.usedBytes)} / {manager.monthlyBytes ? bytesLabel(manager.monthlyBytes) : 'unlimited'}
            </span>
          {:else if key === 'pressure'}
            <div class="w-40 space-y-1">
              <ProgressBar value={percent(manager.usedBytes, manager.monthlyBytes)} />
              <p class="text-xs text-slate-500">{(manager.pressure * 100).toFixed(1)}%</p>
            </div>
          {:else if key === 'exhaustion'}
            <span class="text-sm text-slate-600">{durationLabel(manager.projectedExhaustionSeconds)}</span>
          {:else if key === 'state'}
            <Badge tone={capacityTone(manager.state)} label={manager.state} />
          {/if}
        {/snippet}
      </DataTable>
    </section>

    <section class="surface">
      <div class="border-b border-slate-200 p-4">
        <h2 class="text-sm font-semibold text-slate-900">Edge telemetry</h2>
      </div>
      <DataTable
        rows={telemetry}
        columns={[
          { key: 'edge', label: 'Edge' },
          { key: 'queue', label: 'Queue' },
          { key: 'quality', label: 'RTT / jitter / loss' },
          { key: 'bandwidth', label: 'Bandwidth' },
          { key: 'flows', label: 'Flows', align: 'right' },
          { key: 'updated', label: 'Updated' },
        ]}
        rowKey={(edge: EdgeTelemetry) => edge.edgeId}
        emptyTitle="No edge telemetry"
      >
        {#snippet cell(edge: EdgeTelemetry, key: string)}
          {#if key === 'edge'}
            <span class="font-mono text-xs text-slate-700">{edge.edgeId}</span>
            <div class="text-xs text-slate-400">{edge.source}</div>
          {:else if key === 'queue'}
            <span class="text-sm text-slate-600">{edge.queueDepth.toFixed(0)} · EWMA {edge.queueDepthEwma.toFixed(1)}</span>
            <div class="text-xs text-slate-400">drop {edge.dropRate.toFixed(2)}%</div>
          {:else if key === 'quality'}
            <span class="text-sm text-slate-600">
              {edge.rttMilliseconds.toFixed(0)} ms · {edge.jitterMilliseconds.toFixed(1)} ms · {edge.lossPercent.toFixed(2)}%
            </span>
          {:else if key === 'bandwidth'}
            <span class="text-sm text-slate-600">{bitrateLabel(edge.measuredBandwidthMbps * 1_000_000)}</span>
          {:else if key === 'flows'}
            <span class="text-sm text-slate-600">{edge.activeFlows.toLocaleString()}</span>
          {:else if key === 'updated'}
            <span class="text-xs text-slate-500">{relativeTime(edge.updatedAt)}</span>
          {/if}
        {/snippet}
      </DataTable>
    </section>

    <section class="surface">
      <div class="border-b border-slate-200 p-4">
        <h2 class="text-sm font-semibold text-slate-900">Demand</h2>
      </div>
      <DataTable
        rows={demand}
        columns={[
          { key: 'peer', label: 'Peer' },
          { key: 'domain', label: 'Domain' },
          { key: 'flow', label: 'Flow class' },
          { key: 'path', label: 'Path' },
          { key: 'bytes', label: 'Bytes', align: 'right' },
          { key: 'observed', label: 'Observed' },
        ]}
        rowKey={(sample: DemandSample) => `${sample.peerId}:${sample.pathId}:${sample.observedAt}`}
        emptyTitle="No demand samples"
      >
        {#snippet cell(sample: DemandSample, key: string)}
          {#if key === 'peer'}
            <span class="font-mono text-xs text-slate-700">{shortPeerId(sample.peerId, 12)}</span>
          {:else if key === 'domain'}
            <span class="font-mono text-xs text-slate-600">{sample.sourceGroupId} → {sample.destinationScope}</span>
          {:else if key === 'flow'}
            <Badge tone={flowTone(sample.flowClass)} label={sample.flowClass} />
          {:else if key === 'path'}
            <span class="font-mono text-xs text-slate-500">{sample.pathId}</span>
          {:else if key === 'bytes'}
            <span class="text-sm text-slate-600">{bytesLabel(sample.bytes)}</span>
          {:else if key === 'observed'}
            <span class="text-xs text-slate-500">{relativeTime(sample.observedAt)}</span>
          {/if}
        {/snippet}
      </DataTable>
    </section>

    <section class="surface">
      <div class="border-b border-slate-200 p-4">
        <h2 class="text-sm font-semibold text-slate-900">FEC</h2>
      </div>
      <DataTable
        rows={fecClasses}
        columns={[
          { key: 'class', label: 'Flow class' },
          { key: 'state', label: 'State' },
          { key: 'packets', label: 'Packets', align: 'right' },
          { key: 'recovered', label: 'Recovered', align: 'right' },
          { key: 'overhead', label: 'Overhead' },
        ]}
        rowKey={(entry: FECClassDiagnostics) => entry.flowClass}
        emptyTitle="No FEC records"
      >
        {#snippet cell(entry: FECClassDiagnostics, key: string)}
          {#if key === 'class'}
            <Badge tone={flowTone(entry.flowClass)} label={entry.flowClass} />
          {:else if key === 'state'}
            <Badge tone={entry.enabled ? 'emerald' : 'slate'} label={entry.enabled ? 'enabled' : 'disabled'} />
            {#if entry.lastError}<div class="mt-1 text-xs text-rose-600">{entry.lastError}</div>{/if}
          {:else if key === 'packets'}
            <span class="text-sm text-slate-600">{entry.packets.toLocaleString()}</span>
          {:else if key === 'recovered'}
            <span class="text-sm text-slate-600">{entry.recoveredPackets.toLocaleString()}</span>
          {:else if key === 'overhead'}
            <span class="text-sm text-slate-600">{(entry.overheadRatio * 100).toFixed(1)}%</span>
          {/if}
        {/snippet}
      </DataTable>
    </section>

    {#if status.problems.length > 0}
      <section class="surface p-5">
        <h2 class="text-sm font-semibold text-slate-900">Problems</h2>
        <ul class="mt-2 space-y-1.5 text-sm text-amber-700">
          {#each status.problems as problem (problem)}
            <li class="flex items-start gap-2"><span class="mt-1 h-1.5 w-1.5 rounded-full bg-amber-500"></span>{problem}</li>
          {/each}
        </ul>
      </section>
    {/if}
  {/if}
</div>
