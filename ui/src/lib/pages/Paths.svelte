<script lang="ts">
  import Badge from '../components/Badge.svelte';
  import DataTable from '../components/DataTable.svelte';
  import EmptyState from '../components/EmptyState.svelte';
  import PageHeader from '../components/PageHeader.svelte';
  import Skeleton from '../components/Skeleton.svelte';
  import { shortPeerId } from '../format';
  import { network } from '../stores/network.svelte';
  import { session } from '../stores/session.svelte';
  import type { AdmissionReport, RouteAssignment } from '../types';

  let admissions = $state<Record<string, Record<string, AdmissionReport>>>({});
  let loading = $state(false);
  let error = $state('');
  let selected = $state<RouteAssignment | null>(null);

  // Certified assignments come straight from the snapshot; the local
  // admission results are explicitly non-certified observations that only
  // reflect what this manager last heard.
  const assignments = $derived(network.snapshot?.state.assignments ?? []);

  async function loadAdmissions() {
    const client = session.client;
    if (!client) return;
    loading = true;
    error = '';
    try {
      const view = await client.assignments();
      admissions = view.admissions;
    } catch (caught) {
      error = caught instanceof Error ? caught.message : String(caught);
    } finally {
      loading = false;
    }
  }

  $effect(() => {
    void loadAdmissions();
  });

  function admissionFor(assignment: RouteAssignment, pathId: string): AdmissionReport | undefined {
    return admissions[assignment.sourcePeerId]?.[pathId];
  }

  const columns = [
    { key: 'route', label: 'Source → destination' },
    { key: 'primary', label: 'Primary path' },
    { key: 'fallbacks', label: 'Fallbacks', align: 'right' as const },
    { key: 'admission', label: 'Local admission' },
  ];

  function kindTone(kind: string): 'emerald' | 'sky' | 'slate' {
    if (kind === 'direct') return 'emerald';
    if (kind === 'via_manager') return 'sky';
    return 'slate';
  }
</script>

<div class="space-y-5">
  <PageHeader
    title="Paths"
    shown={assignments.length}
    total={assignments.length}
    subtitle="Certified route assignments produced by the planner and committed through BFT."
  />

  {#if error}
    <p class="rounded-xl border border-rose-200 bg-rose-50 p-3 text-sm text-rose-700">{error}</p>
  {/if}

  <div class="surface">
    {#if loading && assignments.length === 0}
      <Skeleton />
    {:else if assignments.length === 0}
      <EmptyState
        title="No route assignments yet"
        hint="Assignments appear once the planner certifies a path between two policy-allowed peers."
      />
    {:else}
      <DataTable
        rows={[...assignments].sort((left, right) => left.id.localeCompare(right.id))}
        {columns}
        rowKey={(assignment) => assignment.id}
        emptyTitle="No route assignments yet"
      >
        {#snippet cell(assignment: RouteAssignment, key: string)}
          {#if key === 'route'}
            <button class="text-left font-medium text-slate-900 hover:text-emerald-700" onclick={() => (selected = assignment)}>
              {shortPeerId(assignment.sourcePeerId, 10)} → {shortPeerId(assignment.destinationPeerId, 10)}
            </button>
            <div class="font-mono text-xs text-slate-400">epoch {assignment.epoch} · max hops {assignment.maxHops || '—'}</div>
          {:else if key === 'primary'}
            <Badge tone={kindTone(assignment.primary.kind)} label={assignment.primary.kind} />
            <div class="mt-1 text-xs text-slate-500">
              {assignment.primary.rttMilliseconds.toFixed(0)} ms · {assignment.primary.lossPercent.toFixed(1)}% loss · {assignment.primary.bandwidthMbps.toFixed(0)} Mbps
            </div>
            {#if (assignment.primary.managerHops ?? []).length > 0}
              <div class="mt-1 font-mono text-xs text-slate-400">
                via {(assignment.primary.managerHops ?? []).map((hop) => shortPeerId(hop, 8)).join(' → ')}
              </div>
            {/if}
          {:else if key === 'fallbacks'}
            <span class="text-sm text-slate-700">{assignment.fallbacks.length}</span>
          {:else if key === 'admission'}
            {@const report = admissionFor(assignment, assignment.primary.id)}
            {#if report}
              <Badge tone={report.ok ? 'emerald' : 'rose'} label={report.ok ? 'reachable' : 'failed'} />
              <div class="mt-1 text-xs text-slate-500">{report.rttMs.toFixed(0)} ms · {report.lossPct.toFixed(1)}% loss</div>
            {:else}
              <span class="text-xs text-slate-400">no client report</span>
            {/if}
          {/if}
        {/snippet}
      </DataTable>
    {/if}
  </div>
</div>

{#if selected}
  <div class="surface p-5">
    <h2 class="text-sm font-semibold text-slate-900">
      Assignment {shortPeerId(selected.sourcePeerId, 10)} → {shortPeerId(selected.destinationPeerId, 10)}
    </h2>
    <p class="mt-1 text-xs text-slate-500">
      Certified assignment. Quality estimates are scoring inputs; the local admission column is a non-certified client observation.
    </p>
    <div class="mt-4 space-y-3">
      {#each [selected.primary, ...selected.fallbacks] as path, index (path.id)}
        {@const report = admissionFor(selected, path.id)}
        <div class="rounded-lg border border-slate-200 p-3">
          <div class="flex items-center gap-2">
            <Badge tone={kindTone(path.kind)} label={path.kind} />
            <span class="text-xs text-slate-500">{index === 0 ? 'primary' : `fallback ${index}`}</span>
            <span class="font-mono text-xs text-slate-400">{path.id}</span>
          </div>
          <div class="mt-2 grid grid-cols-2 gap-2 text-xs text-slate-600 md:grid-cols-4">
            <span>RTT {path.rttMilliseconds.toFixed(0)} ms</span>
            <span>Loss {path.lossPercent.toFixed(1)}%</span>
            <span>BW {path.bandwidthMbps.toFixed(0)} Mbps</span>
            <span>Confidence {path.confidence.toFixed(2)}</span>
          </div>
          {#if (path.managerHops ?? []).length > 0}
            <p class="mt-2 break-all font-mono text-xs text-slate-500">hops: {(path.managerHops ?? []).join(' → ')}</p>
          {/if}
          <p class="mt-2 text-xs text-slate-500">
            {#if report}
              local admission: {report.ok ? 'reachable' : 'failed'} · {report.rttMs.toFixed(0)} ms · {report.lossPct.toFixed(1)}% loss
            {:else}
              local admission: no report from {shortPeerId(selected.sourcePeerId, 8)}
            {/if}
          </p>
        </div>
      {/each}
    </div>
    <button class="btn-secondary mt-4" onclick={() => (selected = null)}>Close</button>
  </div>
{/if}
