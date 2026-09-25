<script lang="ts">
  import Badge from '../components/Badge.svelte';
  import PageHeader from '../components/PageHeader.svelte';
  import Skeleton from '../components/Skeleton.svelte';
  import TrustBadge from '../components/TrustBadge.svelte';
  import { bytesLabel } from '../format';
  import { session } from '../stores/session.svelte';
  import type { Diagnostics } from '../types';

  let diagnostics = $state<Diagnostics | null>(null);
  let loading = $state(false);
  let error = $state('');

  async function load() {
    const client = session.client;
    if (!client) return;
    loading = true;
    error = '';
    try {
      diagnostics = await client.diagnostics();
    } catch (caught) {
      error = caught instanceof Error ? caught.message : String(caught);
    } finally {
      loading = false;
    }
  }

  $effect(() => {
    void load();
  });
</script>

<div class="space-y-5">
  <PageHeader title="Diagnostics" subtitle="Operator view of consensus, forwarding, link and quota health.">
    {#snippet actions()}
      <button class="btn-secondary" onclick={() => void load()} disabled={loading}>
        {loading ? 'Refreshing…' : 'Refresh'}
      </button>
    {/snippet}
  </PageHeader>

  {#if error}
    <p class="rounded-xl border border-rose-200 bg-rose-50 p-3 text-sm text-rose-700">{error}</p>
  {/if}

  {#if !diagnostics}
    <div class="surface"><Skeleton rows={5} /></div>
  {:else}
    <div class="grid gap-4 md:grid-cols-3">
      <div class="surface p-4">
        <p class="text-xs uppercase tracking-wide text-slate-500">Protocol</p>
        <p class="mt-1 text-2xl font-semibold text-slate-900">{diagnostics.protocolVersion}</p>
        <p class="text-xs text-slate-500">network {diagnostics.networkId || '—'}</p>
      </div>
      <div class="surface p-4">
        <p class="text-xs uppercase tracking-wide text-slate-500">Committed height</p>
        <p class="mt-1 text-2xl font-semibold text-slate-900">{diagnostics.height}</p>
        <p class="text-xs text-slate-500">quorum {diagnostics.quorumSize} of {diagnostics.committeeSize}</p>
      </div>
      <div class="surface p-4">
        <p class="text-xs uppercase tracking-wide text-slate-500">Forwarding</p>
        <p class="mt-1 text-2xl font-semibold text-slate-900">{diagnostics.forwarding.forwarded}</p>
        <p class="text-xs text-slate-500">{diagnostics.forwarding.dropped} dropped</p>
      </div>
    </div>

    <section class="surface p-5">
      <h2 class="text-sm font-semibold text-slate-900">Certified state</h2>
      <div class="mt-3 flex flex-wrap gap-2">
        <Badge tone="slate" label={`${diagnostics.peers} peers`} />
        <Badge tone="slate" label={`${diagnostics.groups} groups`} />
        <Badge tone="slate" label={`${diagnostics.policies} policies`} />
        <Badge tone="slate" label={`${diagnostics.budgets} budgets`} />
        <Badge tone="slate" label={`${diagnostics.assignments} assignments`} />
        <Badge tone="slate" label={`${diagnostics.linkSegments} link segments`} />
      </div>
    </section>

    <section class="surface p-5">
      <h2 class="text-sm font-semibold text-slate-900">Active alerts</h2>
      <p class="mt-1 text-xs text-slate-500">Alerts are evaluated per manager and are not certified state.</p>
      {#if diagnostics.alerts.length === 0}
        <p class="mt-2 text-sm text-emerald-700">No active alerts.</p>
      {:else}
        <ul class="mt-3 space-y-2">
          {#each diagnostics.alerts as alert (alert.id)}
            <li class="flex items-start gap-3 rounded-lg border border-amber-200 bg-amber-50 p-3">
              <Badge tone={alert.severity === 'critical' ? 'rose' : 'amber'} label={alert.severity} />
              <div>
                <p class="text-sm font-medium text-amber-900">{alert.rule}</p>
                <p class="text-xs text-amber-800">{alert.summary}</p>
              </div>
            </li>
          {/each}
        </ul>
      {/if}
    </section>

    <section class="surface p-5">
      <h2 class="text-sm font-semibold text-slate-900">Problems</h2>
      {#if diagnostics.problems.length === 0}
        <p class="mt-2 text-sm text-emerald-700">No problems detected.</p>
      {:else}
        <ul class="mt-2 space-y-1.5 text-sm text-amber-700">
          {#each diagnostics.problems as problem (problem)}
            <li class="flex items-start gap-2"><span class="mt-1 h-1.5 w-1.5 rounded-full bg-amber-500"></span>{problem}</li>
          {/each}
        </ul>
      {/if}
    </section>

    <section class="surface p-5">
      <h2 class="text-sm font-semibold text-slate-900">Observed peers</h2>
      <p class="mt-1 text-xs text-slate-500">Presence is observed per manager, never certified.</p>
      {#if diagnostics.presence.length === 0}
        <p class="mt-2 text-sm text-slate-500">No peer observations yet.</p>
      {:else}
        <ul class="mt-3 divide-y divide-slate-100">
          {#each diagnostics.presence as observation (observation.peerId)}
            <li class="flex items-center justify-between py-2 text-sm">
              <span class="font-mono text-xs text-slate-600">{observation.peerId}</span>
              <TrustBadge {observation} />
            </li>
          {/each}
        </ul>
      {/if}
    </section>

    <section class="surface p-5">
      <h2 class="text-sm font-semibold text-slate-900">Quota usage</h2>
      {#if diagnostics.quotaUsage.length === 0}
        <p class="mt-2 text-sm text-slate-500">No budgets accounted yet.</p>
      {:else}
        <ul class="mt-3 divide-y divide-slate-100">
          {#each diagnostics.quotaUsage as budget (budget.id)}
            <li class="flex items-center justify-between py-2 text-sm">
              <span class="text-slate-700">{budget.id}</span>
              <span class="text-xs text-slate-500">
                {bytesLabel(budget.usedDailyBytes)} / {budget.dailyBytes ? bytesLabel(budget.dailyBytes) : 'unlimited'} today
              </span>
            </li>
          {/each}
        </ul>
      {/if}
    </section>
  {/if}
</div>
