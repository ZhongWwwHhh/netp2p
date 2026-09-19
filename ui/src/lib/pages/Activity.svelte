<script lang="ts">
  import Badge from '../components/Badge.svelte';
  import EmptyState from '../components/EmptyState.svelte';
  import PageHeader from '../components/PageHeader.svelte';
  import Skeleton from '../components/Skeleton.svelte';
  import { shortHash } from '../format';
  import { network, refreshActivity } from '../stores/network.svelte';
  import type { Snapshot } from '../types';

  let expanded = $state<number | null>(null);

  $effect(() => {
    if (network.activity.length === 0 && network.snapshot) {
      void refreshActivity();
    }
  });

  // Summarize each transition so the log reads as an audit trail rather than
  // raw JSON.
  function summarize(entry: Snapshot): string {
    const transition = entry.transition as Record<string, unknown> & { type?: string };
    const type = transition?.type ?? 'unknown';
    const target = (value: unknown, key = 'id') =>
      value && typeof value === 'object' && key in value ? String((value as Record<string, unknown>)[key]) : '';
    switch (type) {
      case 'genesis':
        return 'Seeded the network';
      case 'register_peer':
        return `Registered peer ${target(transition.peer, 'peerId') || 'unknown'}`;
      case 'update_peer':
        return `Updated peer metadata for ${target(transition.peer, 'peerId') || 'unknown'}`;
      case 'upsert_group':
        return `Upserted group ${target(transition.group)}`;
      case 'remove_group':
        return `Removed group ${transition.targetId ?? ''}`;
      case 'upsert_policy':
        return `Upserted policy ${target(transition.policy)}`;
      case 'remove_policy':
        return `Removed policy ${transition.targetId ?? ''}`;
      case 'upsert_route':
        return `Upserted route ${target(transition.route)}`;
      case 'remove_route':
        return `Removed route ${transition.targetId ?? ''}`;
      case 'upsert_budget':
        return `Upserted budget ${target(transition.budget)}`;
      case 'remove_budget':
        return `Removed budget ${transition.targetId ?? ''}`;
      case 'upsert_setup_key':
        return `Upserted setup key ${target(transition.setupKeyRecord)}`;
      case 'remove_setup_key':
        return `Removed setup key ${transition.targetId ?? ''}`;
      case 'upsert_nameserver':
        return `Upserted nameserver ${target(transition.nameserver)}`;
      case 'remove_nameserver':
        return `Removed nameserver ${transition.targetId ?? ''}`;
      case 'upsert_zone':
        return `Upserted DNS zone ${target(transition.zone)}`;
      case 'remove_zone':
        return `Removed DNS zone ${transition.targetId ?? ''}`;
      case 'update_dns_settings':
        return 'Updated DNS settings';
      default:
        return type;
    }
  }

  function transitionTone(type: string | undefined): 'emerald' | 'rose' | 'slate' | 'sky' {
    if (!type) return 'slate';
    if (type.startsWith('remove_')) return 'rose';
    if (type.startsWith('upsert_') || type.startsWith('update_')) return 'emerald';
    return 'sky';
  }
</script>

<div class="space-y-5">
  <PageHeader
    title="Activity"
    shown={network.activity.length}
    total={network.activity.length}
    subtitle="Certified decision log. Every entry is covered by the quorum certificate, so it cannot be rewritten by one manager."
  >
    {#snippet actions()}
      <button class="btn-secondary" onclick={() => void refreshActivity()} disabled={network.loading}>
        {network.loading ? 'Loading…' : 'Reload'}
      </button>
    {/snippet}
  </PageHeader>

  {#if network.error}
    <p class="rounded-xl border border-rose-200 bg-rose-50 p-3 text-sm text-rose-700">{network.error}</p>
  {/if}

  <div class="surface">
    {#if network.loading && network.activity.length === 0}
      <Skeleton rows={5} />
    {:else if network.activity.length === 0}
      <EmptyState title="No decisions yet" hint="Certified transitions appear here as they commit." />
    {:else}
      <ul class="divide-y divide-slate-100">
        {#each network.activity as entry (entry.height)}
          <li class="px-4 py-3">
            <div class="flex flex-wrap items-center justify-between gap-3">
              <div class="flex items-center gap-3">
                <span class="w-14 shrink-0 font-mono text-xs text-slate-500">#{entry.height}</span>
                <Badge tone={transitionTone(entry.transition?.type)} label={entry.transition?.type ?? 'unknown'} />
                <span class="text-sm text-slate-800">{summarize(entry)}</span>
              </div>
              <div class="flex items-center gap-3 text-xs text-slate-500">
                <span>leader {entry.leaderId || '—'}</span>
                <span>{entry.qc.signers.length} signers</span>
                <span class="font-mono" title={entry.qc.transitionHash}>{shortHash(entry.qc.transitionHash, 10)}</span>
                <button class="btn-ghost text-xs" onclick={() => (expanded = expanded === entry.height ? null : entry.height)}>
                  {expanded === entry.height ? 'Hide' : 'Raw'}
                </button>
              </div>
            </div>
            {#if expanded === entry.height}
              <div class="mt-3 rounded-lg bg-slate-50 p-3">
                <p class="text-xs font-medium text-slate-500">Transition</p>
                <pre class="mt-1 overflow-x-auto font-mono text-xs text-slate-700">{JSON.stringify(entry.transition, null, 2)}</pre>
                <p class="mt-2 text-xs font-medium text-slate-500">Certificate</p>
                <p class="mt-1 break-all font-mono text-xs text-slate-700">
                  state {entry.stateHash} · round {entry.qc.round} · signers {entry.qc.signers.join(', ')}
                </p>
              </div>
            {/if}
          </li>
        {/each}
      </ul>
    {/if}
  </div>
</div>
