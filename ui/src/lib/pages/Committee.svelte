<script lang="ts">
  import Badge from '../components/Badge.svelte';
  import DataTable from '../components/DataTable.svelte';
  import PageHeader from '../components/PageHeader.svelte';
  import StatusDot from '../components/StatusDot.svelte';
  import TrustBadge from '../components/TrustBadge.svelte';
  import { shortHash, shortPeerId } from '../format';
  import { network, presenceFor, submit } from '../stores/network.svelte';
  import { session, can } from '../stores/session.svelte';
  import type { CommitteeMember, ManagerJoinRequest, ManagerJoinStatus } from '../types';

  const snapshot = $derived(network.snapshot);
  const committee = $derived(snapshot?.committee ?? []);
  const ordered = $derived([...committee].sort((left, right) => left.id.localeCompare(right.id)));
  // The QC records which committee shares contributed as a bitmap over the
  // sorted committee order.
  const signed = $derived.by(() => {
    const set = new Set<string>();
    const bitmap = snapshot?.qc.signerBitmap;
    const bytes = typeof bitmap === 'string'
      ? Array.from(atob(bitmap), (char) => char.charCodeAt(0))
      : (bitmap ?? []);
    ordered.forEach((member, index) => {
      const byte = bytes[Math.floor(index / 8)];
      if (byte !== undefined && (byte & (1 << (index % 8)))) set.add(member.id);
    });
    return set;
  });
  // The leader of the next height is determined by committee order and round.
  const nextLeader = $derived.by(() => {
    if (!snapshot || committee.length === 0) return '';
    return ordered[(snapshot.height + 1) % ordered.length]?.id ?? '';
  });
  const quorumSize = $derived(snapshot?.committeeConfig?.threshold ?? committee.length);
  const managerJoins = $derived(snapshot?.state?.managerJoins ?? []);
  const canReviewJoins = $derived(can('settings', 'update'));

  async function reviewManagerJoin(request: ManagerJoinRequest, status: Extract<ManagerJoinStatus, 'approved' | 'rejected'>) {
    await submit({
      type: 'review_manager_join',
      managerJoin: {
        ...request,
        status,
        reviewedBy: session.identity?.email ?? 'web console',
        reviewedAt: new Date().toISOString(),
        reason: status === 'rejected' ? 'Rejected from Web Console' : request.reason ?? '',
      },
    });
  }
</script>

<div class="space-y-5">
  <PageHeader title="Committee" subtitle="The BFT committee that certifies every state change." />

  {#if snapshot}
    <div class="grid gap-4 md:grid-cols-4">
      <div class="surface p-4">
        <p class="text-xs uppercase tracking-wide text-slate-500">Certified height</p>
        <p class="mt-1 text-2xl font-semibold text-slate-900">{snapshot.height}</p>
      </div>
      <div class="surface p-4">
        <p class="text-xs uppercase tracking-wide text-slate-500">Committee epoch</p>
        <p class="mt-1 text-2xl font-semibold text-slate-900">{snapshot.qc.committeeEpoch}</p>
      </div>
      <div class="surface p-4">
        <p class="text-xs uppercase tracking-wide text-slate-500">QC signers</p>
        <p class="mt-1 text-2xl font-semibold text-slate-900">{signed.size}/{committee.length}</p>
        <p class="text-xs text-slate-500">quorum {quorumSize}</p>
      </div>
      <div class="surface p-4">
        <p class="text-xs uppercase tracking-wide text-slate-500">Next leader</p>
        <p class="mt-1 text-lg font-semibold text-slate-900">{nextLeader || '—'}</p>
      </div>
    </div>

    <div class="surface p-4">
      <dl class="grid gap-4 text-sm md:grid-cols-3">
        <div>
          <dt class="text-xs uppercase tracking-wide text-slate-500">Leader at this height</dt>
          <dd class="mt-1 font-medium text-slate-800">{snapshot.leaderId || '—'}</dd>
        </div>
        <div>
          <dt class="text-xs uppercase tracking-wide text-slate-500">State hash</dt>
          <dd class="mt-1 font-mono text-xs text-slate-700">{shortHash(snapshot.stateHash, 24)}</dd>
        </div>
        <div>
          <dt class="text-xs uppercase tracking-wide text-slate-500">Transition hash</dt>
          <dd class="mt-1 font-mono text-xs text-slate-700">{shortHash(snapshot.qc.transitionHash, 24)}</dd>
        </div>
      </dl>
    </div>
  {/if}

  <div class="surface">
    <DataTable
      rows={committee}
      columns={[
        { key: 'id', label: 'Manager' },
        { key: 'peer', label: 'Peer ID' },
        { key: 'address', label: 'Transport' },
        { key: 'signed', label: 'Signed this height' },
        { key: 'observed', label: 'Observed' },
      ]}
      rowKey={(member) => member.id}
      emptyTitle="Committee unavailable"
      emptyHint="Connect to a manager to load the committee."
    >
      {#snippet cell(member: CommitteeMember, key: string)}
        {#if key === 'id'}
          <div class="flex items-center gap-2">
            <span class="font-medium text-slate-900">{member.id}</span>
            {#if member.id === nextLeader}<Badge tone="sky" label="next" />{/if}
          </div>
        {:else if key === 'peer'}
          <span class="font-mono text-xs text-slate-600">{shortPeerId(member.peerId, 18)}</span>
        {:else if key === 'address'}
          <span class="font-mono text-xs text-slate-600">{member.address}</span>
        {:else if key === 'signed'}
          <StatusDot online={signed.has(member.id)} label={signed.has(member.id) ? 'signed' : 'not in QC'} />
        {:else if key === 'observed'}
          <TrustBadge observation={presenceFor(member.peerId)} />
        {/if}
      {/snippet}
    </DataTable>
  </div>

  {#if managerJoins.length > 0}
    <div class="surface">
      <div class="mb-3 flex items-center justify-between">
        <div>
          <h2 class="text-sm font-semibold text-slate-900">Manager join requests</h2>
          <p class="text-xs text-slate-500">Approve a candidate before it can enter the next committee epoch.</p>
        </div>
      </div>
      <DataTable
        rows={managerJoins}
        columns={[
          { key: 'managerId', label: 'Manager' },
          { key: 'peerId', label: 'Peer ID' },
          { key: 'address', label: 'Transport' },
          { key: 'status', label: 'Status' },
          { key: 'actions', label: 'Actions' },
        ]}
        rowKey={(request) => request.id}
        emptyTitle="No join requests"
        emptyHint="Candidate managers that present a valid join token appear here."
      >
        {#snippet cell(request: ManagerJoinRequest, key: string)}
          {#if key === 'managerId'}
            <span class="font-medium text-slate-900">{request.managerId}</span>
          {:else if key === 'peerId'}
            <span class="font-mono text-xs text-slate-600">{shortPeerId(request.peerId, 18)}</span>
          {:else if key === 'address'}
            <span class="font-mono text-xs text-slate-600">{request.address}</span>
          {:else if key === 'status'}
            <Badge
              tone={request.status === 'approved' ? 'emerald' : request.status === 'rejected' ? 'rose' : 'slate'}
              label={request.status}
            />
          {:else if key === 'actions'}
            {#if canReviewJoins && request.status === 'pending'}
              <div class="flex gap-2">
                <button
                  class="btn btn-primary"
                  onclick={() => reviewManagerJoin(request, 'approved')}
                >
                  Approve
                </button>
                <button
                  class="btn btn-ghost"
                  onclick={() => reviewManagerJoin(request, 'rejected')}
                >
                  Reject
                </button>
              </div>
            {:else}
              <span class="text-xs text-slate-500">{request.reviewedBy ? `reviewed by ${request.reviewedBy}` : 'waiting for review'}</span>
            {/if}
          {/if}
        {/snippet}
      </DataTable>
    </div>
  {/if}
</div>
