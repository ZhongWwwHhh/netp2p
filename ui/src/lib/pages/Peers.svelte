<script lang="ts">
  import Badge from '../components/Badge.svelte';
  import DataTable from '../components/DataTable.svelte';
  import Drawer from '../components/Drawer.svelte';
  import FilterBar from '../components/FilterBar.svelte';
  import PageHeader from '../components/PageHeader.svelte';
  import Skeleton from '../components/Skeleton.svelte';
  import TrustBadge from '../components/TrustBadge.svelte';
  import { relativeTime, shortPeerId } from '../format';
  import { network, presenceFor, submit } from '../stores/network.svelte';
  import { can } from '../stores/session.svelte';
  import { notify } from '../stores/toast.svelte';
  import type { Peer, RouteAssignment } from '../types';

  let query = $state('');
  let statusFilter = $state('');
  let groupFilter = $state('');
  let selected = $state<Peer | null>(null);
  let sortKey = $state('name');
  let sortAsc = $state(true);
  let busy = $state(false);
  let postureDraft = $state('');

  // Keep the posture editor in sync with the selected peer's certified labels.
  $effect(() => {
    postureDraft = (selected?.posture ?? []).join(', ');
  });

  const canWrite = $derived(can('peers', 'update'));

  const peers = $derived(network.snapshot?.state.peers ?? []);
  const groups = $derived(network.snapshot?.state.groups ?? []);
  const assignments = $derived(network.snapshot?.state.assignments ?? []);

  // Assignments are directional, so a peer both originates and receives paths.
  // The certified view is what the committee committed; it is not a live probe.
  function outboundFor(peerId: string): RouteAssignment | undefined {
    return assignments.find((assignment) => assignment.sourcePeerId === peerId);
  }

  function pathsInvolving(peerId: string): RouteAssignment[] {
    return assignments.filter(
      (assignment) => assignment.sourcePeerId === peerId || assignment.destinationPeerId === peerId,
    );
  }

  const filtered = $derived.by(() => {
    const needle = query.trim().toLowerCase();
    const rows = peers.filter((peer) => {
      if (needle && !`${peer.hostname ?? ''} ${peer.overlayIp} ${peer.peerId}`.toLowerCase().includes(needle)) return false;
      if (groupFilter && !(peer.groups ?? []).includes(groupFilter)) return false;
      if (statusFilter) {
        const online = presenceFor(peer.peerId)?.online ?? false;
        if (statusFilter === 'Online' && !online) return false;
        if (statusFilter === 'Offline' && online) return false;
      }
      return true;
    });
    return rows.sort((left, right) => {
      const direction = sortAsc ? 1 : -1;
      if (sortKey === 'address') return left.overlayIp.localeCompare(right.overlayIp) * direction;
      if (sortKey === 'os') return `${left.os ?? ''}`.localeCompare(`${right.os ?? ''}`) * direction;
      if (sortKey === 'lastSeen') {
        const leftSeen = presenceFor(left.peerId)?.lastSeen ?? '';
        const rightSeen = presenceFor(right.peerId)?.lastSeen ?? '';
        return leftSeen.localeCompare(rightSeen) * direction;
      }
      return `${left.hostname ?? left.peerId}`.localeCompare(`${right.hostname ?? right.peerId}`) * direction;
    });
  });

  function sortBy(key: string) {
    if (sortKey === key) {
      sortAsc = !sortAsc;
    } else {
      sortKey = key;
      sortAsc = true;
    }
  }

  const columns = [
    { key: 'name', label: 'Name', sortable: true },
    { key: 'address', label: 'Address', sortable: true },
    { key: 'groups', label: 'Groups' },
    { key: 'role', label: 'Role' },
    { key: 'path', label: 'Path (certified)' },
    { key: 'os', label: 'OS / Version', sortable: true },
    { key: 'lastSeen', label: 'Last seen', sortable: true },
    { key: 'status', label: 'Status' },
  ];

  // Exit nodes are the only peers allowed to gateway internet/subnet traffic.
  // The flag is certified through update_peer, so the toggle is admin-gated.
  async function toggleExitNode(peer: Peer) {
    busy = true;
    const ok = await submit({ type: 'update_peer', peer: { ...peer, isExitNode: !peer.isExitNode } });
    busy = false;
    if (ok) {
      selected = { ...peer, isExitNode: !peer.isExitNode };
      notify(`${peer.hostname || shortPeerId(peer.peerId, 12)} ${peer.isExitNode ? 'is no longer' : 'is now'} an exit node`);
    } else {
      notify(network.error || 'commit failed', 'error');
    }
  }

  // Posture labels are peer-advertised but only certified through update_peer,
  // so editing them is admin-gated.
  async function savePosture(peer: Peer) {
    const posture = postureDraft
      .split(',')
      .map((label) => label.trim())
      .filter((label) => label.length > 0);
    busy = true;
    const ok = await submit({ type: 'update_peer', peer: { ...peer, posture } });
    busy = false;
    if (ok) {
      selected = { ...peer, posture };
      notify('Posture updated');
    } else {
      notify(network.error || 'commit failed', 'error');
    }
  }
</script>

<div class="space-y-5">
  <PageHeader
    title="Peers"
    shown={filtered.length}
    total={peers.length}
    subtitle="Devices and headless machines registered in this network."
  />

  <div class="surface">
    <div class="border-b border-slate-200 p-4">
      <FilterBar
        bind:query
        placeholder="Search by name, peer ID or overlay IP…"
        chips={['Online', 'Offline']}
        activeChip={statusFilter}
        onChip={(chip) => (statusFilter = chip)}
      />
      {#if groups.length > 0}
        <div class="mt-3 flex flex-wrap items-center gap-2">
          <span class="text-xs text-slate-500">Group</span>
          <button
            class={`rounded-full border px-3 py-1 text-xs ${groupFilter === '' ? 'border-emerald-300 bg-emerald-50 text-emerald-700' : 'border-slate-300 bg-white text-slate-600 hover:bg-slate-50'}`}
            onclick={() => (groupFilter = '')}
          >All</button>
          {#each groups as group (group.id)}
            <button
              class={`rounded-full border px-3 py-1 text-xs ${groupFilter === group.id ? 'border-emerald-300 bg-emerald-50 text-emerald-700' : 'border-slate-300 bg-white text-slate-600 hover:bg-slate-50'}`}
              onclick={() => (groupFilter = group.id)}
            >{group.id}</button>
          {/each}
        </div>
      {/if}
    </div>

    {#if network.loading && !network.snapshot}
      <Skeleton />
    {:else}
      <DataTable
        rows={filtered}
        {columns}
        rowKey={(peer) => peer.peerId}
        {sortKey}
        {sortAsc}
        onSort={sortBy}
        emptyTitle="No peers registered"
        emptyHint="Peers appear here once a client logs in with a setup key."
      >
        {#snippet cell(peer: Peer, key: string)}
          {#if key === 'name'}
            <button class="text-left font-medium text-slate-900 hover:text-emerald-700" onclick={() => (selected = peer)}>
              {peer.hostname || shortPeerId(peer.peerId, 14)}
            </button>
            <div class="font-mono text-xs text-slate-400">{shortPeerId(peer.peerId, 18)}</div>
          {:else if key === 'address'}
            <span class="font-mono text-xs text-slate-700">{peer.overlayIp}</span>
          {:else if key === 'groups'}
            <div class="flex flex-wrap gap-1">
              {#each peer.groups ?? [] as group (group)}
                <Badge tone="slate" label={group} />
              {/each}
              {#if (peer.groups ?? []).length === 0}
                <span class="text-xs text-slate-400">none</span>
              {/if}
            </div>
          {:else if key === 'role'}
            {#if peer.isExitNode}
              <Badge tone="sky" label="exit node" />
            {:else}
              <span class="text-xs text-slate-400">—</span>
            {/if}
          {:else if key === 'path'}
            {@const assignment = outboundFor(peer.peerId)}
            {#if assignment}
              <Badge tone={assignment.primary.kind === 'direct' ? 'emerald' : 'sky'} label={assignment.primary.kind} />
              {#if (assignment.primary.managerHops ?? []).length > 0}
                <div class="mt-1 font-mono text-xs text-slate-400">
                  via {(assignment.primary.managerHops ?? []).map((hop) => shortPeerId(hop, 6)).join(' → ')}
                </div>
              {/if}
            {:else}
              <span class="text-xs text-slate-400">—</span>
            {/if}
          {:else if key === 'os'}
            <span class="text-sm text-slate-700">{peer.os || 'unknown'}</span>
            <div class="text-xs text-slate-400">{peer.clientVersion ? `v${peer.clientVersion}` : '—'}</div>
          {:else if key === 'lastSeen'}
            {#if presenceFor(peer.peerId)}
              <span class="text-sm text-slate-600">{relativeTime(presenceFor(peer.peerId)?.lastSeen)}</span>
            {:else}
              <span class="text-xs text-slate-400">—</span>
            {/if}
          {:else if key === 'status'}
            <TrustBadge observation={presenceFor(peer.peerId)} />
          {/if}
        {/snippet}
      </DataTable>
    {/if}
  </div>
</div>

<Drawer open={selected !== null} title={selected?.hostname || 'Peer'} onClose={() => (selected = null)}>
  {#if selected}
    {@const observation = presenceFor(selected.peerId)}
    <dl class="space-y-3 text-sm">
      <div>
        <dt class="text-xs uppercase tracking-wide text-slate-400">Peer ID</dt>
        <dd class="break-all font-mono text-xs text-slate-700">{selected.peerId}</dd>
      </div>
      <div>
        <dt class="text-xs uppercase tracking-wide text-slate-400">Overlay address</dt>
        <dd class="font-mono text-xs text-slate-700">{selected.overlayIp}</dd>
      </div>
      <div>
        <dt class="text-xs uppercase tracking-wide text-slate-400">Groups</dt>
        <dd class="flex flex-wrap gap-1">
          {#each selected.groups ?? [] as group (group)}<Badge tone="slate" label={group} />{/each}
        </dd>
      </div>
      <div>
        <dt class="text-xs uppercase tracking-wide text-slate-400">Exit node</dt>
        <dd class="mt-1 flex items-center gap-2">
          {#if selected.isExitNode}
            <Badge tone="sky" label="enabled" />
          {:else}
            <Badge tone="slate" label="disabled" />
          {/if}
          {#if canWrite}
            <button class="btn-ghost text-xs" disabled={busy} onclick={() => toggleExitNode(selected!)}>
              {selected.isExitNode ? 'Disable' : 'Enable'}
            </button>
          {/if}
        </dd>
        <dd class="mt-1 text-xs text-slate-500">
          Exit nodes may gateway internet or subnet routes (Linux/TUN clients only).
        </dd>
      </div>
      <div>
        <dt class="text-xs uppercase tracking-wide text-slate-400">Posture</dt>
        <dd class="mt-1 flex flex-wrap gap-1">
          {#each selected.posture ?? [] as label (label)}
            <span class="code">{label}</span>
          {/each}
          {#if (selected.posture ?? []).length === 0}
            <span class="text-xs text-slate-400">none</span>
          {/if}
        </dd>
        {#if canWrite}
          <dd class="mt-1 flex items-center gap-2">
            <input
              class="input"
              placeholder="labels, comma separated"
              bind:value={postureDraft}
              disabled={busy}
            />
            <button class="btn-ghost text-xs" disabled={busy} onclick={() => savePosture(selected!)}>Save</button>
          </dd>
          <dd class="mt-1 text-xs text-slate-500">
            Declarative labels matched by policy posture requirements.
          </dd>
        {/if}
      </div>
      <div>
        <dt class="text-xs uppercase tracking-wide text-slate-400">Certified metadata</dt>
        <dd class="text-slate-700">{selected.os || 'unknown'} · {selected.clientVersion ? `v${selected.clientVersion}` : 'unknown version'}</dd>
      </div>
      <div>
        <dt class="text-xs uppercase tracking-wide text-slate-400">Observed state</dt>
        <dd><TrustBadge {observation} /></dd>
        {#if observation}
          <dd class="mt-1 text-xs text-slate-500">Observer: {observation.observer} · {observation.remoteAddr ?? 'unknown address'}</dd>
        {/if}
      </div>
      <div>
        <dt class="text-xs uppercase tracking-wide text-slate-400">Certified paths</dt>
        <dd class="mt-1 space-y-2">
          {#if pathsInvolving(selected.peerId).length === 0}
            <span class="text-xs text-slate-400">no certified assignment</span>
          {:else}
            {#each pathsInvolving(selected.peerId) as assignment (assignment.id)}
              <div class="rounded-lg border border-slate-200 p-2">
                <p class="text-xs text-slate-500">
                  {assignment.sourcePeerId === selected.peerId ? 'outbound' : 'inbound'} ·
                  {shortPeerId(assignment.sourcePeerId, 8)} → {shortPeerId(assignment.destinationPeerId, 8)}
                </p>
                <div class="mt-1 flex items-center gap-2">
                  <Badge tone={assignment.primary.kind === 'direct' ? 'emerald' : 'sky'} label={assignment.primary.kind} />
                  <span class="text-xs text-slate-500">
                    {assignment.primary.rttMilliseconds.toFixed(0)} ms · {assignment.primary.lossPercent.toFixed(1)}% loss
                  </span>
                </div>
                {#if (assignment.primary.managerHops ?? []).length > 0}
                  <p class="mt-1 break-all font-mono text-xs text-slate-400">{(assignment.primary.managerHops ?? []).join(' → ')}</p>
                {/if}
              </div>
            {/each}
          {/if}
        </dd>
      </div>
      <div>
        <dt class="text-xs uppercase tracking-wide text-slate-400">Libp2p addresses</dt>
        <dd class="space-y-1">
          {#each selected.addresses ?? [] as address (address)}
            <p class="break-all font-mono text-xs text-slate-600">{address}</p>
          {/each}
          {#if (selected.addresses ?? []).length === 0}
            <span class="text-xs text-slate-400">none reported</span>
          {/if}
        </dd>
      </div>
    </dl>
  {/if}
</Drawer>
