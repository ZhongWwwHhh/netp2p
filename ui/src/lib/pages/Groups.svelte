<script lang="ts">
  import Badge from '../components/Badge.svelte';
  import ConfirmDialog from '../components/ConfirmDialog.svelte';
  import DataTable from '../components/DataTable.svelte';
  import Drawer from '../components/Drawer.svelte';
  import FilterBar from '../components/FilterBar.svelte';
  import FormField from '../components/FormField.svelte';
  import MultiSelect from '../components/MultiSelect.svelte';
  import PageHeader from '../components/PageHeader.svelte';
  import { network, submit } from '../stores/network.svelte';
  import { can } from '../stores/session.svelte';
  import { notify } from '../stores/toast.svelte';
  import type { Group } from '../types';

  let query = $state('');
  let editing = $state<Group | null>(null);
  let pendingDelete = $state<Group | null>(null);
  let busy = $state(false);

  const groups = $derived(network.snapshot?.state.groups ?? []);
  const peers = $derived(network.snapshot?.state.peers ?? []);
  const peerIds = $derived(peers.map((peer) => peer.peerId));

  const filtered = $derived(
    groups.filter((group) => group.id.toLowerCase().includes(query.trim().toLowerCase())),
  );
  const canWrite = $derived(can('groups', 'update'));
  const canDelete = $derived(can('groups', 'delete'));

  function create() {
    editing = { id: '', peerIds: [] };
  }

  async function save() {
    if (!editing) return;
    const id = editing.id.trim();
    if (!id) {
      notify('Group id is required', 'error');
      return;
    }
    busy = true;
    const ok = await submit({
      type: 'upsert_group',
      group: { ...editing, id, peerIds: editing.peerIds ?? [] },
    });
    busy = false;
    if (ok) {
      notify(`Group ${id} committed`);
      editing = null;
    } else {
      notify(network.error || 'commit failed', 'error');
    }
  }

  async function remove(group: Group) {
    busy = true;
    const ok = await submit({ type: 'remove_group', targetId: group.id });
    busy = false;
    pendingDelete = null;
    if (ok) {
      notify(`Group ${group.id} removed`);
    } else {
      notify(network.error || 'commit failed', 'error');
    }
  }
</script>

<div class="space-y-5">
  <PageHeader title="Groups" shown={filtered.length} total={groups.length} subtitle="Authorization unit shared by peers, policies, routes and DNS.">
    {#snippet actions()}
      {#if canWrite}
        <button class="btn-primary" onclick={create}>Create group</button>
      {/if}
    {/snippet}
  </PageHeader>

  <div class="surface">
    <div class="border-b border-slate-200 p-4">
      <FilterBar bind:query placeholder="Search groups…" />
    </div>
    <DataTable
      rows={filtered}
      columns={[
        { key: 'id', label: 'Group' },
        { key: 'source', label: 'Source' },
        { key: 'peers', label: 'Peer members' },
        { key: 'actions', label: '', align: 'right' },
      ]}
      rowKey={(group) => group.id}
      emptyTitle="No groups yet"
      emptyHint="Create a group to start expressing policy."
    >
      {#snippet cell(group: Group, key: string)}
        {#if key === 'id'}
          <span class="font-medium text-slate-900">{group.id}</span>
          {#if group.ssoClaim}
            <div class="text-xs text-slate-500">SSO claim: {group.ssoClaim}</div>
          {/if}
        {:else if key === 'source'}
          <Badge tone={group.managed ? 'sky' : 'slate'} label={group.managed ? 'SSO managed' : 'Manual'} />
        {:else if key === 'peers'}
          <span class="text-sm text-slate-600">{group.peerIds?.length ?? 0} peer(s)</span>
        {:else if key === 'actions'}
          <div class="flex justify-end gap-1">
            {#if canWrite}
              <button class="btn-ghost" onclick={() => (editing = { ...group, peerIds: [...(group.peerIds ?? [])] })}>Edit</button>
            {/if}
            {#if canDelete}
              <button class="btn-ghost text-rose-600" onclick={() => (pendingDelete = group)}>Delete</button>
            {/if}
          </div>
        {/if}
      {/snippet}
    </DataTable>
  </div>
</div>

<Drawer open={editing !== null} title={editing?.id ? `Edit ${editing.id}` : 'Create group'} onClose={() => (editing = null)}>
  {#if editing}
    <div class="space-y-4">
      <FormField label="Group id" hint="Referenced by policies, routes and DNS objects.">
        <input class="input" bind:value={editing.id} disabled={groups.some((group) => group.id === editing?.id)} />
      </FormField>
      <FormField label="Peer members" hint="Type a peer ID and press Enter, or pick from registered peers.">
        <MultiSelect options={peerIds} bind:selected={editing.peerIds} placeholder="Add peer ID…" />
      </FormField>
      {#if editing.managed}
        <p class="rounded-lg border border-sky-200 bg-sky-50 p-3 text-xs text-sky-800">
          This group is managed by an SSO claim; membership is refreshed on login.
        </p>
      {/if}
    </div>
  {/if}
  {#snippet footer()}
    <button class="btn-secondary" onclick={() => (editing = null)} disabled={busy}>Cancel</button>
    <button class="btn-primary" onclick={save} disabled={busy}>{busy ? 'Committing…' : 'Save'}</button>
  {/snippet}
</Drawer>

<ConfirmDialog
  open={pendingDelete !== null}
  title="Delete group"
  message={`Delete ${pendingDelete?.id ?? ''}? Policies or routes referencing it will keep the stale id until updated.`}
  busy={busy}
  onCancel={() => (pendingDelete = null)}
  onConfirm={() => pendingDelete && remove(pendingDelete)}
/>
