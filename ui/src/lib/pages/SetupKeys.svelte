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
  import { notify } from '../stores/toast.svelte';
  import type { SetupKey } from '../types';

  let query = $state('');
  let editing = $state<SetupKey | null>(null);
  let pendingDelete = $state<SetupKey | null>(null);
  let busy = $state(false);
  // The committee returns the full key, but the console only reveals it once
  // per creation so it does not linger in the UI.
  let revealed = $state('');

  const keys = $derived(network.snapshot?.state.setupKeys ?? []);
  const groupIds = $derived((network.snapshot?.state.groups ?? []).map((group) => group.id));
  const filtered = $derived(
    keys.filter((record) => `${record.key} ${record.groups.join(' ')}`.toLowerCase().includes(query.trim().toLowerCase())),
  );

  function create() {
    revealed = '';
    editing = { key: '', groups: [] };
  }

  async function save() {
    if (!editing) return;
    const key = editing.key.trim();
    if (!key) return notify('Key is required', 'error');
    if (editing.groups.length === 0) return notify('At least one group is required', 'error');
    busy = true;
    const ok = await submit({ type: 'upsert_setup_key', setupKeyRecord: { key, groups: [...editing.groups] } });
    busy = false;
    if (ok) {
      revealed = key;
      notify(`Setup key ${key} committed`);
      editing = null;
    } else {
      notify(network.error || 'commit failed', 'error');
    }
  }

  async function remove(record: SetupKey) {
    busy = true;
    const ok = await submit({ type: 'remove_setup_key', targetId: record.key });
    busy = false;
    pendingDelete = null;
    notify(ok ? `Setup key removed` : network.error || 'commit failed', ok ? 'success' : 'error');
  }
</script>

<div class="space-y-5">
  <PageHeader title="Setup Keys" shown={filtered.length} total={keys.length} subtitle="Registration tokens that place new peers into groups.">
    {#snippet actions()}
      <button class="btn-primary" onclick={create}>Create key</button>
    {/snippet}
  </PageHeader>

  {#if revealed}
    <div class="rounded-xl border border-amber-200 bg-amber-50 p-4">
      <p class="text-sm font-medium text-amber-900">Copy this key now</p>
      <p class="mt-1 text-sm text-amber-800">It is shown once after creation; list rows only confirm the key exists.</p>
      <code class="mt-2 block break-all rounded bg-white px-3 py-2 font-mono text-sm text-slate-800">{revealed}</code>
      <button class="btn-secondary mt-2" onclick={() => (revealed = '')}>Dismiss</button>
    </div>
  {/if}

  <div class="surface">
    <div class="border-b border-slate-200 p-4">
      <FilterBar bind:query placeholder="Search setup keys…" />
    </div>
    <DataTable
      rows={filtered}
      columns={[
        { key: 'key', label: 'Key' },
        { key: 'groups', label: 'Grants groups' },
        { key: 'actions', label: '', align: 'right' },
      ]}
      rowKey={(record) => record.key}
      emptyTitle="No setup keys"
      emptyHint="Create a setup key so clients can register."
    >
      {#snippet cell(record: SetupKey, key: string)}
        {#if key === 'key'}
          <span class="font-mono text-xs text-slate-700">{record.key}</span>
        {:else if key === 'groups'}
          <div class="flex flex-wrap gap-1">
            {#each record.groups as group (group)}<Badge tone="slate" label={group} />{/each}
          </div>
        {:else if key === 'actions'}
          <div class="flex justify-end gap-1">
            <button class="btn-ghost" onclick={() => (editing = { key: record.key, groups: [...record.groups] })}>Edit</button>
            <button class="btn-ghost text-rose-600" onclick={() => (pendingDelete = record)}>Delete</button>
          </div>
        {/if}
      {/snippet}
    </DataTable>
  </div>
</div>

<Drawer open={editing !== null} title={editing?.key ? `Edit ${editing.key}` : 'Create setup key'} onClose={() => (editing = null)}>
  {#if editing}
    <div class="space-y-4">
      <FormField label="Key"><input class="input font-mono" bind:value={editing.key} placeholder="setup-key-name" /></FormField>
      <FormField label="Auto-assign groups">
        <MultiSelect options={groupIds} bind:selected={editing.groups} placeholder="Add group…" />
      </FormField>
    </div>
  {/if}
  {#snippet footer()}
    <button class="btn-secondary" onclick={() => (editing = null)} disabled={busy}>Cancel</button>
    <button class="btn-primary" onclick={save} disabled={busy}>{busy ? 'Committing…' : 'Save'}</button>
  {/snippet}
</Drawer>

<ConfirmDialog
  open={pendingDelete !== null}
  title="Delete setup key"
  message={`Delete ${pendingDelete?.key ?? ''}? New clients will no longer be able to register with it.`}
  busy={busy}
  onCancel={() => (pendingDelete = null)}
  onConfirm={() => pendingDelete && remove(pendingDelete)}
/>
