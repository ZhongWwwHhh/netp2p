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
  import type { SetupKey } from '../types';

  let query = $state('');
  let editing = $state<SetupKey | null>(null);
  let pendingDelete = $state<SetupKey | null>(null);
  let pendingRevoke = $state<SetupKey | null>(null);
  let busy = $state(false);
  let revealed = $state('');

  const keys = $derived(network.snapshot?.state.setupKeys ?? []);
  const groupIds = $derived((network.snapshot?.state.groups ?? []).map((group) => group.id));
  const filtered = $derived(
    keys.filter((record) => `${record.name ?? ''} ${record.tokenPrefix ?? ''} ${record.groups.join(' ')}`.toLowerCase().includes(query.trim().toLowerCase())),
  );

  const canWrite = $derived(can('setup_keys', 'update'));
  const canDelete = $derived(can('setup_keys', 'delete'));

  function keyStatus(record: SetupKey): { label: string; tone: 'emerald' | 'rose' | 'amber' | 'slate' } {
    if (record.revoked) return { label: 'revoked', tone: 'rose' };
    if (record.expiresAt && new Date(record.expiresAt) <= new Date()) return { label: 'expired', tone: 'amber' };
    const limit = record.type === 'one-off' ? 1 : record.usageLimit ?? 0;
    if (limit > 0 && (record.usedCount ?? 0) >= limit) return { label: 'exhausted', tone: 'amber' };
    return { label: 'active', tone: 'emerald' };
  }

  function usageLabel(record: SetupKey): string {
    const used = record.usedCount ?? 0;
    const limit = record.type === 'one-off' ? 1 : record.usageLimit ?? 0;
    return limit > 0 ? `${used} / ${limit}` : `${used}`;
  }

  function create() {
    revealed = '';
    editing = { id: '', name: '', type: 'reusable', groups: [], usageLimit: 0, expiresAt: '' };
  }

  async function save() {
    if (!editing) return;
    if (!editing.name?.trim()) return notify('Name is required', 'error');
    if (editing.groups.length === 0) return notify('At least one group is required', 'error');
    busy = true;
    const record: SetupKey = {
      id: crypto.randomUUID(),
      name: editing.name.trim(),
      type: editing.type ?? 'reusable',
      groups: [...editing.groups],
      usageLimit: editing.type === 'one-off' ? 1 : (editing.usageLimit ?? 0),
      expiresAt: editing.expiresAt || '',
    };
    const ok = await submit({ type: 'upsert_setup_key', setupKeyRecord: record });
    busy = false;
    if (ok) {
      // The response snapshot contains the plaintext token; extract it for display.
      const updated = (network.snapshot?.state.setupKeys ?? []).find((k) => k.id === record.id);
      revealed = updated?.token ?? '';
      notify(`Setup key "${record.name}" committed`);
      editing = null;
    } else {
      notify(network.error || 'commit failed', 'error');
    }
  }

  async function revoke(record: SetupKey) {
    busy = true;
    const ok = await submit({ type: 'revoke_setup_key', targetId: record.id });
    busy = false;
    pendingRevoke = null;
    notify(ok ? `Setup key revoked` : network.error || 'revoke failed', ok ? 'success' : 'error');
  }

  async function remove(record: SetupKey) {
    busy = true;
    const ok = await submit({ type: 'remove_setup_key', targetId: record.id });
    busy = false;
    pendingDelete = null;
    notify(ok ? `Setup key removed` : network.error || 'commit failed', ok ? 'success' : 'error');
  }
</script>

<div class="space-y-5">
  <PageHeader title="Setup Keys" shown={filtered.length} total={keys.length} subtitle="Registration tokens that place new peers into groups.">
    {#snippet actions()}
      {#if canWrite}
        <button class="btn-primary" onclick={create}>Create key</button>
      {/if}
    {/snippet}
  </PageHeader>

  {#if revealed}
    <div class="rounded-xl border border-amber-200 bg-amber-50 p-4">
      <p class="text-sm font-medium text-amber-900">Copy this token now</p>
      <p class="mt-1 text-sm text-amber-800">It is shown once after creation; the list only shows a prefix.</p>
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
        { key: 'name', label: 'Name' },
        { key: 'type', label: 'Type' },
        { key: 'groups', label: 'Grants groups' },
        { key: 'expires', label: 'Expires' },
        { key: 'usage', label: 'Used' },
        { key: 'status', label: 'Status' },
        { key: 'actions', label: '', align: 'right' },
      ]}
      rowKey={(record) => record.id}
      emptyTitle="No setup keys"
      emptyHint="Create a setup key so clients can register."
    >
      {#snippet cell(record: SetupKey, key: string)}
        {#if key === 'name'}
          <span class="text-sm text-slate-800">{record.name || record.id}</span>
        {:else if key === 'type'}
          <span class="text-xs text-slate-600">{record.type === 'one-off' ? 'One-off' : 'Reusable'}</span>
        {:else if key === 'groups'}
          <div class="flex flex-wrap gap-1">
            {#each record.groups as group (group)}<Badge tone="slate" label={group} />{/each}
          </div>
        {:else if key === 'expires'}
          <span class="text-xs text-slate-600">{record.expiresAt ? new Date(record.expiresAt).toLocaleDateString() : 'Never'}</span>
        {:else if key === 'usage'}
          <span class="font-mono text-xs text-slate-700">{usageLabel(record)}</span>
        {:else if key === 'status'}
          {@const status = keyStatus(record)}
          <Badge tone={status.tone} label={status.label} />
        {:else if key === 'actions'}
          <div class="flex justify-end gap-1">
            {#if canWrite && !record.revoked && keyStatus(record).label === 'active'}
              <button class="btn-ghost text-amber-600" onclick={() => (pendingRevoke = record)}>Revoke</button>
            {/if}
            {#if canDelete}
              <button class="btn-ghost text-rose-600" onclick={() => (pendingDelete = record)}>Delete</button>
            {/if}
          </div>
        {/if}
      {/snippet}
    </DataTable>
  </div>
</div>

<Drawer open={editing !== null} title="Create setup key" onClose={() => (editing = null)}>
  {#if editing}
    <div class="space-y-4">
      <FormField label="Name"><input class="input" bind:value={editing.name} placeholder="workstation-bootstrap" /></FormField>
      <FormField label="Type">
        <select class="input" bind:value={editing.type}>
          <option value="reusable">Reusable</option>
          <option value="one-off">One-off</option>
        </select>
      </FormField>
      <FormField label="Auto-assign groups">
        <MultiSelect options={groupIds} bind:selected={editing.groups} placeholder="Add group…" />
      </FormField>
      {#if editing.type !== 'one-off'}
        <FormField label="Usage limit (0 = unlimited)">
          <input class="input" type="number" min="0" bind:value={editing.usageLimit} />
        </FormField>
      {/if}
      <FormField label="Expires">
        <select class="input" bind:value={editing.expiresAt}>
          <option value="">Never</option>
          <option value="7d">7 days</option>
          <option value="30d">30 days</option>
          <option value="90d">90 days</option>
        </select>
      </FormField>
    </div>
  {/if}
  {#snippet footer()}
    <button class="btn-secondary" onclick={() => (editing = null)} disabled={busy}>Cancel</button>
    <button class="btn-primary" onclick={save} disabled={busy}>{busy ? 'Committing…' : 'Create key'}</button>
  {/snippet}
</Drawer>

<ConfirmDialog
  open={pendingRevoke !== null}
  title="Revoke setup key"
  message={`Revoke "${pendingRevoke?.name ?? ''}"? Existing peers are unaffected; no new registrations will be accepted.`}
  busy={busy}
  onCancel={() => (pendingRevoke = null)}
  onConfirm={() => pendingRevoke && revoke(pendingRevoke)}
/>

<ConfirmDialog
  open={pendingDelete !== null}
  title="Delete setup key"
  message={`Delete "${pendingDelete?.name ?? ''}"? This removes the key from certified state permanently.`}
  busy={busy}
  onCancel={() => (pendingDelete = null)}
  onConfirm={() => pendingDelete && remove(pendingDelete)}
/>
