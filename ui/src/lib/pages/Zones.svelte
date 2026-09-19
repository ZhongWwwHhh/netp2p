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
  import type { DNSRecord, DNSZone } from '../types';

  let query = $state('');
  let editing = $state<DNSZone | null>(null);
  let pendingDelete = $state<DNSZone | null>(null);
  let busy = $state(false);

  const zones = $derived(network.snapshot?.state.zones ?? []);
  const groupIds = $derived((network.snapshot?.state.groups ?? []).map((group) => group.id));
  const recordTypes = ['A', 'AAAA', 'CNAME', 'TXT', 'MX', 'SRV'];

  const filtered = $derived(
    zones.filter((zone) => `${zone.id} ${zone.domain}`.toLowerCase().includes(query.trim().toLowerCase())),
  );

  function create() {
    editing = { id: '', domain: '', records: [], groups: [], enabled: true };
  }

  function addRecord() {
    if (!editing) return;
    editing = { ...editing, records: [...editing.records, { name: '', type: 'A', value: '', ttl: 300 }] };
  }

  function updateRecord(index: number, patch: Partial<DNSRecord>) {
    if (!editing) return;
    editing = {
      ...editing,
      records: editing.records.map((record, position) => (position === index ? { ...record, ...patch } : record)),
    };
  }

  function removeRecord(index: number) {
    if (!editing) return;
    editing = { ...editing, records: editing.records.filter((_, position) => position !== index) };
  }

  async function save() {
    if (!editing) return;
    const id = editing.id.trim();
    if (!id) return notify('Zone id is required', 'error');
    if (!editing.domain.trim()) return notify('Domain is required', 'error');
    busy = true;
    const ok = await submit({ type: 'upsert_zone', zone: { ...editing, id } });
    busy = false;
    if (ok) {
      notify(`Zone ${editing.domain} committed`);
      editing = null;
    } else {
      notify(network.error || 'commit failed', 'error');
    }
  }

  async function remove(zone: DNSZone) {
    busy = true;
    const ok = await submit({ type: 'remove_zone', targetId: zone.id });
    busy = false;
    pendingDelete = null;
    notify(ok ? `Zone ${zone.domain} removed` : network.error || 'commit failed', ok ? 'success' : 'error');
  }
</script>

<div class="space-y-5">
  <PageHeader title="Zones" shown={filtered.length} total={zones.length} subtitle="Authoritative records the overlay resolves before falling back to upstream DNS.">
    {#snippet actions()}
      <button class="btn-primary" onclick={create}>Add zone</button>
    {/snippet}
  </PageHeader>

  <p class="rounded-xl border border-sky-200 bg-sky-50 p-3 text-xs text-sky-800">
    Control plane only. Zone resolution on peers arrives with the TUN/split-DNS layer.
  </p>

  <div class="surface">
    <div class="border-b border-slate-200 p-4">
      <FilterBar bind:query placeholder="Search zones…" />
    </div>
    <DataTable
      rows={filtered}
      columns={[
        { key: 'domain', label: 'Zone' },
        { key: 'records', label: 'Records' },
        { key: 'groups', label: 'Applies to' },
        { key: 'state', label: 'State' },
        { key: 'actions', label: '', align: 'right' },
      ]}
      rowKey={(zone) => zone.id}
      emptyTitle="No zones"
      emptyHint="Add a zone to resolve internal names inside the overlay."
    >
      {#snippet cell(zone: DNSZone, key: string)}
        {#if key === 'domain'}
          <span class="font-medium text-slate-900">{zone.domain}</span>
          <div class="font-mono text-xs text-slate-500">{zone.id}</div>
        {:else if key === 'records'}
          <span class="text-sm text-slate-600">{zone.records.length} record(s)</span>
        {:else if key === 'groups'}
          <div class="flex flex-wrap gap-1">
            {#each zone.groups ?? [] as group (group)}<Badge tone="slate" label={group} />{/each}
            {#if (zone.groups ?? []).length === 0}<span class="text-xs text-slate-400">everyone</span>{/if}
          </div>
        {:else if key === 'state'}
          <Badge tone={zone.enabled ? 'emerald' : 'slate'} label={zone.enabled ? 'enabled' : 'disabled'} />
        {:else if key === 'actions'}
          <div class="flex justify-end gap-1">
            <button class="btn-ghost" onclick={() => (editing = { ...zone, records: zone.records.map((record) => ({ ...record })), groups: [...(zone.groups ?? [])] })}>Edit</button>
            <button class="btn-ghost text-rose-600" onclick={() => (pendingDelete = zone)}>Delete</button>
          </div>
        {/if}
      {/snippet}
    </DataTable>
  </div>
</div>

<Drawer open={editing !== null} title={editing?.domain ? `Edit ${editing.domain}` : 'Add zone'} onClose={() => (editing = null)}>
  {#if editing}
    <div class="space-y-4">
      <FormField label="Zone id"><input class="input" bind:value={editing.id} /></FormField>
      <FormField label="Domain"><input class="input font-mono" bind:value={editing.domain} placeholder="internal.example" /></FormField>
      <FormField label="Applies to groups">
        <MultiSelect options={groupIds} bind:selected={editing.groups} placeholder="Add group…" />
      </FormField>
      <FormField label="Records">
        <div class="space-y-2">
          {#each editing.records as record, index (index)}
            <div class="grid grid-cols-12 gap-2">
              <input class="input col-span-4" value={record.name} oninput={(event) => updateRecord(index, { name: event.currentTarget.value })} placeholder="host" />
              <select class="input col-span-2" value={record.type} onchange={(event) => updateRecord(index, { type: event.currentTarget.value })}>
                {#each recordTypes as type (type)}<option value={type}>{type}</option>{/each}
              </select>
              <input class="input col-span-4" value={record.value} oninput={(event) => updateRecord(index, { value: event.currentTarget.value })} placeholder="100.64.0.1" />
              <input class="input col-span-1" type="number" value={record.ttl ?? 0} oninput={(event) => updateRecord(index, { ttl: Number(event.currentTarget.value) })} placeholder="ttl" />
              <button class="btn-ghost col-span-1 text-rose-600" onclick={() => removeRecord(index)} aria-label="Remove record">✕</button>
            </div>
          {/each}
          <button class="btn-secondary" onclick={addRecord}>Add record</button>
        </div>
      </FormField>
      <label class="inline-flex items-center gap-2 text-sm text-slate-700">
        <input type="checkbox" bind:checked={editing.enabled} /> Enabled
      </label>
    </div>
  {/if}
  {#snippet footer()}
    <button class="btn-secondary" onclick={() => (editing = null)} disabled={busy}>Cancel</button>
    <button class="btn-primary" onclick={save} disabled={busy}>{busy ? 'Committing…' : 'Save'}</button>
  {/snippet}
</Drawer>

<ConfirmDialog
  open={pendingDelete !== null}
  title="Delete zone"
  message={`Delete ${pendingDelete?.domain ?? ''}? Names in it will stop resolving inside the overlay.`}
  busy={busy}
  onCancel={() => (pendingDelete = null)}
  onConfirm={() => pendingDelete && remove(pendingDelete)}
/>
