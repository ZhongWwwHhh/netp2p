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
  import type { Nameserver } from '../types';

  let query = $state('');
  let editing = $state<Nameserver | null>(null);
  let pendingDelete = $state<Nameserver | null>(null);
  let busy = $state(false);
  let serverDraft = $state('');

  const nameservers = $derived(network.snapshot?.state.nameservers ?? []);
  const groupIds = $derived((network.snapshot?.state.groups ?? []).map((group) => group.id));
  const filtered = $derived(
    nameservers.filter((entry) => `${entry.id} ${entry.name} ${entry.servers.join(' ')}`.toLowerCase().includes(query.trim().toLowerCase())),
  );

  function create() {
    serverDraft = '';
    editing = { id: '', name: '', groups: [], matchDomains: [], servers: [], primary: false, enabled: true };
  }

  function addServer() {
    if (!editing) return;
    const value = serverDraft.trim();
    if (!value) return;
    editing = { ...editing, servers: [...editing.servers, value] };
    serverDraft = '';
  }

  function removeServer(value: string) {
    if (!editing) return;
    editing = { ...editing, servers: editing.servers.filter((server) => server !== value) };
  }

  async function save() {
    if (!editing) return;
    const id = editing.id.trim();
    if (!id) return notify('Nameserver id is required', 'error');
    if (editing.servers.length === 0) return notify('At least one server address is required', 'error');
    busy = true;
    const ok = await submit({ type: 'upsert_nameserver', nameserver: { ...editing, id } });
    busy = false;
    if (ok) {
      notify(`Nameserver ${id} committed`);
      editing = null;
    } else {
      notify(network.error || 'commit failed', 'error');
    }
  }

  async function remove(entry: Nameserver) {
    busy = true;
    const ok = await submit({ type: 'remove_nameserver', targetId: entry.id });
    busy = false;
    pendingDelete = null;
    notify(ok ? `Nameserver ${entry.id} removed` : network.error || 'commit failed', ok ? 'success' : 'error');
  }
</script>

<div class="space-y-5">
  <PageHeader title="Nameservers" shown={filtered.length} total={nameservers.length} subtitle="Resolvers the overlay hands to peers, optionally scoped to match domains.">
    {#snippet actions()}
      <button class="btn-primary" onclick={create}>Add nameserver</button>
    {/snippet}
  </PageHeader>

  <p class="rounded-xl border border-sky-200 bg-sky-50 p-3 text-xs text-sky-800">
    Control plane only. Applying these resolvers on a client requires the TUN/split-DNS layer, which is not enabled yet.
  </p>

  <div class="surface">
    <div class="border-b border-slate-200 p-4">
      <FilterBar bind:query placeholder="Search nameservers…" />
    </div>
    <DataTable
      rows={filtered}
      columns={[
        { key: 'id', label: 'Nameserver' },
        { key: 'servers', label: 'Servers' },
        { key: 'domains', label: 'Match domains' },
        { key: 'groups', label: 'Applies to' },
        { key: 'state', label: 'State' },
        { key: 'actions', label: '', align: 'right' },
      ]}
      rowKey={(entry) => entry.id}
      emptyTitle="No nameservers"
      emptyHint="Add a nameserver to push DNS configuration to peers."
    >
      {#snippet cell(entry: Nameserver, key: string)}
        {#if key === 'id'}
          <span class="font-medium text-slate-900">{entry.name || entry.id}</span>
          <div class="font-mono text-xs text-slate-500">{entry.id}</div>
        {:else if key === 'servers'}
          <div class="flex flex-wrap gap-1">
            {#each entry.servers as server (server)}<span class="code">{server}</span>{/each}
          </div>
        {:else if key === 'domains'}
          <div class="flex flex-wrap gap-1">
            {#each entry.matchDomains ?? [] as domain (domain)}<Badge tone="slate" label={domain} />{/each}
            {#if (entry.matchDomains ?? []).length === 0}<span class="text-xs text-slate-400">all domains</span>{/if}
          </div>
        {:else if key === 'groups'}
          <div class="flex flex-wrap gap-1">
            {#each entry.groups as group (group)}<Badge tone="slate" label={group} />{/each}
            {#if entry.groups.length === 0}<span class="text-xs text-slate-400">everyone</span>{/if}
          </div>
        {:else if key === 'state'}
          <div class="flex items-center gap-1">
            <Badge tone={entry.enabled ? 'emerald' : 'slate'} label={entry.enabled ? 'enabled' : 'disabled'} />
            {#if entry.primary}<Badge tone="sky" label="primary" />{/if}
          </div>
        {:else if key === 'actions'}
          <div class="flex justify-end gap-1">
            <button class="btn-ghost" onclick={() => (editing = { ...entry, groups: [...entry.groups], matchDomains: [...(entry.matchDomains ?? [])], servers: [...entry.servers] })}>Edit</button>
            <button class="btn-ghost text-rose-600" onclick={() => (pendingDelete = entry)}>Delete</button>
          </div>
        {/if}
      {/snippet}
    </DataTable>
  </div>
</div>

<Drawer open={editing !== null} title={editing?.id ? `Edit ${editing.id}` : 'Add nameserver'} onClose={() => (editing = null)}>
  {#if editing}
    <div class="space-y-4">
      <FormField label="Nameserver id"><input class="input" bind:value={editing.id} /></FormField>
      <FormField label="Display name"><input class="input" bind:value={editing.name} placeholder="Corporate DNS" /></FormField>
      <FormField label="Server addresses">
        <div class="space-y-2">
          <div class="flex gap-2">
            <input class="input" bind:value={serverDraft} placeholder="1.1.1.1" onkeydown={(event) => event.key === 'Enter' && (event.preventDefault(), addServer())} />
            <button class="btn-secondary" onclick={addServer}>Add</button>
          </div>
          <div class="flex flex-wrap gap-1">
            {#each editing.servers as server (server)}
              <span class="inline-flex items-center gap-1 rounded-full bg-slate-100 px-2 py-0.5 text-xs text-slate-700">
                {server}
                <button class="text-slate-400 hover:text-rose-600" onclick={() => removeServer(server)} aria-label={`Remove ${server}`}>✕</button>
              </span>
            {/each}
          </div>
        </div>
      </FormField>
      <FormField label="Match domains" hint="Empty matches every domain. Otherwise this resolver is used only for these suffixes.">
        <MultiSelect options={[]} bind:selected={editing.matchDomains} placeholder="Add domain suffix…" />
      </FormField>
      <FormField label="Applies to groups">
        <MultiSelect options={groupIds} bind:selected={editing.groups} placeholder="Add group…" />
      </FormField>
      <div class="flex gap-6">
        <label class="inline-flex items-center gap-2 text-sm text-slate-700">
          <input type="checkbox" bind:checked={editing.enabled} /> Enabled
        </label>
        <label class="inline-flex items-center gap-2 text-sm text-slate-700">
          <input type="checkbox" bind:checked={editing.primary} /> Primary
        </label>
      </div>
    </div>
  {/if}
  {#snippet footer()}
    <button class="btn-secondary" onclick={() => (editing = null)} disabled={busy}>Cancel</button>
    <button class="btn-primary" onclick={save} disabled={busy}>{busy ? 'Committing…' : 'Save'}</button>
  {/snippet}
</Drawer>

<ConfirmDialog
  open={pendingDelete !== null}
  title="Delete nameserver"
  message={`Delete ${pendingDelete?.id ?? ''}? Peers using it will fall back to their other resolvers.`}
  busy={busy}
  onCancel={() => (pendingDelete = null)}
  onConfirm={() => pendingDelete && remove(pendingDelete)}
/>
