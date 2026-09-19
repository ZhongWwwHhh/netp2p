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
  import type { Route } from '../types';

  let query = $state('');
  let editing = $state<Route | null>(null);
  let pendingDelete = $state<Route | null>(null);
  let busy = $state(false);

  const routes = $derived(network.snapshot?.state.routes ?? []);
  const groups = $derived((network.snapshot?.state.groups ?? []).map((group) => group.id));
  const budgets = $derived(network.snapshot?.state.budgets ?? []);
  const pathTypes = ['direct', 'relay', 'multi-hop', 'gateway'];

  const filtered = $derived(
    routes.filter((route) =>
      `${route.id} ${route.destination} ${route.routingGroup}`.toLowerCase().includes(query.trim().toLowerCase()),
    ),
  );

  const canWrite = $derived(can('routes', 'update'));
  const canDelete = $derived(can('routes', 'delete'));

  function create() {
    editing = {
      id: '',
      destination: '',
      routingGroup: '',
      distributionGroups: [],
      metric: 100,
      allowedPathTypes: [],
      maxHops: 0,
      budgetIds: [],
    } as Route;
  }

  async function save() {
    if (!editing) return;
    const id = editing.id.trim();
    if (!id) return notify('Route id is required', 'error');
    if (!editing.destination.trim()) return notify('Destination CIDR or domain is required', 'error');
    if (!editing.routingGroup.trim()) return notify('Routing group is required', 'error');
    busy = true;
    const ok = await submit({ type: 'upsert_route', route: { ...editing, id } });
    busy = false;
    if (ok) {
      notify(`Route ${id} committed`);
      editing = null;
    } else {
      notify(network.error || 'commit failed', 'error');
    }
  }

  async function remove(route: Route) {
    busy = true;
    const ok = await submit({ type: 'remove_route', targetId: route.id });
    busy = false;
    pendingDelete = null;
    notify(ok ? `Route ${route.id} removed` : network.error || 'commit failed', ok ? 'success' : 'error');
  }
</script>

<div class="space-y-5">
  <PageHeader title="Routes" shown={filtered.length} total={routes.length} subtitle="Advertise CIDRs or domains through a routing group to distribution groups.">
    {#snippet actions()}
      {#if canWrite}
        <button class="btn-primary" onclick={create}>Add route</button>
      {/if}
    {/snippet}
  </PageHeader>

  <div class="surface">
    <div class="border-b border-slate-200 p-4">
      <FilterBar bind:query placeholder="Search routes…" />
    </div>
    <DataTable
      rows={filtered}
      columns={[
        { key: 'id', label: 'Route' },
        { key: 'destination', label: 'Destination' },
        { key: 'routing', label: 'Routing group' },
        { key: 'distribution', label: 'Distribution' },
        { key: 'paths', label: 'Allowed paths' },
        { key: 'metric', label: 'Metric', align: 'right' },
        { key: 'actions', label: '', align: 'right' },
      ]}
      rowKey={(route) => route.id}
      emptyTitle="No routes"
      emptyHint="Add a route so peers can reach networks behind a routing peer."
    >
      {#snippet cell(route: Route, key: string)}
        {#if key === 'id'}
          <span class="font-medium text-slate-900">{route.id}</span>
        {:else if key === 'destination'}
          <span class="font-mono text-xs text-slate-700">{route.destination}</span>
        {:else if key === 'routing'}
          <Badge tone="sky" label={route.routingGroup} />
        {:else if key === 'distribution'}
          <div class="flex flex-wrap gap-1">
            {#each route.distributionGroups as group (group)}<Badge tone="slate" label={group} />{/each}
            {#if route.distributionGroups.length === 0}<span class="text-xs text-slate-400">everyone</span>{/if}
          </div>
        {:else if key === 'paths'}
          <div class="flex flex-wrap gap-1">
            {#each route.allowedPathTypes ?? [] as path (path)}<span class="code">{path}</span>{/each}
            {#if (route.allowedPathTypes ?? []).length === 0}<span class="text-xs text-slate-400">any</span>{/if}
          </div>
        {:else if key === 'metric'}
          <span class="text-sm text-slate-600">{route.metric}</span>
        {:else if key === 'actions'}
          <div class="flex justify-end gap-1">
            {#if canWrite}
              <button class="btn-ghost" onclick={() => (editing = { ...route, distributionGroups: [...route.distributionGroups], allowedPathTypes: [...(route.allowedPathTypes ?? [])], budgetIds: [...(route.budgetIds ?? [])] })}>Edit</button>
            {/if}
            {#if canDelete}
              <button class="btn-ghost text-rose-600" onclick={() => (pendingDelete = route)}>Delete</button>
            {/if}
          </div>
        {/if}
      {/snippet}
    </DataTable>
  </div>
</div>

<Drawer open={editing !== null} title={editing?.id ? `Edit ${editing.id}` : 'Add route'} onClose={() => (editing = null)}>
  {#if editing}
    <div class="space-y-4">
      <FormField label="Route id"><input class="input" bind:value={editing.id} /></FormField>
      <FormField label="Destination" hint="CIDR or DNS suffix reachable through the routing group.">
        <input class="input font-mono" bind:value={editing.destination} placeholder="10.10.0.0/16" />
      </FormField>
      <FormField label="Routing group" hint="Peers in this group forward the traffic.">
        <input class="input" bind:value={editing.routingGroup} placeholder="servers" />
      </FormField>
      <FormField label="Distribution groups" hint="Who may use this route. Empty means every peer.">
        <MultiSelect options={groups} bind:selected={editing.distributionGroups} placeholder="Add distribution group…" />
      </FormField>
      <FormField label="Allowed path types" hint="Empty allows every path the client can measure.">
        <div class="flex flex-wrap gap-2">
          {#each pathTypes as path (path)}
            <label class="inline-flex items-center gap-1.5 text-sm text-slate-700">
              <input
                type="checkbox"
                checked={(editing.allowedPathTypes ?? []).includes(path)}
                onchange={(event) => {
                  if (!editing) return;
                  const current = editing.allowedPathTypes ?? [];
                  editing = {
                    ...editing,
                    allowedPathTypes: event.currentTarget.checked
                      ? [...current, path]
                      : current.filter((value) => value !== path),
                  };
                }}
              />
              {path}
            </label>
          {/each}
        </div>
      </FormField>
      <div class="grid grid-cols-2 gap-4">
        <FormField label="Metric"><input class="input" type="number" bind:value={editing.metric} /></FormField>
        <FormField label="Max hops" hint="0 means unlimited."><input class="input" type="number" bind:value={editing.maxHops} /></FormField>
      </div>
      <FormField label="Traffic budgets">
        <MultiSelect options={budgets.map((budget) => budget.id)} bind:selected={editing.budgetIds} placeholder="Attach budget…" />
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
  title="Delete route"
  message={`Delete ${pendingDelete?.id ?? ''}? Peers will lose reachability through it.`}
  busy={busy}
  onCancel={() => (pendingDelete = null)}
  onConfirm={() => pendingDelete && remove(pendingDelete)}
/>
