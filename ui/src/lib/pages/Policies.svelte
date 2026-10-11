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
  import type { FlowClass, Policy, Service } from '../types';

  let query = $state('');
  let editing = $state<Policy | null>(null);
  let pendingDelete = $state<Policy | null>(null);
  let busy = $state(false);

  const policies = $derived(network.snapshot?.state.policies ?? []);
  const groupIds = $derived((network.snapshot?.state.groups ?? []).map((group) => group.id));
  const flowClasses: (FlowClass | '')[] = ['', 'latency', 'throughput', 'cost', 'reliability', 'realtime'];
  const filtered = $derived(
    policies.filter((policy) =>
      `${policy.id} ${policy.sourceGroups.join(' ')} ${policy.destinationGroups.join(' ')}`
        .toLowerCase()
        .includes(query.trim().toLowerCase()),
    ),
  );

  const canWrite = $derived(can('policies', 'update'));
  const canDelete = $derived(can('policies', 'delete'));

  function create() {
    editing = {
      id: '',
      sourceGroups: [],
      destinationGroups: [],
      services: [{ protocol: 'tcp', startPort: 0, endPort: 0 }],
      effect: 'allow',
      direction: 'bidirectional',
      priority: 10,
      flowClass: '',
    } as Policy;
  }

  function addService() {
    editing?.services.push({ protocol: 'tcp', startPort: 0, endPort: 0 });
    if (editing) editing = { ...editing, services: [...editing.services] };
  }

  function removeService(index: number) {
    if (!editing) return;
    editing = { ...editing, services: editing.services.filter((_, position) => position !== index) };
  }

  function serviceLabel(service: Service): string {
    if (!service.protocol || service.protocol === 'any') return 'any';
    if (!service.startPort && !service.endPort) return service.protocol;
    if (service.startPort === service.endPort) return `${service.protocol}/${service.startPort}`;
    return `${service.protocol}/${service.startPort}-${service.endPort}`;
  }

  async function save() {
    if (!editing) return;
    const id = editing.id.trim();
    if (!id) return notify('Policy id is required', 'error');
    if (editing.sourceGroups.length === 0 || editing.destinationGroups.length === 0) {
      return notify('Source and destination groups are required', 'error');
    }
    busy = true;
    const ok = await submit({ type: 'upsert_policy', policy: { ...editing, id } });
    busy = false;
    if (ok) {
      notify(`Policy ${id} committed`);
      editing = null;
    } else {
      notify(network.error || 'commit failed', 'error');
    }
  }

  async function remove(policy: Policy) {
    busy = true;
    const ok = await submit({ type: 'remove_policy', targetId: policy.id });
    busy = false;
    pendingDelete = null;
    notify(ok ? `Policy ${policy.id} removed` : network.error || 'commit failed', ok ? 'success' : 'error');
  }
</script>

<div class="space-y-5">
  <PageHeader title="Policies" shown={filtered.length} total={policies.length} subtitle="Decide which groups may reach which groups, over which protocols.">
    {#snippet actions()}
      {#if canWrite}
        <button class="btn-primary" onclick={create}>Create policy</button>
      {/if}
    {/snippet}
  </PageHeader>

  <div class="surface">
    <div class="border-b border-slate-200 p-4">
      <FilterBar bind:query placeholder="Search policies…" />
    </div>
    <DataTable
      rows={filtered}
      columns={[
        { key: 'id', label: 'Policy' },
        { key: 'source', label: 'Source' },
        { key: 'destination', label: 'Destination' },
        { key: 'services', label: 'Protocol / port' },
        { key: 'flow', label: 'Flow class' },
        { key: 'direction', label: 'Direction' },
        { key: 'priority', label: 'Priority', align: 'right' },
        { key: 'actions', label: '', align: 'right' },
      ]}
      rowKey={(policy) => policy.id}
      emptyTitle="No policies yet"
      emptyHint="Without an allow policy, peers cannot reach each other."
    >
      {#snippet cell(policy: Policy, key: string)}
        {#if key === 'id'}
          <span class="font-medium text-slate-900">{policy.id}</span>
          <div class="mt-0.5"><Badge tone={policy.effect === 'allow' ? 'emerald' : 'rose'} label={policy.effect} /></div>
        {:else if key === 'source'}
          <div class="flex flex-wrap gap-1">
            {#each policy.sourceGroups as group (group)}<Badge tone="slate" label={group} />{/each}
          </div>
        {:else if key === 'destination'}
          <div class="flex flex-wrap gap-1">
            {#each policy.destinationGroups as group (group)}<Badge tone="slate" label={group} />{/each}
          </div>
        {:else if key === 'services'}
          <div class="flex flex-wrap gap-1">
            {#each policy.services as service (serviceLabel(service))}
              <span class="code">{serviceLabel(service)}</span>
            {/each}
          </div>
        {:else if key === 'direction'}
          <span class="text-sm text-slate-600">{policy.direction === 'bidirectional' ? 'both ways' : 'one way'}</span>
        {:else if key === 'flow'}
          <Badge tone="sky" label={policy.flowClass || 'inherit'} />
        {:else if key === 'priority'}
          <span class="text-sm text-slate-600">{policy.priority}</span>
        {:else if key === 'actions'}
          <div class="flex justify-end gap-1">
            {#if canWrite}
              <button class="btn-ghost" onclick={() => (editing = { ...policy, services: policy.services.map((service) => ({ ...service })) })}>Edit</button>
            {/if}
            {#if canDelete}
              <button class="btn-ghost text-rose-600" onclick={() => (pendingDelete = policy)}>Delete</button>
            {/if}
          </div>
        {/if}
      {/snippet}
    </DataTable>
  </div>
</div>

<Drawer open={editing !== null} title={editing?.id ? `Edit ${editing.id}` : 'Create policy'} onClose={() => (editing = null)}>
  {#if editing}
    <div class="space-y-4">
      <FormField label="Policy id"><input class="input" bind:value={editing.id} /></FormField>
      <div class="grid grid-cols-2 gap-4">
        <FormField label="Effect">
          <select class="input" bind:value={editing.effect}>
            <option value="allow">allow</option>
            <option value="deny">deny</option>
          </select>
        </FormField>
        <FormField label="Direction">
          <select class="input" bind:value={editing.direction}>
            <option value="bidirectional">bidirectional</option>
            <option value="unidirectional">unidirectional</option>
          </select>
        </FormField>
      </div>
      <FormField label="Source groups">
        <MultiSelect options={groupIds} bind:selected={editing.sourceGroups} placeholder="Add source group…" />
      </FormField>
      <FormField label="Destination groups">
        <MultiSelect options={groupIds} bind:selected={editing.destinationGroups} placeholder="Add destination group…" />
      </FormField>
      <FormField label="Protocols and ports">
        <div class="space-y-2">
          {#each editing.services as service, index (index)}
            <div class="flex items-center gap-2">
              <input class="input" bind:value={service.protocol} placeholder="tcp / udp / icmp / any" />
              <input class="input w-24" type="number" min="0" max="65535" bind:value={service.startPort} placeholder="from" />
              <input class="input w-24" type="number" min="0" max="65535" bind:value={service.endPort} placeholder="to" />
              <button class="btn-ghost text-rose-600" onclick={() => removeService(index)} aria-label="Remove protocol">✕</button>
            </div>
          {/each}
          <button class="btn-secondary" onclick={addService}>Add protocol</button>
        </div>
      </FormField>
      <FormField label="Flow class">
        <select class="input" bind:value={editing.flowClass}>
          {#each flowClasses as flowClass (flowClass)}
            <option value={flowClass}>{flowClass || 'inherit'}</option>
          {/each}
        </select>
      </FormField>
      <FormField label="Priority" hint="Higher priority deny rules win over lower priority allow rules.">
        <input class="input" type="number" bind:value={editing.priority} />
      </FormField>
      <FormField label="Posture requirements" hint="Optional labels the peer must satisfy. Empty means no requirement.">
        <MultiSelect options={[]} bind:selected={editing.postureRequirements} placeholder="Add posture label…" />
      </FormField>
      <FormField label="Link constraints" hint="Optional path constraints, for example relay-free.">
        <MultiSelect options={[]} bind:selected={editing.linkConstraints} placeholder="Add link constraint…" />
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
  title="Delete policy"
  message={`Delete ${pendingDelete?.id ?? ''}? Traffic it currently allows will be blocked.`}
  busy={busy}
  onCancel={() => (pendingDelete = null)}
  onConfirm={() => pendingDelete && remove(pendingDelete)}
/>
