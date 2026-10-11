<script lang="ts">
  import ConfirmDialog from '../components/ConfirmDialog.svelte';
  import DataTable from '../components/DataTable.svelte';
  import Drawer from '../components/Drawer.svelte';
  import FilterBar from '../components/FilterBar.svelte';
  import FormField from '../components/FormField.svelte';
  import MultiSelect from '../components/MultiSelect.svelte';
  import PageHeader from '../components/PageHeader.svelte';
  import ProgressBar from '../components/ProgressBar.svelte';
  import { bitrateLabel, bytesLabel, percent } from '../format';
  import { network, submit } from '../stores/network.svelte';
  import { can } from '../stores/session.svelte';
  import { notify } from '../stores/toast.svelte';
  import type { Budget } from '../types';

  let query = $state('');
  let editing = $state<Budget | null>(null);
  let pendingDelete = $state<Budget | null>(null);
  let busy = $state(false);

  const budgets = $derived(network.snapshot?.state.budgets ?? []);
  const subjectTypes = ['user', 'group', 'peer', 'route', 'service', 'manager'];
  const exhaustActions = ['block', 'throttle', 'degrade', 'switch-path'];

  const filtered = $derived(
    budgets.filter((budget) => `${budget.id} ${budget.subjectType} ${budget.subjectId}`.toLowerCase().includes(query.trim().toLowerCase())),
  );
  const canWrite = $derived(can('budgets', 'update'));
  const canDelete = $derived(can('budgets', 'delete'));

  function create() {
    editing = {
      id: '',
      subjectType: 'group',
      subjectId: '',
      dailyBytes: 0,
      monthlyBytes: 0,
      peakBps: 0,
      peakBurstBytes: 0,
      forwardingCostLimit: 0,
      onExhausted: 'throttle',
      usedDailyBytes: 0,
      usedMonthlyBytes: 0,
    } as Budget;
  }

  async function save() {
    if (!editing) return;
    const id = editing.id.trim();
    if (!id) return notify('Budget id is required', 'error');
    if (!editing.subjectId.trim()) return notify('Subject id is required', 'error');
    busy = true;
    const ok = await submit({ type: 'upsert_budget', budget: { ...editing, id } });
    busy = false;
    if (ok) {
      notify(`Budget ${id} committed`);
      editing = null;
    } else {
      notify(network.error || 'commit failed', 'error');
    }
  }

  async function remove(budget: Budget) {
    busy = true;
    const ok = await submit({ type: 'remove_budget', targetId: budget.id });
    busy = false;
    pendingDelete = null;
    notify(ok ? `Budget ${budget.id} removed` : network.error || 'commit failed', ok ? 'success' : 'error');
  }
</script>

<div class="space-y-5">
  <PageHeader title="Traffic Budgets" shown={filtered.length} total={budgets.length} subtitle="Rate and volume limits attached to peers, groups, routes or services.">
    {#snippet actions()}
      {#if canWrite}
        <button class="btn-primary" onclick={create}>Create budget</button>
      {/if}
    {/snippet}
  </PageHeader>

  <div class="surface">
    <div class="border-b border-slate-200 p-4">
      <FilterBar bind:query placeholder="Search budgets…" />
    </div>
    <DataTable
      rows={filtered}
      columns={[
        { key: 'id', label: 'Budget' },
        { key: 'subject', label: 'Applies to' },
        { key: 'daily', label: 'Daily usage' },
        { key: 'monthly', label: 'Monthly usage' },
        { key: 'peak', label: 'Peak rate', align: 'right' },
        { key: 'exhausted', label: 'On exhaustion' },
        { key: 'actions', label: '', align: 'right' },
      ]}
      rowKey={(budget) => budget.id}
      emptyTitle="No traffic budgets"
      emptyHint="Budgets appear here once the committee certifies them."
    >
      {#snippet cell(budget: Budget, key: string)}
        {#if key === 'id'}
          <span class="font-medium text-slate-900">{budget.id}</span>
        {:else if key === 'subject'}
          <span class="text-sm text-slate-700">{budget.subjectType}</span>
          <div class="font-mono text-xs text-slate-500">{budget.subjectId}</div>
        {:else if key === 'daily'}
          <div class="w-40 space-y-1">
            <ProgressBar value={percent(budget.usedDailyBytes, budget.dailyBytes)} />
            <p class="text-xs text-slate-500">
              {bytesLabel(budget.usedDailyBytes)} / {budget.dailyBytes ? bytesLabel(budget.dailyBytes) : 'unlimited'}
            </p>
          </div>
        {:else if key === 'monthly'}
          <div class="w-40 space-y-1">
            <ProgressBar value={percent(budget.usedMonthlyBytes, budget.monthlyBytes)} />
            <p class="text-xs text-slate-500">
              {bytesLabel(budget.usedMonthlyBytes)} / {budget.monthlyBytes ? bytesLabel(budget.monthlyBytes) : 'unlimited'}
            </p>
          </div>
        {:else if key === 'peak'}
          <span class="text-sm text-slate-600">{bitrateLabel(budget.peakBps)}</span>
        {:else if key === 'exhausted'}
          <span class="code">{budget.onExhausted || 'none'}</span>
        {:else if key === 'actions'}
          <div class="flex justify-end gap-1">
            {#if canWrite}
              <button class="btn-ghost" onclick={() => (editing = { ...budget })}>Edit</button>
            {/if}
            {#if canDelete}
              <button class="btn-ghost text-rose-600" onclick={() => (pendingDelete = budget)}>Delete</button>
            {/if}
          </div>
        {/if}
      {/snippet}
    </DataTable>
  </div>
</div>

<Drawer open={editing !== null} title={editing?.id ? `Edit ${editing.id}` : 'Create budget'} onClose={() => (editing = null)}>
  {#if editing}
    <div class="space-y-4">
      <FormField label="Budget id"><input class="input" bind:value={editing.id} /></FormField>
      <div class="grid grid-cols-2 gap-4">
        <FormField label="Subject type">
          <select class="input" bind:value={editing.subjectType}>
            {#each subjectTypes as type (type)}<option value={type}>{type}</option>{/each}
          </select>
        </FormField>
        <FormField label="Subject id"><input class="input" bind:value={editing.subjectId} /></FormField>
      </div>
      <div class="grid grid-cols-2 gap-4">
        <FormField label="Daily bytes" hint="0 means unlimited.">
          <input class="input" type="number" min="0" bind:value={editing.dailyBytes} />
        </FormField>
        <FormField label="Monthly bytes" hint="0 means unlimited.">
          <input class="input" type="number" min="0" bind:value={editing.monthlyBytes} />
        </FormField>
      </div>
      <div class="grid grid-cols-2 gap-4">
        <FormField label="Peak rate (bps)" hint="0 means unlimited.">
          <input class="input" type="number" min="0" bind:value={editing.peakBps} />
        </FormField>
        <FormField label="Peak burst (bytes)" hint="Token bucket burst; 0 uses the rate.">
          <input class="input" type="number" min="0" bind:value={editing.peakBurstBytes} />
        </FormField>
      </div>
      <div class="grid grid-cols-2 gap-4">
        <FormField label="Forwarding cost limit">
          <input class="input" type="number" min="0" bind:value={editing.forwardingCostLimit} />
        </FormField>
        <FormField label="On exhaustion">
          <select class="input" bind:value={editing.onExhausted}>
            {#each exhaustActions as action (action)}<option value={action}>{action}</option>{/each}
          </select>
        </FormField>
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
  title="Delete budget"
  message={`Delete ${pendingDelete?.id ?? ''}? Routes referencing it will lose their limit.`}
  busy={busy}
  onCancel={() => (pendingDelete = null)}
  onConfirm={() => pendingDelete && remove(pendingDelete)}
/>
