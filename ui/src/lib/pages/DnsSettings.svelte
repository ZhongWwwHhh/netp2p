<script lang="ts">
  import MultiSelect from '../components/MultiSelect.svelte';
  import PageHeader from '../components/PageHeader.svelte';
  import { network, submit } from '../stores/network.svelte';
  import { can } from '../stores/session.svelte';
  import { notify } from '../stores/toast.svelte';

  let busy = $state(false);
  let disabled = $state(false);
  let groups = $state<string[]>([]);
  let loaded = $state(false);

  const settings = $derived(network.snapshot?.state.dnsSettings);
  const groupIds = $derived((network.snapshot?.state.groups ?? []).map((group) => group.id));
  const canWrite = $derived(can('dns', 'update'));

  // Seed the form from certified state once it arrives, without stomping edits
  // the operator has already started.
  $effect(() => {
    if (loaded || !settings) return;
    disabled = settings.disabled;
    groups = [...(settings.groups ?? [])];
    loaded = true;
  });

  async function save() {
    busy = true;
    const ok = await submit({ type: 'update_dns_settings', dnsSettings: { disabled, groups: [...groups] } });
    busy = false;
    notify(ok ? 'DNS settings committed' : network.error || 'commit failed', ok ? 'success' : 'error');
  }
</script>

<div class="space-y-5">
  <PageHeader title="DNS Settings" subtitle="Network-wide switches for overlay DNS handling." />

  <div class="surface max-w-2xl space-y-5 p-5">
    <label class="flex items-start gap-3">
      <input type="checkbox" class="mt-1" bind:checked={disabled} />
      <span>
        <span class="block text-sm font-medium text-slate-900">Disable overlay DNS</span>
        <span class="block text-sm text-slate-600">Peers keep using their system resolvers for every domain.</span>
      </span>
    </label>

    <div>
      <span class="label">Groups the setting applies to</span>
      <MultiSelect options={groupIds} bind:selected={groups} placeholder="Add group…" />
      <p class="mt-1 text-xs text-slate-500">Empty applies the setting to every peer in the network.</p>
    </div>

    {#if canWrite}
      <div class="flex justify-end">
        <button class="btn-primary" onclick={save} disabled={busy}>{busy ? 'Committing…' : 'Save settings'}</button>
      </div>
    {/if}
  </div>

  <p class="rounded-xl border border-sky-200 bg-sky-50 p-3 text-xs text-sky-800">
    Control plane only. Peers receive these settings inside their certified snapshot but do not apply them until the
    TUN/split-DNS layer is enabled.
  </p>
</div>
