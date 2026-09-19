<script lang="ts">
import StatCard from "./lib/StatCard.svelte";
import Panel from "./lib/Panel.svelte";
  import { onMount } from 'svelte';
  import { apiClient, type ApiClient } from './lib/api';
  import type { Bootstrap, Snapshot } from './lib/types';

  let bootstrap = $state<Bootstrap | null>(null);
  let token = $state('');
  let client = $state<ApiClient | null>(null);
  let snapshot = $state<Snapshot | null>(null);
  let busy = $state(false);
  let error = $state('');

  let groupId = $state('');
  let setupKey = $state('');
  let setupGroups = $state('');
  let policyId = $state('');
  let policySource = $state('');
  let policyDestination = $state('');

  onMount(async () => {
    const response = await fetch('/api/bootstrap');
    if (!response.ok) throw new Error(`bootstrap failed: ${response.status}`);
    bootstrap = await response.json();
  });

  async function connect(event: SubmitEvent) {
    event.preventDefault();
    if (!bootstrap) return;
    busy = true;
    error = '';
    let next: ApiClient | null = null;
    try {
      if (client) {
        await client.stop();
        client = null;
      }
      next = await apiClient(bootstrap);
      next.setToken(token);
      client = next;
      await refresh();
    } catch (caught) {
      error = caught instanceof Error ? caught.message : String(caught);
      if (next) {
        await next.stop().catch(() => undefined);
      }
      client = null;
    } finally {
      busy = false;
    }
  }

  async function refresh() {
    if (!client) return;
    snapshot = await client.snapshot();
  }

  async function apply(transition: Parameters<ApiClient['transition']>[0]) {
    busy = true;
    error = '';
    try {
      snapshot = await client!.transition(transition);
    } catch (caught) {
      error = caught instanceof Error ? caught.message : String(caught);
    } finally {
      busy = false;
    }
  }

  function addGroup(event: SubmitEvent) {
    event.preventDefault();
    const id = groupId.trim();
    if (!id) return;
    void apply({ type: 'upsert_group', group: { id } });
    groupId = '';
  }

  function addSetupKey(event: SubmitEvent) {
    event.preventDefault();
    const key = setupKey.trim();
    const groups = setupGroups.split(',').map((value) => value.trim()).filter(Boolean);
    if (!key || groups.length === 0) return;
    void apply({ type: 'upsert_setup_key', setupKeyRecord: { key, groups } });
    setupKey = '';
    setupGroups = '';
  }

  function addPolicy(event: SubmitEvent) {
    event.preventDefault();
    const id = policyId.trim();
    const sourceGroups = policySource.split(',').map((value) => value.trim()).filter(Boolean);
    const destinationGroups = policyDestination.split(',').map((value) => value.trim()).filter(Boolean);
    if (!id || sourceGroups.length === 0 || destinationGroups.length === 0) return;
    void apply({
      type: 'upsert_policy',
      policy: {
        id,
        sourceGroups,
        destinationGroups,
        services: [{ protocol: 'any', startPort: 0, endPort: 0 }],
        effect: 'allow',
        direction: 'bidirectional',
        priority: 10,
      },
    });
    policyId = '';
    policySource = '';
    policyDestination = '';
  }
</script>

<main class="min-h-screen bg-slate-950 text-slate-100">
  <header class="border-b border-slate-800 bg-slate-900/80 px-6 py-4">
    <div class="mx-auto flex max-w-7xl items-center justify-between">
      <h1 class="text-lg font-semibold">NetP2P Console</h1>
      {#if snapshot}
        <span class="text-sm text-slate-400">height {snapshot.height}</span>
      {/if}
    </div>
  </header>

  <section class="mx-auto max-w-7xl px-6 py-8">
    {#if error}
      <p class="mb-6 rounded-lg border border-rose-800 bg-rose-950 p-3 text-rose-200">{error}</p>
    {/if}

    {#if !snapshot}
      <form onsubmit={connect} class="mx-auto mt-16 max-w-sm rounded-2xl border border-slate-800 bg-slate-900 p-6">
        <h2 class="text-xl font-semibold">Sign in</h2>
        <p class="mt-2 text-sm text-slate-400">Manager {bootstrap?.peerId ?? 'loading...'}</p>
        <input bind:value={token} type="password" placeholder="Admin token" class="input mt-5" />
        <button disabled={busy || !bootstrap} class="button mt-4 w-full">Connect over libp2p</button>
      </form>
    {:else}
      <div class="grid gap-4 md:grid-cols-4">
        <StatCard label="Certified height" value={snapshot.height.toString()} />
        <StatCard label="Peers" value={snapshot.state.peers.length.toString()} />
        <StatCard label="Policies" value={snapshot.state.policies.length.toString()} />
        <StatCard label="QC signers" value={`${snapshot.qc.signers.length}/${snapshot.committee.length}`} />
      </div>

      <div class="mt-8 grid gap-6 lg:grid-cols-2">
        <Panel title="Peers">
          {#each snapshot.state.peers as peer (peer.peerId)}
            <div class="flex justify-between gap-4 border-b border-slate-800 py-2 last:border-0">
              <span class="font-mono text-xs">{peer.overlayIp}</span>
              <span class="truncate font-mono text-xs text-slate-400">{peer.peerId}</span>
            </div>
          {/each}
        </Panel>
        <Panel title="Groups">
          {#each snapshot.state.groups as group (group.id)}
            <div class="flex items-center justify-between border-b border-slate-800 py-2 last:border-0">
              <span>{group.id}</span>
              {#if group.managed}<span class="rounded bg-sky-900 px-2 py-0.5 text-xs">SSO</span>{/if}
            </div>
          {/each}
        </Panel>
        <Panel title="Policies">
          {#each snapshot.state.policies as policy (policy.id)}
            <div class="flex justify-between border-b border-slate-800 py-2 last:border-0">
              <span>{policy.id}</span>
              <span class="text-xs text-slate-400">{policy.effect} · {policy.direction}</span>
            </div>
          {/each}
        </Panel>
        <Panel title="Committee">
          {#each snapshot.committee as member (member.id)}
            <div class="flex justify-between border-b border-slate-800 py-2 last:border-0">
              <span>{member.id}</span>
              <span class="text-xs text-slate-400">{snapshot.qc.signers.includes(member.id) ? 'signed' : ''}</span>
            </div>
          {/each}
        </Panel>
      </div>

      <div class="mt-8 grid gap-6 lg:grid-cols-3">
        <form onsubmit={addGroup} class="rounded-2xl border border-slate-800 bg-slate-900 p-4">
          <h3 class="font-medium">Create group</h3>
          <input bind:value={groupId} placeholder="group id" class="input mt-3" />
          <button class="button mt-3">Upsert</button>
        </form>
        <form onsubmit={addSetupKey} class="rounded-2xl border border-slate-800 bg-slate-900 p-4">
          <h3 class="font-medium">Create setup key</h3>
          <input bind:value={setupKey} placeholder="key" class="input mt-3" />
          <input bind:value={setupGroups} placeholder="groups, comma separated" class="input mt-3" />
          <button class="button mt-3">Upsert</button>
        </form>
        <form onsubmit={addPolicy} class="rounded-2xl border border-slate-800 bg-slate-900 p-4">
          <h3 class="font-medium">Create allow policy</h3>
          <input bind:value={policyId} placeholder="policy id" class="input mt-3" />
          <input bind:value={policySource} placeholder="source groups" class="input mt-3" />
          <input bind:value={policyDestination} placeholder="destination groups" class="input mt-3" />
          <button class="button mt-3">Upsert</button>
        </form>
      </div>
    {/if}
  </section>
</main>

<style global>
  .input { width: 100%; border: 1px solid #334155; border-radius: 0.5rem; background: #020617; padding: 0.625rem; font-size: 0.875rem; }
  .button { border-radius: 0.5rem; background: #10b981; padding: 0.625rem 1rem; font-size: 0.875rem; font-weight: 500; color: #020617; }
</style>
