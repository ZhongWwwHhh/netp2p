<script lang="ts">
  import { relativeTime } from '../format';
  import { routeTitle, router } from '../router.svelte';
  import { network, refresh, refreshPresence } from '../stores/network.svelte';
  import { session, disconnect } from '../stores/session.svelte';

  let refreshing = $state(false);

  async function reload() {
    refreshing = true;
    await Promise.all([refresh(), refreshPresence()]);
    refreshing = false;
  }
</script>

<header class="flex items-center justify-between border-b border-slate-200 bg-white px-6 py-3">
  <div class="flex items-center gap-3">
    <h2 class="text-sm font-medium text-slate-900">{routeTitle(router.path)}</h2>
    {#if network.snapshot}
      <span class="text-xs text-slate-500">height {network.snapshot.height}</span>
    {/if}
  </div>
  <div class="flex items-center gap-3">
    {#if network.lastRefresh}
      <span class="text-xs text-slate-500">refreshed {relativeTime(network.lastRefresh)}</span>
    {/if}
    <button class="btn-secondary" onclick={reload} disabled={refreshing}>{refreshing ? 'Refreshing…' : 'Refresh'}</button>
    <div class="flex items-center gap-2 border-l border-slate-200 pl-3">
      <div class="text-right">
        <p class="text-xs font-medium text-slate-700">Admin</p>
        <p class="text-xs text-slate-500">{session.bootstrap?.peerId.slice(0, 10) ?? ''}…</p>
      </div>
      <button class="btn-ghost" onclick={() => void disconnect()}>Sign out</button>
    </div>
  </div>
</header>
