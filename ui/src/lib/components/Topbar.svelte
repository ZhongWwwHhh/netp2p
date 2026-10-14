<script lang="ts">
  import { relativeTime } from '../format';
  import { navigate, routeTitle, router } from '../router.svelte';
  import { network, refresh, refreshAlerts, refreshPresence } from '../stores/network.svelte';
  import { session, logout } from '../stores/session.svelte';
  import { notify } from '../stores/toast.svelte';

  let refreshing = $state(false);
  let changingPassword = $state(false);
  let busy = $state(false);
  let password = $state('');
  let confirmation = $state('');
  let error = $state('');
  let { onMenu }: { onMenu?: () => void } = $props();

  async function reload() {
    refreshing = true;
    await Promise.all([refresh(), refreshPresence(), refreshAlerts()]);
    refreshing = false;
  }

  async function changePassword() {
    if (!session.client || !session.identity?.userId) return;
    if (password.length < 12 || password !== confirmation) {
      error = 'Passwords must match and contain at least 12 characters.';
      return;
    }
    busy = true;
    error = '';
    try {
      await session.client.updateCredentials(session.identity.userId, { password });
      changingPassword = false;
      password = '';
      confirmation = '';
      await logout();
      notify('Password changed. Sign in again.');
    } catch (caught) {
      error = caught instanceof Error ? caught.message : String(caught);
    } finally {
      busy = false;
    }
  }

  $effect(() => {
    if (network.snapshot) void refreshAlerts();
  });
</script>

<header class="flex min-w-0 items-center justify-between gap-3 border-b border-slate-200 bg-white px-4 py-3 sm:px-6">
  <div class="flex min-w-0 items-center gap-2">
    <button aria-label="Open navigation" class="btn-ghost px-2 lg:hidden" onclick={onMenu}>☰</button>
    <h2 class="truncate text-sm font-medium text-slate-900">{routeTitle(router.path)}</h2>
    {#if network.snapshot}
      <span class="hidden text-xs text-slate-500 sm:inline">height {network.snapshot.height}</span>
    {/if}
    {#if network.alerts.length > 0}
      <button
        class="hidden items-center gap-1 rounded-full bg-amber-100 px-2 py-0.5 text-xs font-medium text-amber-800 hover:bg-amber-200 sm:inline-flex"
        title={network.alerts.map((alert) => alert.summary).join('\n')}
        onclick={() => navigate('/diagnostics')}
      >
        {network.alerts.length} alert{network.alerts.length === 1 ? '' : 's'}
      </button>
    {/if}
  </div>
  <div class="flex shrink-0 items-center gap-2 sm:gap-3">
    {#if network.lastRefresh}
      <span class="hidden text-xs text-slate-500 md:inline">refreshed {relativeTime(network.lastRefresh)}</span>
    {/if}
    <button class="btn-secondary hidden sm:inline-flex" onclick={reload} disabled={refreshing}>{refreshing ? 'Refreshing…' : 'Refresh'}</button>
    <div class="flex items-center gap-2 border-l border-slate-200 pl-3 sm:border-l sm:pl-3">
      <div class="hidden text-right sm:block">
        <p class="text-xs font-medium text-slate-700">{session.identity?.name || session.identity?.email || 'Admin'}</p>
        <p class="text-xs text-slate-500">{session.identity?.email || (session.bootstrap?.peerId.slice(0, 10) ?? '')}</p>
      </div>
      <button class="btn-ghost hidden sm:inline-flex" onclick={() => (changingPassword = true)}>Password</button>
      <button class="btn-ghost" onclick={() => void logout()}>Sign out</button>
    </div>
  </div>
</header>

{#if changingPassword}
  <div class="fixed inset-0 z-50 flex items-center justify-center bg-slate-900/50">
    <form class="surface w-full max-w-md space-y-4 p-5" onsubmit={(event) => { event.preventDefault(); void changePassword(); }}>
      <h3 class="text-lg font-semibold">Change password</h3>
      {#if error}<p class="rounded-xl border border-rose-200 bg-rose-50 p-3 text-sm text-rose-700">{error}</p>{/if}
      <label class="label" for="new-password">New password</label>
      <input id="new-password" class="input" type="password" autocomplete="new-password" bind:value={password} required minlength="12" />
      <label class="label" for="confirm-password">Confirm password</label>
      <input id="confirm-password" class="input" type="password" autocomplete="new-password" bind:value={confirmation} required minlength="12" />
      <div class="flex justify-end gap-2">
        <button type="button" class="btn-secondary" onclick={() => (changingPassword = false)} disabled={busy}>Cancel</button>
        <button type="submit" class="btn-primary" disabled={busy}>{busy ? 'Saving…' : 'Save'}</button>
      </div>
    </form>
  </div>
{/if}
