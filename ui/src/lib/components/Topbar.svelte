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

<header class="flex items-center justify-between border-b border-slate-200 bg-white px-6 py-3">
  <div class="flex items-center gap-3">
    <h2 class="text-sm font-medium text-slate-900">{routeTitle(router.path)}</h2>
    {#if network.snapshot}
      <span class="text-xs text-slate-500">height {network.snapshot.height}</span>
    {/if}
    {#if network.alerts.length > 0}
      <button
        class="inline-flex items-center gap-1 rounded-full bg-amber-100 px-2 py-0.5 text-xs font-medium text-amber-800 hover:bg-amber-200"
        title={network.alerts.map((alert) => alert.summary).join('\n')}
        onclick={() => navigate('/diagnostics')}
      >
        {network.alerts.length} alert{network.alerts.length === 1 ? '' : 's'}
      </button>
    {/if}
  </div>
  <div class="flex items-center gap-3">
    {#if network.lastRefresh}
      <span class="text-xs text-slate-500">refreshed {relativeTime(network.lastRefresh)}</span>
    {/if}
    <button class="btn-secondary" onclick={reload} disabled={refreshing}>{refreshing ? 'Refreshing…' : 'Refresh'}</button>
    <div class="flex items-center gap-2 border-l border-slate-200 pl-3">
      <div class="text-right">
        <p class="text-xs font-medium text-slate-700">{session.identity?.name || session.identity?.email || 'Admin'}</p>
        <p class="text-xs text-slate-500">{session.identity?.email || (session.bootstrap?.peerId.slice(0, 10) ?? '')}</p>
      </div>
      <button class="btn-ghost" onclick={() => (changingPassword = true)}>Password</button>
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
