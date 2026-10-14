<script lang="ts">
  import {
    bootstrapOwner, connect, loadAuthStatus, loadBootstrap, loginLocal, resumeSession, session,
  } from '../stores/session.svelte';
  import { onMount } from 'svelte';
  import { refresh, refreshPresence } from '../stores/network.svelte';

  let email = $state('');
  let name = $state('');
  let password = $state('');
  let confirmPassword = $state('');
  let adminToken = $state('');
  let ssoPending = $state(false);

  loadBootstrap();
  loadAuthStatus();

  onMount(() => {
    void resumeSession().then((resumed) => {
      if (resumed) void Promise.all([refresh(), refreshPresence()]);
    });
  });

  const needsOwner = $derived(session.authStatus?.needsOwner ?? false);

  async function finishLogin(token = '') {
    if (await connect(token)) {
      await Promise.all([refresh(), refreshPresence()]);
    }
  }

  async function submit(event: SubmitEvent) {
    event.preventDefault();
    if (needsOwner && password !== confirmPassword) {
      session.error = 'Passwords do not match';
      return;
    }
    const result = needsOwner
      ? await bootstrapOwner(email, name, password)
      : await loginLocal(email, password);
    if (result) await finishLogin();
  }

  async function submitAdminToken() {
    if (adminToken) await finishLogin(adminToken);
  }

  function signInWithSSO() {
    ssoPending = true;
    const redirect = encodeURIComponent(globalThis.location.pathname);
    globalThis.location.assign(`/auth/login?redirect=${redirect}`);
  }
</script>

<div class="flex min-h-screen items-center justify-center bg-slate-50 p-6">
  <form class="surface w-full max-w-sm p-6" onsubmit={submit}>
    <div class="flex items-center gap-2">
      <span class="text-lg font-semibold text-slate-900">NetP2P</span>
      <span class="rounded bg-emerald-100 px-1.5 py-0.5 text-xs font-medium text-emerald-700">BFT</span>
    </div>
    <p class="mt-1 text-sm text-slate-600">
      {needsOwner ? 'Create the first owner account.' : 'Sign in to the control plane.'}
    </p>

    {#if session.loadError}
      <p class="mt-4 rounded-lg border border-rose-200 bg-rose-50 p-3 text-sm text-rose-700">{session.loadError}</p>
    {/if}
    {#if session.error}
      <p class="mt-4 rounded-lg border border-rose-200 bg-rose-50 p-3 text-sm text-rose-700">{session.error}</p>
    {/if}

    {#if needsOwner}
      <label class="mt-5 block">
        <span class="label">Owner name</span>
        <input class="input" bind:value={name} autocomplete="name" placeholder="Network Owner" />
      </label>
    {/if}
    <label class="mt-4 block">
      <span class="label">Email</span>
      <input class="input" bind:value={email} type="email" autocomplete="username" required />
    </label>
    <label class="mt-4 block">
      <span class="label">Password</span>
      <input
        class="input"
        bind:value={password}
        type="password"
        autocomplete={needsOwner ? 'new-password' : 'current-password'}
        minlength={needsOwner ? 12 : undefined}
        required
      />
    </label>
    {#if needsOwner}
      <label class="mt-4 block">
        <span class="label">Confirm password</span>
        <input class="input" bind:value={confirmPassword} type="password" autocomplete="new-password" required />
      </label>
    {/if}

    <p class="mt-3 text-xs text-slate-500">
      Manager <span class="code">{session.bootstrap?.peerId?.slice(0, 16) ?? 'loading'}…</span>
    </p>
    <button class="btn-primary mt-5 w-full" disabled={session.connecting || !session.bootstrap}>
      {session.connecting ? 'Signing in…' : needsOwner ? 'Create owner' : 'Sign in'}
    </button>

    {#if session.bootstrap?.oidc}
      <button
        type="button"
        class="btn-secondary mt-2 w-full"
        disabled={session.connecting || ssoPending}
        onclick={signInWithSSO}
      >
        {ssoPending ? 'Redirecting…' : 'Sign in with SSO'}
      </button>
    {/if}

    <details class="mt-4">
      <summary class="cursor-pointer text-xs font-medium text-slate-600">Admin token</summary>
      <input class="input mt-2" bind:value={adminToken} type="password" autocomplete="off" />
      <button type="button" class="btn-secondary mt-2 w-full" disabled={session.connecting || !adminToken} onclick={submitAdminToken}>
        Connect
      </button>
    </details>
  </form>
</div>
