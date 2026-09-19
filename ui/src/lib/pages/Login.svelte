<script lang="ts">
  import { loadBootstrap, session, connect } from '../stores/session.svelte';
  import { refresh, refreshPresence } from '../stores/network.svelte';

  let token = $state('');

  loadBootstrap();

  async function submit(event: SubmitEvent) {
    event.preventDefault();
    if (await connect(token)) {
      await Promise.all([refresh(), refreshPresence()]);
    }
  }
</script>

<div class="flex min-h-screen items-center justify-center bg-slate-50 p-6">
  <form class="surface w-full max-w-sm p-6" onsubmit={submit}>
    <div class="flex items-center gap-2">
      <span class="text-lg font-semibold text-slate-900">NetP2P</span>
      <span class="rounded bg-emerald-100 px-1.5 py-0.5 text-xs font-medium text-emerald-700">BFT</span>
    </div>
    <p class="mt-1 text-sm text-slate-600">Sign in to the control plane.</p>

    {#if session.loadError}
      <p class="mt-4 rounded-lg border border-rose-200 bg-rose-50 p-3 text-sm text-rose-700">{session.loadError}</p>
    {/if}
    {#if session.error}
      <p class="mt-4 rounded-lg border border-rose-200 bg-rose-50 p-3 text-sm text-rose-700">{session.error}</p>
    {/if}

    <label class="mt-5 block">
      <span class="label">Admin token</span>
      <input class="input" bind:value={token} type="password" placeholder="Admin token" />
    </label>

    <p class="mt-3 text-xs text-slate-500">
      Manager <span class="code">{session.bootstrap?.peerId?.slice(0, 16) ?? 'loading'}…</span>
    </p>
    <button class="btn-primary mt-5 w-full" disabled={session.connecting || !session.bootstrap}>
      {session.connecting ? 'Connecting…' : 'Connect over libp2p'}
    </button>
    <p class="mt-3 text-center text-xs text-slate-500">
      Control-plane requests travel over a libp2p WebRTC channel, not HTTP.
    </p>
  </form>
</div>
