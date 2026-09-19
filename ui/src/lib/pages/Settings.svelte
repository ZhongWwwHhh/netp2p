<script lang="ts">
  import Badge from '../components/Badge.svelte';
  import PageHeader from '../components/PageHeader.svelte';
  import { shortPeerId } from '../format';
  import { network } from '../stores/network.svelte';
  import { disconnect, session } from '../stores/session.svelte';

  const bootstrap = $derived(session.bootstrap);
  const snapshot = $derived(network.snapshot);
</script>

<div class="space-y-5">
  <PageHeader title="Settings" subtitle="Connection, network and build information for this console session." />

  <div class="grid gap-5 lg:grid-cols-2">
    <section class="surface p-5">
      <h2 class="text-sm font-semibold text-slate-900">Manager connection</h2>
      <dl class="mt-3 space-y-3 text-sm">
        <div>
          <dt class="text-xs uppercase tracking-wide text-slate-500">Manager peer ID</dt>
          <dd class="break-all font-mono text-xs text-slate-700">{bootstrap?.peerId ?? '—'}</dd>
        </div>
        <div>
          <dt class="text-xs uppercase tracking-wide text-slate-500">API protocol</dt>
          <dd class="font-mono text-xs text-slate-700">{bootstrap?.apiProtocol ?? '—'}</dd>
        </div>
        <div>
          <dt class="text-xs uppercase tracking-wide text-slate-500">WebRTC addresses</dt>
          <dd class="space-y-1">
            {#each bootstrap?.webrtcAddresses ?? [] as address (address)}
              <p class="break-all font-mono text-xs text-slate-600">{address}</p>
            {/each}
          </dd>
        </div>
        <div>
          <dt class="text-xs uppercase tracking-wide text-slate-500">Browser peer ID</dt>
          <dd class="break-all font-mono text-xs text-slate-700">{session.client?.peerId?.toString() ?? '—'}</dd>
        </div>
      </dl>
      <button class="btn-secondary mt-4" onclick={() => void disconnect()}>Sign out of this manager</button>
    </section>

    <section class="surface p-5">
      <h2 class="text-sm font-semibold text-slate-900">Network state</h2>
      <dl class="mt-3 space-y-3 text-sm">
        <div>
          <dt class="text-xs uppercase tracking-wide text-slate-500">Network id</dt>
          <dd class="text-slate-700">{snapshot?.state.networkId ?? bootstrap?.networkId ?? '—'}</dd>
        </div>
        <div>
          <dt class="text-xs uppercase tracking-wide text-slate-500">Overlay CIDR</dt>
          <dd class="font-mono text-xs text-slate-700">{snapshot?.state.overlayCidr ?? '—'}</dd>
        </div>
        <div>
          <dt class="text-xs uppercase tracking-wide text-slate-500">Height / epoch</dt>
          <dd class="text-slate-700">{snapshot ? `${snapshot.height} / ${snapshot.epoch}` : '—'}</dd>
        </div>
        <div>
          <dt class="text-xs uppercase tracking-wide text-slate-500">State hash</dt>
          <dd class="break-all font-mono text-xs text-slate-700">{snapshot?.stateHash ?? '—'}</dd>
        </div>
        <div>
          <dt class="text-xs uppercase tracking-wide text-slate-500">Objects</dt>
          <dd class="flex flex-wrap gap-1">
            {#if snapshot}
              <Badge tone="slate" label={`${snapshot.state.peers.length} peers`} />
              <Badge tone="slate" label={`${snapshot.state.groups.length} groups`} />
              <Badge tone="slate" label={`${snapshot.state.policies.length} policies`} />
              <Badge tone="slate" label={`${snapshot.state.routes.length} routes`} />
              <Badge tone="slate" label={`${snapshot.state.budgets.length} budgets`} />
              <Badge tone="slate" label={`${snapshot.state.nameservers.length} nameservers`} />
              <Badge tone="slate" label={`${snapshot.state.zones.length} zones`} />
            {/if}
          </dd>
        </div>
      </dl>
    </section>

    <section class="surface p-5">
      <h2 class="text-sm font-semibold text-slate-900">Build</h2>
      <p class="mt-2 text-sm text-slate-600">Manager version <span class="code">{bootstrap?.version ?? '—'}</span></p>
      <p class="mt-1 text-xs text-slate-500">
        Committee {shortPeerId(bootstrap?.committee[0]?.peerId ?? '', 12)} and {bootstrap?.committee.length ?? 0} members total.
      </p>
    </section>

    <section class="surface p-5">
      <h2 class="text-sm font-semibold text-slate-900">Trust model</h2>
      <ul class="mt-2 space-y-2 text-sm text-slate-600">
        <li>Certified state comes from the BFT committee as a signed snapshot.</li>
        <li>Online status is observed per manager and gossiped, never certified.</li>
        <li>Write operations are committed through consensus before the UI updates.</li>
      </ul>
    </section>
  </div>
</div>
