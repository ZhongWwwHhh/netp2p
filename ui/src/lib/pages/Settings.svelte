<script lang="ts">
  import Badge from '../components/Badge.svelte';
  import PageHeader from '../components/PageHeader.svelte';
  import { shortPeerId } from '../format';
  import { network, submit } from '../stores/network.svelte';
  import { can, disconnect, session } from '../stores/session.svelte';
  import { notify } from '../stores/toast.svelte';
  import type { NetworkSettings } from '../types';

  const bootstrap = $derived(session.bootstrap);
  const snapshot = $derived(network.snapshot);
  const canWrite = $derived(can('settings', 'update'));

  let busy = $state(false);
  let settings = $state<NetworkSettings>({});
  let loaded = $state(false);
  let allowGroups = $state('');

  $effect(() => {
    const current = snapshot?.state.settings;
    if (loaded || !current) return;
    settings = { ...current };
    allowGroups = (current.jwtAllowGroups ?? []).join(', ');
    loaded = true;
  });

  async function saveSettings() {
    busy = true;
    const ok = await submit({
      type: 'update_network_settings',
      settings: {
        ...settings,
        jwtAllowGroups: allowGroups
          .split(',')
          .map((value) => value.trim())
          .filter(Boolean),
      },
    });
    busy = false;
    if (ok) {
      notify('Network settings committed');
    } else {
      notify(network.error || 'commit failed', 'error');
    }
  }
</script>

<div class="space-y-5">
  <PageHeader title="Settings" subtitle="Connection, network and build information for this console session." />

  <div class="grid gap-5 lg:grid-cols-2">
    <section class="surface p-5">
      <h2 class="text-sm font-semibold text-slate-900">Session</h2>
      <dl class="mt-3 space-y-3 text-sm">
        <div>
          <dt class="text-xs uppercase tracking-wide text-slate-500">Signed in as</dt>
          <dd class="text-slate-700">
            {session.identity?.name || session.identity?.email || session.identity?.subject || '—'}
          </dd>
        </div>
        <div>
          <dt class="text-xs uppercase tracking-wide text-slate-500">Role</dt>
          <dd class="mt-1">
            <Badge tone={session.identity?.role === 'owner' ? 'emerald' : 'slate'} label={session.identity?.role ?? '—'} />
            {#if session.identity?.static}
              <span class="ml-2 text-xs text-slate-500">break-glass token</span>
            {/if}
          </dd>
        </div>
        {#if bootstrap?.oidc}
          <div>
            <dt class="text-xs uppercase tracking-wide text-slate-500">Identity provider</dt>
            <dd class="break-all text-xs text-slate-600">{bootstrap.oidc.issuer}</dd>
          </div>
        {/if}
      </dl>
      <button class="btn-secondary mt-4" onclick={() => void disconnect()}>Sign out of this manager</button>
    </section>

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

    <section class="surface p-5 lg:col-span-2">
      <h2 class="text-sm font-semibold text-slate-900">Network settings</h2>
      <p class="mt-1 text-xs text-slate-500">Certified configuration applied to peers on their next sync.</p>
      <div class="mt-4 grid gap-4 md:grid-cols-2">
        <label class="block">
          <span class="label">Overlay DNS domain</span>
          <input class="input" bind:value={settings.dnsDomain} disabled={!canWrite} placeholder="netp2p.internal" />
        </label>
        <label class="block">
          <span class="label">Login expiration (days)</span>
          <input class="input" type="number" min="0" bind:value={settings.loginExpirationDays} disabled={!canWrite} />
        </label>
        <label class="block">
          <span class="label">JWT groups claim</span>
          <input class="input" bind:value={settings.jwtGroupsClaimName} disabled={!canWrite} placeholder="groups" />
        </label>
        <label class="block">
          <span class="label">Allowed IdP groups</span>
          <input class="input" bind:value={allowGroups} disabled={!canWrite} placeholder="comma separated; empty allows all" />
        </label>
        <label class="flex items-center gap-2 md:col-span-2">
          <input type="checkbox" bind:checked={settings.jwtGroupsEnabled} disabled={!canWrite} />
          <span class="text-sm text-slate-700">Mirror identity provider groups into managed groups</span>
        </label>
        <label class="block">
          <span class="label">Link min bandwidth (Mbps)</span>
          <input class="input" type="number" min="0" step="1" bind:value={settings.linkMinBandwidthMbps} disabled={!canWrite} placeholder="10" />
        </label>
        <label class="block">
          <span class="label">Via-manager latency advantage (ms)</span>
          <input class="input" type="number" min="0" step="1" bind:value={settings.viaManagerLatencyAdvantageMs} disabled={!canWrite} placeholder="50" />
        </label>
        <label class="block">
          <span class="label">Via-manager loss advantage (%)</span>
          <input class="input" type="number" min="0" step="0.5" bind:value={settings.viaManagerLossAdvantagePct} disabled={!canWrite} placeholder="5" />
        </label>
        <label class="block">
          <span class="label">Probe interval (seconds)</span>
          <input class="input" type="number" min="1" bind:value={settings.linkProbeIntervalSeconds} disabled={!canWrite} placeholder="10" />
        </label>
        <label class="block">
          <span class="label">Probe timeout (ms)</span>
          <input class="input" type="number" min="100" bind:value={settings.linkProbeTimeoutMs} disabled={!canWrite} placeholder="3000" />
        </label>
        <label class="block">
          <span class="label">Probe bandwidth budget (KB)</span>
          <input class="input" type="number" min="0" bind:value={settings.probeBandwidthBudgetKb} disabled={!canWrite} placeholder="128" />
        </label>
        <label class="block">
          <span class="label">Max manager hops</span>
          <input class="input" type="number" min="1" bind:value={settings.maxManagerHops} disabled={!canWrite} placeholder="2" />
        </label>
        <label class="block">
          <span class="label">Default flow class</span>
          <select class="input" bind:value={settings.defaultFlowClass} disabled={!canWrite}>
            {#each ['', 'latency', 'throughput', 'reliability', 'cost'] as flowClass (flowClass)}
              <option value={flowClass}>{flowClass || 'default (latency)'}</option>
            {/each}
          </select>
        </label>
        <label class="block">
          <span class="label">Quota report interval (seconds)</span>
          <input class="input" type="number" min="1" bind:value={settings.quotaReportIntervalSeconds} disabled={!canWrite} placeholder="30" />
        </label>
        <label class="flex items-center gap-2">
          <input type="checkbox" bind:checked={settings.viaManagerEnabled} disabled={!canWrite} />
          <span class="text-sm text-slate-700">Allow via-manager paths</span>
        </label>
        <label class="flex items-center gap-2">
          <input type="checkbox" bind:checked={settings.directPathEnabled} disabled={!canWrite} />
          <span class="text-sm text-slate-700">Allow direct P2P paths</span>
        </label>
        <label class="flex items-center gap-2 md:col-span-2">
          <input type="checkbox" bind:checked={settings.quotaEnforcementEnabled} disabled={!canWrite} />
          <span class="text-sm text-slate-700">Enforce traffic budgets (blocks, throttles and path switches)</span>
        </label>
        <label class="flex items-center gap-2 md:col-span-2">
          <input type="checkbox" bind:checked={settings.exitNodeEnabled} disabled={!canWrite} />
          <span class="text-sm text-slate-700">Allow exit nodes and subnet routes (kernel NAT on Linux/TUN gateways)</span>
        </label>
      </div>
      {#if canWrite}
        <div class="mt-4 flex justify-end">
          <button class="btn-primary" onclick={saveSettings} disabled={busy}>{busy ? 'Committing…' : 'Save settings'}</button>
        </div>
      {/if}
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
