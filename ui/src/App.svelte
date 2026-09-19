<script lang="ts">
  import { onMount } from 'svelte';
  import AppShell from './lib/components/AppShell.svelte';
  import Skeleton from './lib/components/Skeleton.svelte';
  import Activity from './lib/pages/Activity.svelte';
  import Budgets from './lib/pages/Budgets.svelte';
  import Committee from './lib/pages/Committee.svelte';
  import DnsSettings from './lib/pages/DnsSettings.svelte';
  import Groups from './lib/pages/Groups.svelte';
  import Login from './lib/pages/Login.svelte';
  import Nameservers from './lib/pages/Nameservers.svelte';
  import Peers from './lib/pages/Peers.svelte';
  import Policies from './lib/pages/Policies.svelte';
  import Routes from './lib/pages/Routes.svelte';
  import Settings from './lib/pages/Settings.svelte';
  import SetupKeys from './lib/pages/SetupKeys.svelte';
  import Users from './lib/pages/Users.svelte';
  import Zones from './lib/pages/Zones.svelte';
  import { defaultPath, navigate, router, startRouter } from './lib/router.svelte';
  import { network } from './lib/stores/network.svelte';
  import { loadBootstrap, session } from './lib/stores/session.svelte';

  onMount(() => {
    void loadBootstrap();
    return startRouter();
  });

  // Keep the URL in sync when the app boots on an unknown path.
  $effect(() => {
    if (!router.path.startsWith('/')) navigate(defaultPath);
  });

  const pages: Record<string, typeof Peers> = {
    '/peers': Peers,
    '/policies': Policies,
    '/groups': Groups,
    '/setup-keys': SetupKeys,
    '/users': Users,
    '/routes': Routes,
    '/budgets': Budgets,
    '/dns/nameservers': Nameservers,
    '/dns/zones': Zones,
    '/dns/settings': DnsSettings,
    '/committee': Committee,
    '/activity': Activity,
    '/settings': Settings,
  };

  const page = $derived(pages[router.path] ?? Peers);
</script>

{#if !session.client}
  <Login />
{:else if !network.snapshot}
  <AppShell>
    {#if network.error}
      <p class="rounded-xl border border-rose-200 bg-rose-50 p-3 text-sm text-rose-700">{network.error}</p>
    {:else}
      <div class="surface"><Skeleton rows={6} /></div>
    {/if}
  </AppShell>
{:else}
  <AppShell>
    {#if network.error}
      <p class="mb-4 rounded-xl border border-rose-200 bg-rose-50 p-3 text-sm text-rose-700">{network.error}</p>
    {/if}
    {@const Page = page}
    <Page />
  </AppShell>
{/if}
