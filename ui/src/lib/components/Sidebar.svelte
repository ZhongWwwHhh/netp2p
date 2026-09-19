<script lang="ts">
  import { navigate, routes, router } from '../router.svelte';
  import { network } from '../stores/network.svelte';
  import { session } from '../stores/session.svelte';

  const groups = $derived(
    routes.reduce<{ name: string; items: typeof routes }[]>((accumulator, route) => {
      const last = accumulator[accumulator.length - 1];
      if (last && last.name === route.group) {
        last.items.push(route);
      } else {
        accumulator.push({ name: route.group, items: [route] });
      }
      return accumulator;
    }, []),
  );
</script>

<aside class="flex h-full w-64 shrink-0 flex-col border-r border-slate-200 bg-white">
  <div class="flex items-center gap-2 px-5 py-4">
    <span class="text-lg font-semibold text-slate-900">NetP2P</span>
    <span class="rounded bg-emerald-100 px-1.5 py-0.5 text-xs font-medium text-emerald-700">BFT</span>
  </div>

  <nav class="flex-1 overflow-y-auto px-3 pb-4">
    {#each groups as group (group.name)}
      <p class="nav-group">{group.name}</p>
      {#each group.items as route (route.path)}
        <button class={`nav-link w-full ${router.path === route.path ? 'nav-link-active' : ''}`} onclick={() => navigate(route.path)}>
          {route.title}
        </button>
      {/each}
    {/each}
  </nav>

  <div class="border-t border-slate-200 px-4 py-3 text-xs text-slate-500">
    {#if network.snapshot}
      <p>height {network.snapshot.height} · epoch {network.snapshot.epoch}</p>
    {/if}
    <p class="mt-0.5 truncate">{session.bootstrap?.networkId ?? 'loading network…'}</p>
  </div>
</aside>
