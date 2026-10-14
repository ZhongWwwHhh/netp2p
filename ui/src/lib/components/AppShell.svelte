<script lang="ts">
  import Sidebar from './Sidebar.svelte';
  import Toast from './Toast.svelte';
  import Topbar from './Topbar.svelte';

  let { children }: { children?: import('svelte').Snippet } = $props();
  let mobileNavOpen = $state(false);
</script>

<div class="flex h-screen overflow-hidden bg-slate-50">
  {#if mobileNavOpen}
    <button aria-label="Close navigation" class="fixed inset-0 z-30 bg-slate-900/30 lg:hidden" onclick={() => (mobileNavOpen = false)}></button>
  {/if}
  <div class={`fixed inset-y-0 left-0 z-40 w-64 transform border-r border-slate-200 bg-white transition-transform lg:static lg:z-auto lg:translate-x-0 ${mobileNavOpen ? 'translate-x-0' : '-translate-x-full'}`}>
    <Sidebar onNavigate={() => (mobileNavOpen = false)} />
  </div>
  <div class="flex min-w-0 flex-1 flex-col">
    <Topbar onMenu={() => (mobileNavOpen = true)} />
    <main class="flex-1 overflow-y-auto px-4 py-5 sm:px-6 sm:py-6">
      <div class="mx-auto max-w-7xl">
        {@render children?.()}
      </div>
    </main>
  </div>
  <Toast />
</div>
