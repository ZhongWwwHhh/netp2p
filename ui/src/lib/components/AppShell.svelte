<script lang="ts">
  import Sidebar from './Sidebar.svelte';
  import Toast from './Toast.svelte';
  import Topbar from './Topbar.svelte';

  let { children }: { children?: import('svelte').Snippet } = $props();
</script>

<div class="flex h-screen overflow-hidden bg-slate-50">
  <Sidebar />
  <div class="flex min-w-0 flex-1 flex-col">
    <Topbar />
    <main class="flex-1 overflow-y-auto px-6 py-6">
      <div class="mx-auto max-w-7xl">
        {@render children?.()}
      </div>
    </main>
  </div>
  <Toast />
</div>
