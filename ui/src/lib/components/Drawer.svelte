<script lang="ts">
  let { open, title, onClose, children, footer }: {
    open: boolean;
    title: string;
    onClose: () => void;
    children?: import('svelte').Snippet;
    footer?: import('svelte').Snippet;
  } = $props();
</script>

{#if open}
  <div class="fixed inset-0 z-40 flex justify-end">
    <button class="absolute inset-0 h-full w-full cursor-default bg-slate-900/30" aria-label="Close" onclick={onClose}></button>
    <aside class="relative flex h-full w-full max-w-lg flex-col border-l border-slate-200 bg-white shadow-xl">
      <header class="flex items-center justify-between border-b border-slate-200 px-5 py-4">
        <h2 class="text-base font-semibold text-slate-900">{title}</h2>
        <button class="btn-ghost" onclick={onClose} aria-label="Close">✕</button>
      </header>
      <div class="flex-1 overflow-y-auto px-5 py-4">
        {@render children?.()}
      </div>
      {#if footer}
        <footer class="flex items-center justify-end gap-2 border-t border-slate-200 px-5 py-4">
          {@render footer()}
        </footer>
      {/if}
    </aside>
  </div>
{/if}
