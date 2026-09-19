<script lang="ts">
  import { toasts, dismiss } from '../stores/toast.svelte';
</script>

<div class="pointer-events-none fixed bottom-4 right-4 z-50 flex w-full max-w-sm flex-col gap-2">
  {#each toasts.items as toast (toast.id)}
    <div
      class={`pointer-events-auto flex items-start justify-between gap-3 rounded-lg border px-4 py-3 text-sm shadow-sm ${
        toast.tone === 'error' ? 'border-rose-200 bg-rose-50 text-rose-800' : 'border-emerald-200 bg-emerald-50 text-emerald-800'
      }`}
    >
      <span>{toast.message}</span>
      <button class="text-xs opacity-70 hover:opacity-100" onclick={() => dismiss(toast.id)} aria-label="Dismiss">✕</button>
    </div>
  {/each}
</div>
