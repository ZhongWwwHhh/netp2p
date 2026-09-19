<script lang="ts">
  let { open, title, message, confirmLabel = 'Delete', busy = false, onConfirm, onCancel }: {
    open: boolean;
    title: string;
    message: string;
    confirmLabel?: string;
    busy?: boolean;
    onConfirm: () => void;
    onCancel: () => void;
  } = $props();
</script>

{#if open}
  <div class="fixed inset-0 z-50 flex items-center justify-center p-4">
    <button class="absolute inset-0 h-full w-full cursor-default bg-slate-900/30" aria-label="Cancel" onclick={onCancel}></button>
    <div class="surface relative w-full max-w-md p-5">
      <h2 class="text-base font-semibold text-slate-900">{title}</h2>
      <p class="mt-2 text-sm text-slate-600">{message}</p>
      <div class="mt-5 flex justify-end gap-2">
        <button class="btn-secondary" onclick={onCancel} disabled={busy}>Cancel</button>
        <button class="btn-danger" onclick={onConfirm} disabled={busy}>{confirmLabel}</button>
      </div>
    </div>
  </div>
{/if}
