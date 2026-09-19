<script lang="ts">
  let { label, hint, children }: {
    label: string;
    hint?: string;
    children?: import('svelte').Snippet;
  } = $props();
</script>

<div class="space-y-1">
  <span class="label">{label}</span>
  {@render children?.()}
  {#if hint}<p class="text-xs text-slate-500">{hint}</p>{/if}
</div>
