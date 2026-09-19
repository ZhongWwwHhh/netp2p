<script lang="ts">
  let { title, children }: { title: string; children?: import('svelte').Snippet } = $props();
</script>

<div class="rounded-2xl border border-slate-800 bg-slate-900 p-5">
  <h3 class="mb-3 font-medium">{title}</h3>
  {@render children?.()}
</div>
