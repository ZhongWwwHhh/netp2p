<script lang="ts">
  let { title, hint }: { title: string; hint?: string } = $props();
</script>

<div class="flex flex-col items-center justify-center gap-1 px-4 py-12 text-center">
  <p class="text-sm font-medium text-slate-700">{title}</p>
  {#if hint}<p class="text-sm text-slate-500">{hint}</p>{/if}
</div>
