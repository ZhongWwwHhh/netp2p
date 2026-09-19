<script lang="ts">
  let { rows = 4 }: { rows?: number } = $props();
</script>

<div class="space-y-2 p-4">
  {#each Array.from({ length: rows }) as _, index (index)}
    <div class="h-10 animate-pulse rounded-lg bg-slate-100"></div>
  {/each}
</div>
