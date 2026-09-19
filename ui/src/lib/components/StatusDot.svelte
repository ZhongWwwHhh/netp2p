<script lang="ts">
  let { online, label }: { online: boolean; label?: string } = $props();
</script>

<span class="inline-flex items-center gap-2">
  <span class={`h-2 w-2 rounded-full ${online ? 'bg-emerald-500' : 'bg-slate-300'}`}></span>
  {#if label}<span class="text-sm text-slate-600">{label}</span>{/if}
</span>
