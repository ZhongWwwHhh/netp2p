<script lang="ts">
  let { value }: { value: number } = $props();
  const tone = $derived(value >= 90 ? 'bg-rose-500' : value >= 70 ? 'bg-amber-500' : 'bg-emerald-500');
</script>

<div class="h-2 w-full overflow-hidden rounded-full bg-slate-100">
  <div class={`h-full rounded-full ${tone}`} style={`width:${Math.min(100, Math.max(0, value))}%`}></div>
</div>
