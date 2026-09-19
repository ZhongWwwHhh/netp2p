<script lang="ts">
  let { label, value }: { label: string; value: string } = $props();
</script>

<div class="rounded-2xl border border-slate-800 bg-slate-900 p-5">
  <p class="text-sm text-slate-400">{label}</p>
  <p class="mt-2 text-2xl font-semibold">{value}</p>
</div>
