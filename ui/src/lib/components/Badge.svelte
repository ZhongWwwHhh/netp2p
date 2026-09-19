<script lang="ts">
  let { tone = 'slate', label }: { tone?: 'slate' | 'emerald' | 'rose' | 'amber' | 'sky'; label: string } = $props();

  const tones: Record<string, string> = {
    slate: 'bg-slate-100 text-slate-700',
    emerald: 'bg-emerald-100 text-emerald-700',
    rose: 'bg-rose-100 text-rose-700',
    amber: 'bg-amber-100 text-amber-800',
    sky: 'bg-sky-100 text-sky-700',
  };
</script>

<span class={`inline-flex items-center rounded-full px-2 py-0.5 text-xs font-medium ${tones[tone]}`}>{label}</span>
