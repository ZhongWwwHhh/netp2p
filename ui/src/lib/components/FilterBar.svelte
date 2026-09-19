<script lang="ts">
  let { query = $bindable(''), placeholder = 'Search…', chips = [], activeChip = '', onChip }: {
    query?: string;
    placeholder?: string;
    chips?: string[];
    activeChip?: string;
    onChip?: (chip: string) => void;
  } = $props();
</script>

<div class="flex flex-wrap items-center gap-2">
  <input class="input max-w-xs" bind:value={query} {placeholder} />
  {#if chips.length > 0}
    {#each chips as chip (chip)}
      <button
        class={`rounded-full border px-3 py-1 text-xs ${activeChip === chip ? 'border-emerald-300 bg-emerald-50 text-emerald-700' : 'border-slate-300 bg-white text-slate-600 hover:bg-slate-50'}`}
        onclick={() => onChip?.(chip === activeChip ? '' : chip)}
      >
        {chip}
      </button>
    {/each}
  {/if}
</div>
