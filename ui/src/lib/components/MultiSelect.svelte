<script lang="ts">
  // `selected` is optional-aware so forms can bind fields that the committee
  // treats as omitempty without every page having to pre-fill empty arrays.
  // It deliberately has no $bindable fallback: Svelte rejects `bind:x={undefined}`
  // when a fallback is present, and those fields start out undefined.
  let { options, selected = $bindable(), placeholder = 'Select…' }: {
    options: string[];
    selected?: string[] | undefined;
    placeholder?: string;
  } = $props();

  let query = $state('');

  const current = $derived(selected ?? []);

  const available = $derived(
    options.filter((option) => !current.includes(option) && option.toLowerCase().includes(query.toLowerCase())),
  );

  function add(option: string) {
    if (!current.includes(option)) selected = [...current, option];
    query = '';
  }

  // Free-text entry lets the operator reference a group that does not exist
  // yet; the committee rejects the transition if the reference is unknown.
  function addTyped() {
    const value = query.trim();
    if (value && !current.includes(value)) selected = [...current, value];
    query = '';
  }

  function remove(option: string) {
    selected = current.filter((value) => value !== option);
  }
</script>

<div class="space-y-2">
  {#if current.length > 0}
    <div class="flex flex-wrap gap-1.5">
      {#each current as value (value)}
        <span class="inline-flex items-center gap-1 rounded-full bg-slate-100 px-2 py-0.5 text-xs text-slate-700">
          {value}
          <button class="text-slate-400 hover:text-rose-600" onclick={() => remove(value)} aria-label={`Remove ${value}`}>✕</button>
        </span>
      {/each}
    </div>
  {/if}
  <input
    class="input"
    bind:value={query}
    placeholder={placeholder}
    onkeydown={(event) => {
      if (event.key === 'Enter') {
        event.preventDefault();
        addTyped();
      }
    }}
  />
  {#if query && available.length > 0}
    <div class="max-h-40 overflow-y-auto rounded-lg border border-slate-200">
      {#each available as option (option)}
        <button type="button" class="block w-full px-3 py-2 text-left text-sm hover:bg-slate-50" onclick={() => add(option)}>{option}</button>
      {/each}
    </div>
  {/if}
</div>
