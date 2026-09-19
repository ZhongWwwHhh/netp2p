<script lang="ts">
  import { relativeTime } from '../format';
  import type { Presence } from '../types';

  // Presence is observed by one manager, not certified by the committee. The
  // label must always make that distinction explicit.
  let { observation }: { observation: Presence | undefined } = $props();
</script>

{#if observation}
  <span class="inline-flex items-center gap-1.5 text-xs text-slate-500" title={`Observed by ${observation.observer}`}>
    <span class={`h-2 w-2 rounded-full ${observation.online ? 'bg-emerald-500' : 'bg-slate-300'}`}></span>
    {observation.online ? 'Online' : 'Offline'}
    <span class="text-slate-400">· observed {relativeTime(observation.updatedAt)}</span>
  </span>
{:else}
  <span class="text-xs text-slate-400">no observation yet</span>
{/if}
