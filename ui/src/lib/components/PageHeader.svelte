<script lang="ts">
  let { title, shown, total, subtitle, actions }: {
    title: string;
    shown?: number;
    total?: number;
    subtitle?: string;
    actions?: import('svelte').Snippet;
  } = $props();
</script>

<div class="flex flex-wrap items-start justify-between gap-4">
  <div>
    <h1 class="page-title">
      {#if shown !== undefined && total !== undefined}
        {shown === total ? `${total} ${title}` : `${shown} of ${total} ${title}`}
      {:else}
        {title}
      {/if}
    </h1>
    <p class="page-subtitle">{subtitle ?? title}</p>
  </div>
  {#if actions}
    <div class="flex items-center gap-2">{@render actions()}</div>
  {/if}
</div>
