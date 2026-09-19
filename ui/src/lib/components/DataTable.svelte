<script lang="ts" generics="T">
  import EmptyState from './EmptyState.svelte';

  interface Column {
    key: string;
    label: string;
    sortable?: boolean;
    align?: 'left' | 'right' | 'center';
    width?: string;
  }

  let {
    rows,
    columns,
    rowKey,
    cell,
    emptyTitle = 'Nothing here yet',
    emptyHint,
    sortKey = '',
    sortAsc = true,
    onSort,
  }: {
    rows: T[];
    columns: Column[];
    rowKey: (row: T) => string;
    cell: import('svelte').Snippet<[T, string]>;
    emptyTitle?: string;
    emptyHint?: string;
    sortKey?: string;
    sortAsc?: boolean;
    onSort?: (key: string) => void;
  } = $props();
</script>

{#if rows.length === 0}
  <EmptyState title={emptyTitle} hint={emptyHint} />
{:else}
  <div class="overflow-x-auto">
    <table class="w-full border-collapse text-sm">
      <thead class="table-head">
        <tr>
          {#each columns as column (column.key)}
            <th
              class={`px-4 py-3 font-medium ${column.align === 'right' ? 'text-right' : column.align === 'center' ? 'text-center' : 'text-left'}`}
              style={column.width ? `width:${column.width}` : undefined}
            >
              {#if column.sortable && onSort}
                <button class="inline-flex items-center gap-1 hover:text-slate-700" onclick={() => onSort(column.key)}>
                  {column.label}
                  <span class="text-slate-400">{sortKey === column.key ? (sortAsc ? '↑' : '↓') : '↕'}</span>
                </button>
              {:else}
                {column.label}
              {/if}
            </th>
          {/each}
        </tr>
      </thead>
      <tbody>
        {#each rows as row (rowKey(row))}
          <tr class="table-row">
            {#each columns as column (column.key)}
              <td class={`px-4 py-3 align-middle ${column.align === 'right' ? 'text-right' : column.align === 'center' ? 'text-center' : 'text-left'}`}>
                {@render cell(row, column.key)}
              </td>
            {/each}
          </tr>
        {/each}
      </tbody>
    </table>
  </div>
{/if}
