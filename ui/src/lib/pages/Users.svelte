<script lang="ts">
  import Badge from '../components/Badge.svelte';
  import ConfirmDialog from '../components/ConfirmDialog.svelte';
  import DataTable from '../components/DataTable.svelte';
  import Drawer from '../components/Drawer.svelte';
  import FilterBar from '../components/FilterBar.svelte';
  import FormField from '../components/FormField.svelte';
  import PageHeader from '../components/PageHeader.svelte';
  import { network, refresh, submit } from '../stores/network.svelte';
  import { can, session } from '../stores/session.svelte';
  import { notify } from '../stores/toast.svelte';
  import type { User } from '../types';

  const roles = ['owner', 'admin', 'network_admin', 'auditor', 'usage_viewer', 'user'];

  let query = $state('');
  let editing = $state<User | null>(null);
  let credentialing = $state<User | null>(null);
  let pendingDelete = $state<User | null>(null);
  let busy = $state(false);
  let credentialEmail = $state('');
  let credentialPassword = $state('');

  const users = $derived(network.snapshot?.state.users ?? []);
  const filtered = $derived(
    users.filter((user) => {
      const needle = query.trim().toLowerCase();
      if (!needle) return true;
      return (
        user.id.toLowerCase().includes(needle) ||
        (user.email ?? '').toLowerCase().includes(needle) ||
        (user.name ?? '').toLowerCase().includes(needle)
      );
    }),
  );

  const canUpdate = $derived(can('users', 'update'));
  const canDelete = $derived(can('users', 'delete'));

  async function saveRole() {
    if (!editing) return;
    busy = true;
    const ok = await submit({ type: 'update_user_role', user: { id: editing.id, role: editing.role } });
    busy = false;
    if (ok) {
      notify(`Role for ${editing.id} committed`);
      editing = null;
    } else {
      notify(network.error || 'commit failed', 'error');
    }
  }

  async function toggleBlocked(user: User) {
    busy = true;
    const ok = await submit({ type: 'set_user_blocked', user: { id: user.id, role: user.role, blocked: !user.blocked } });
    busy = false;
    if (ok) {
      notify(`${user.id} ${user.blocked ? 'unblocked' : 'blocked'}`);
    } else {
      notify(network.error || 'commit failed', 'error');
    }
  }

  async function remove(user: User) {
    busy = true;
    const ok = await submit({ type: 'remove_user', targetId: user.id });
    busy = false;
    pendingDelete = null;
    if (ok) {
      notify(`${user.id} removed`);
    } else {
      notify(network.error || 'commit failed', 'error');
    }
  }

  async function saveCredentials() {
    if (!credentialing || !session.client) return;
    if (credentialPassword.length < 12) {
      notify('Password must contain at least 12 characters', 'error');
      return;
    }
    busy = true;
    try {
      const input: { email?: string; password?: string } = { password: credentialPassword };
      if (credentialEmail.trim()) input.email = credentialEmail.trim().toLowerCase();
      await session.client.updateCredentials(credentialing.id, input);
      await refresh();
      notify(`Credentials for ${credentialing.id} committed`);
      credentialing = null;
      credentialEmail = '';
      credentialPassword = '';
    } catch (caught) {
      notify(caught instanceof Error ? caught.message : String(caught), 'error');
    } finally {
      busy = false;
    }
  }
</script>

<div class="space-y-5">
  <PageHeader title="Users" shown={filtered.length} total={users.length} subtitle="Identities mirrored from the identity provider. Peers inherit their user's groups." />

  <div class="surface">
    <div class="border-b border-slate-200 p-4">
      <FilterBar bind:query placeholder="Search users…" />
    </div>
    <DataTable
      rows={filtered}
      columns={[
        { key: 'user', label: 'User' },
        { key: 'role', label: 'Role' },
        { key: 'groups', label: 'Auto groups' },
        { key: 'status', label: 'Status' },
        { key: 'actions', label: '', align: 'right' },
      ]}
      rowKey={(user) => user.id}
      emptyTitle="No users yet"
      emptyHint="Users appear after their first SSO login."
    >
      {#snippet cell(user: User, key: string)}
        {#if key === 'user'}
          <div class="font-medium text-slate-900">{user.name || user.email || user.id}</div>
          <div class="text-xs text-slate-500">{user.email ?? user.id}</div>
        {:else if key === 'role'}
          <Badge tone={user.role === 'owner' ? 'emerald' : 'slate'} label={user.role} />
          {#if user.id === session.identity?.userId}
            <span class="ml-2 text-xs text-slate-500">you</span>
          {/if}
        {:else if key === 'groups'}
          <span class="text-sm text-slate-600">{user.autoGroups?.length ?? 0} group(s)</span>
        {:else if key === 'status'}
          <Badge tone={user.blocked ? 'rose' : 'emerald'} label={user.blocked ? 'blocked' : 'active'} />
        {:else if key === 'actions'}
          <div class="flex justify-end gap-1">
            {#if canUpdate}
              <button class="btn-ghost" onclick={() => (editing = { ...user })}>Role</button>
              {#if user.role !== 'owner' && user.id !== session.identity?.userId}
                <button class="btn-ghost" onclick={() => (credentialing = { ...user })}>Credentials</button>
              {/if}
              <button class="btn-ghost" onclick={() => toggleBlocked(user)}>{user.blocked ? 'Unblock' : 'Block'}</button>
            {/if}
            {#if canDelete}
              <button class="btn-ghost text-rose-600" onclick={() => (pendingDelete = user)}>Delete</button>
            {/if}
          </div>
        {/if}
      {/snippet}
    </DataTable>
  </div>
</div>

<Drawer open={editing !== null} title={editing ? `Role for ${editing.id}` : 'Role'} onClose={() => (editing = null)}>
  {#if editing}
    <FormField label="Role" hint="Determines what this user may change through the console and admin API.">
      <select class="input" bind:value={editing.role}>
        {#each roles as role (role)}
          <option value={role}>{role}</option>
        {/each}
      </select>
    </FormField>
  {/if}
  {#snippet footer()}
    <button class="btn-secondary" onclick={() => (editing = null)} disabled={busy}>Cancel</button>
    <button class="btn-primary" onclick={saveRole} disabled={busy}>{busy ? 'Committing…' : 'Save'}</button>
  {/snippet}
</Drawer>

<Drawer open={credentialing !== null} title={credentialing ? `Credentials for ${credentialing.id}` : 'Credentials'} onClose={() => (credentialing = null)}>
  {#if credentialing}
    <div class="space-y-4">
      <FormField label="New email" hint="Leave blank to keep the current email.">
        <input class="input" type="email" autocomplete="off" bind:value={credentialEmail} />
      </FormField>
      <FormField label="New password" hint="At least 12 characters. The verifier is stored; the password is never retained.">
        <input class="input" type="password" autocomplete="new-password" bind:value={credentialPassword} required minlength="12" />
      </FormField>
    </div>
  {/if}
  {#snippet footer()}
    <button class="btn-secondary" onclick={() => (credentialing = null)} disabled={busy}>Cancel</button>
    <button class="btn-primary" onclick={saveCredentials} disabled={busy}>{busy ? 'Committing…' : 'Save'}</button>
  {/snippet}
</Drawer>

<ConfirmDialog
  open={pendingDelete !== null}
  title="Delete user"
  message={`Delete ${pendingDelete?.id ?? ''}? Their registered devices are removed too.`}
  busy={busy}
  onCancel={() => (pendingDelete = null)}
  onConfirm={() => pendingDelete && remove(pendingDelete)}
/>
