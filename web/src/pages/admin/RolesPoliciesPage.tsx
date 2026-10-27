import React, { useState } from 'react';
import { PlusIcon, PencilSquareIcon, TrashIcon, ShieldCheckIcon } from '@heroicons/react/24/outline';
import { Button, Modal, Input, Spinner } from '../../components/ui';
import { apiErrorMessage } from '../../services/client';
import {
    useRoles,
    usePermissions,
    useCreateRole,
    useUpdateRole,
    useDeleteRole,
    useAssignPermissionToRole,
    useRemovePermissionFromRole,
} from '../../features/admin';
import type { Role, RoleWithPermissions, Permission } from '../../types/rbac';
import { BUILT_IN_ROLES, ROLE_ASSIGNABLE_SCOPE_LABELS, type RoleAssignableScope } from '../../types/rbac';

type Tab = 'roles' | 'permissions';

interface RoleFormData {
    name: string;
    description: string;
    assignable_scope: RoleAssignableScope;
    // Permission names, as the server takes them. A role needs at least one (min=1).
    permissions: string[];
}

const emptyRoleForm: RoleFormData = { name: '', description: '', assignable_scope: 'project', permissions: [] };

const sameNames = (a: readonly string[], b: readonly string[]): boolean =>
    a.length === b.length && a.every((n) => b.includes(n));

const isBuiltIn = (name: string): boolean => (BUILT_IN_ROLES as readonly string[]).includes(name);

interface AssignableScopeSelectProps {
    id: string;
    value: RoleAssignableScope;
    onChange: (value: RoleAssignableScope) => void;
    // A built-in role: the server refuses every update of it, so the choice is not offered.
    builtIn?: boolean;
}

// Where the role may be granted (#3546). A new role defaults to per project; widening it
// lets it be granted install-wide, where it applies in EVERY project.
const AssignableScopeSelect: React.FC<AssignableScopeSelectProps> = ({ id, value, onChange, builtIn = false }) => (
    <div>
        <label htmlFor={id} className="block text-sm font-medium mb-1" style={{ color: 'var(--text-secondary)' }}>
            Can be granted
        </label>
        <select
            id={id}
            value={value}
            disabled={builtIn}
            onChange={(e) => onChange(e.target.value as RoleAssignableScope)}
            className="w-full px-3 py-2 rounded-md border text-sm disabled:opacity-60 disabled:cursor-not-allowed"
            style={{
                backgroundColor: 'var(--bg-app)',
                borderColor: 'var(--border-strong)',
                color: 'var(--text-primary)',
            }}
        >
            {(Object.keys(ROLE_ASSIGNABLE_SCOPE_LABELS) as RoleAssignableScope[]).map((s) => (
                <option key={s} value={s}>
                    {ROLE_ASSIGNABLE_SCOPE_LABELS[s]}
                </option>
            ))}
        </select>
        <p className="mt-1 text-xs" style={{ color: 'var(--text-muted)' }}>
            {builtIn
                ? 'This is a built-in role: it cannot be changed, including where it can be granted.'
                : value === 'project'
                  ? 'Grants must name a project. Recommended for most roles.'
                  : 'An install-wide grant applies in every project. Changing this does not change existing grants.'}
        </p>
    </div>
);

interface PermissionChecklistProps {
    permissions: Permission[];
    loading: boolean;
    selected: string[];
    onChange: (selected: string[]) => void;
    disabled?: boolean;
}

// The permissions a role carries, by name. The server refuses a role with none, so the form
// asks for at least one rather than sending an empty list.
const PermissionChecklist: React.FC<PermissionChecklistProps> = ({
    permissions,
    loading,
    selected,
    onChange,
    disabled = false,
}) => {
    const toggle = (name: string) =>
        onChange(selected.includes(name) ? selected.filter((n) => n !== name) : [...selected, name]);
    return (
        <fieldset>
            <legend className="block text-sm font-medium mb-1" style={{ color: 'var(--text-secondary)' }}>
                Permissions
            </legend>
            {loading ? (
                <div className="flex justify-center py-4">
                    <Spinner />
                </div>
            ) : (
                <div
                    className="max-h-48 overflow-y-auto rounded-md border p-2 space-y-3"
                    style={{ borderColor: 'var(--border-strong)' }}
                >
                    {Object.entries(groupByResource(permissions)).map(([resource, perms]) => (
                        <div key={resource}>
                            <h4
                                className="text-xs font-semibold uppercase tracking-wider mb-1"
                                style={{ color: 'var(--text-secondary)' }}
                            >
                                {resource}
                            </h4>
                            {perms.map((perm) => (
                                <label key={perm.id} className="flex items-center gap-2 px-1 py-1 cursor-pointer">
                                    <input
                                        type="checkbox"
                                        checked={selected.includes(perm.name)}
                                        onChange={() => toggle(perm.name)}
                                        disabled={disabled}
                                        className="h-4 w-4 rounded-sm accent-blue-600"
                                    />
                                    <span className="text-sm" style={{ color: 'var(--text-primary)' }}>
                                        {perm.name}
                                    </span>
                                    {perm.description && (
                                        <span className="text-xs" style={{ color: 'var(--text-muted)' }}>
                                            {perm.description}
                                        </span>
                                    )}
                                </label>
                            ))}
                        </div>
                    ))}
                </div>
            )}
            {!loading && selected.length === 0 && (
                <p className="mt-1 text-xs" style={{ color: 'var(--text-muted)' }}>
                    Select at least one permission.
                </p>
            )}
        </fieldset>
    );
};

const groupByResource = (perms: Permission[]): Record<string, Permission[]> =>
    perms.reduce<Record<string, Permission[]>>((acc, p) => {
        const existing = acc[p.resource];
        if (existing !== undefined) {
            existing.push(p);
        } else {
            acc[p.resource] = [p];
        }
        return acc;
    }, {});

interface RoleCardProps {
    role: RoleWithPermissions;
    onEdit: (role: RoleWithPermissions) => void;
    onDelete: (role: Role) => void;
    onManage: (role: RoleWithPermissions) => void;
}

const RoleCard: React.FC<RoleCardProps> = ({ role, onEdit, onDelete, onManage }) => {
    const builtIn = isBuiltIn(role.name);
    return (
        <div
            className="rounded-xl border flex flex-col"
            style={{ borderColor: 'var(--border)', backgroundColor: 'var(--bg-surface)' }}
        >
            <div
                className="px-5 py-4 border-b flex items-start justify-between gap-2"
                style={{ borderColor: 'var(--border)' }}
            >
                <div className="min-w-0">
                    <h3 className="text-sm font-semibold truncate" style={{ color: 'var(--text-primary)' }}>
                        {role.name}
                    </h3>
                    {role.description && (
                        <p
                            className="mt-0.5 text-xs leading-relaxed line-clamp-2"
                            style={{ color: 'var(--text-muted)' }}
                        >
                            {role.description}
                        </p>
                    )}
                </div>
                {builtIn && (
                    <span
                        className="text-[10px] font-semibold px-1.5 py-0.5 rounded-sm uppercase tracking-wide shrink-0"
                        style={{ backgroundColor: 'var(--bg-muted)', color: 'var(--text-muted)' }}
                    >
                        Built-in
                    </span>
                )}
            </div>
            <div className="px-5 py-3 flex-1">
                <p className="text-xs" style={{ color: 'var(--text-muted)' }}>
                    {role.permissions.length} permission{role.permissions.length !== 1 ? 's' : ''}
                </p>
                <p className="mt-1 text-xs" style={{ color: 'var(--text-muted)' }}>
                    {ROLE_ASSIGNABLE_SCOPE_LABELS[role.assignable_scope]}
                </p>
            </div>
            <div className="px-5 py-3 border-t flex items-center gap-2" style={{ borderColor: 'var(--border)' }}>
                <Button size="sm" variant="outline" onClick={() => onManage(role)} className="flex-1">
                    <ShieldCheckIcon className="size-4" />
                    Permissions
                </Button>
                <button
                    type="button"
                    onClick={() => onEdit(role)}
                    className="p-1.5 rounded-md transition-colors"
                    style={{ color: 'var(--text-muted)' }}
                    title="Edit role"
                    onMouseEnter={(e) => ((e.currentTarget as HTMLElement).style.color = 'var(--text-primary)')}
                    onMouseLeave={(e) => ((e.currentTarget as HTMLElement).style.color = 'var(--text-muted)')}
                >
                    <PencilSquareIcon className="h-4 w-4" />
                </button>
                <button
                    type="button"
                    onClick={builtIn ? undefined : () => onDelete(role)}
                    disabled={builtIn}
                    className="p-1.5 rounded-md transition-colors disabled:opacity-30 disabled:cursor-not-allowed"
                    style={{ color: 'var(--text-muted)' }}
                    title={builtIn ? 'Built-in roles cannot be deleted' : 'Delete role'}
                    onMouseEnter={(e) => {
                        if (!builtIn) (e.currentTarget as HTMLElement).style.color = '#ef4444';
                    }}
                    onMouseLeave={(e) => {
                        (e.currentTarget as HTMLElement).style.color = 'var(--text-muted)';
                    }}
                >
                    <TrashIcon className="h-4 w-4" />
                </button>
            </div>
        </div>
    );
};

export const RolesPoliciesPage: React.FC = () => {
    const [tab, setTab] = useState<Tab>('roles');
    const [formData, setFormData] = useState<RoleFormData>(emptyRoleForm);
    const [createOpen, setCreateOpen] = useState(false);
    const [editRole, setEditRole] = useState<RoleWithPermissions | null>(null);
    const [deleteRole, setDeleteRole] = useState<Role | null>(null);
    const [manageRoleId, setManageRoleId] = useState<number | null>(null);

    const { data: roles, isLoading: rolesLoading, error: rolesError } = useRoles();
    const { data: permissions, isLoading: permsLoading } = usePermissions();
    const createMutation = useCreateRole();
    const updateMutation = useUpdateRole();
    const deleteMutation = useDeleteRole();
    const assignMutation = useAssignPermissionToRole();
    const removeMutation = useRemovePermissionFromRole();

    const manageRole = roles?.find((r) => r.id === manageRoleId) ?? null;
    const permsByResource = groupByResource(permissions ?? []);
    const isMutatingPerm = assignMutation.isPending || removeMutation.isPending;

    const openCreate = () => {
        setFormData(emptyRoleForm);
        createMutation.reset();
        setCreateOpen(true);
    };

    const openEdit = (role: RoleWithPermissions) => {
        setFormData({
            name: role.name,
            description: role.description,
            assignable_scope: role.assignable_scope,
            permissions: role.permissions.map((p) => p.name),
        });
        updateMutation.reset();
        setEditRole(role);
    };

    const openDelete = (role: Role) => {
        deleteMutation.reset();
        setDeleteRole(role);
    };

    // The server requires a name, a non-empty description and at least one permission on create.
    const createReady =
        formData.name.trim() !== '' && formData.description.trim() !== '' && formData.permissions.length > 0;

    // The server refuses every update to a built-in role (403, whatever the fields), so its
    // Edit dialog is read-only and Save never sends the PUT.
    const editBuiltIn = editRole !== null && isBuiltIn(editRole.name);
    const permsChanged =
        editRole !== null &&
        !sameNames(
            formData.permissions,
            editRole.permissions.map((p) => p.name)
        );
    // The scope is sent only when the admin changed it: the server keeps the stored scope when the
    // key is absent (read inside its transaction), while echoing the value read when the dialog
    // opened would undo a narrowing another admin committed in between, as a widening.
    const scopeChanged = editRole !== null && formData.assignable_scope !== editRole.assignable_scope;
    // On update the permissions key is optional but, when sent, must hold at least one entry.
    const editReady =
        !editBuiltIn && formData.description.trim() !== '' && !(permsChanged && formData.permissions.length === 0);

    const handleCreate = () => {
        if (!createReady) return;
        createMutation.mutate(formData, { onSuccess: () => setCreateOpen(false) });
    };

    const handleUpdate = () => {
        if (!editRole || editBuiltIn || !editReady) return;
        const { description, permissions, assignable_scope } = formData;
        const opened = editRole.permissions.map((p) => p.name);
        updateMutation.mutate(
            {
                id: editRole.id,
                // No name: the server has no rename. An unchanged scope is left out so the server
                // keeps the current value.
                body: {
                    description,
                    ...(scopeChanged ? { assignable_scope } : {}),
                },
                // Only this admin's own ticks and unticks: useUpdateRole applies them to the set the
                // server holds at Save, so a permission revoked or granted by someone else while
                // the dialog was open is not undone.
                ...(permsChanged
                    ? {
                          permissionChanges: {
                              added: permissions.filter((n) => !opened.includes(n)),
                              removed: opened.filter((n) => !permissions.includes(n)),
                          },
                      }
                    : {}),
            },
            { onSuccess: () => setEditRole(null) }
        );
    };

    const handleDelete = () => {
        if (!deleteRole) return;
        deleteMutation.mutate(deleteRole.id, {
            onSuccess: () => {
                deleteMutation.reset();
                setDeleteRole(null);
            },
        });
    };

    const handleTogglePerm = (perm: Permission) => {
        if (!manageRole) return;
        const assigned = manageRole.permissions.some((p) => p.id === perm.id);
        if (assigned) {
            removeMutation.mutate({ roleId: manageRole.id, permissionId: perm.id });
        } else {
            assignMutation.mutate({ roleId: manageRole.id, permissionId: perm.id });
        }
    };

    return (
        <div className="max-w-5xl mx-auto px-6 py-8">
            <div className="mb-6">
                <h1 className="text-2xl font-bold tracking-tight" style={{ color: 'var(--text-primary)' }}>
                    Roles & Policies
                </h1>
                <p className="mt-1 text-sm" style={{ color: 'var(--text-muted)' }}>
                    Manage roles and their associated permissions.
                </p>
            </div>

            {/* Tab bar */}
            <div className="flex gap-1 mb-6 border-b" style={{ borderColor: 'var(--border)' }}>
                {(['roles', 'permissions'] as const).map((t) => (
                    <button
                        key={t}
                        type="button"
                        onClick={() => setTab(t)}
                        className="px-4 py-2 text-sm font-medium -mb-px border-b-2 transition-colors"
                        style={{
                            borderColor: tab === t ? 'var(--accent)' : 'transparent',
                            color: tab === t ? 'var(--accent-text)' : 'var(--text-muted)',
                        }}
                    >
                        {t === 'roles' ? 'Roles' : 'Permissions'}
                    </button>
                ))}
            </div>

            {/* Roles tab */}
            {tab === 'roles' && (
                <div>
                    <div className="flex justify-end mb-4">
                        <Button size="sm" onClick={openCreate}>
                            <PlusIcon className="size-4" />
                            New Role
                        </Button>
                    </div>

                    {rolesLoading && (
                        <div className="flex justify-center py-12">
                            <Spinner />
                        </div>
                    )}
                    {rolesError !== null && (
                        <p className="text-sm" style={{ color: 'var(--text-muted)' }}>
                            Failed to load roles. Please try again.
                        </p>
                    )}
                    {!rolesLoading && !rolesError && (
                        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
                            {(roles ?? []).map((role) => (
                                <RoleCard
                                    key={role.id}
                                    role={role}
                                    onEdit={openEdit}
                                    onDelete={openDelete}
                                    onManage={(r) => setManageRoleId(r.id)}
                                />
                            ))}
                            {roles?.length === 0 && (
                                <p
                                    className="col-span-full text-sm py-8 text-center"
                                    style={{ color: 'var(--text-muted)' }}
                                >
                                    No roles found.
                                </p>
                            )}
                        </div>
                    )}
                </div>
            )}

            {/* Permissions tab */}
            {tab === 'permissions' && (
                <div>
                    <p className="text-xs mb-5" style={{ color: 'var(--text-muted)' }}>
                        System-defined permissions. Read-only.
                    </p>
                    {permsLoading && (
                        <div className="flex justify-center py-12">
                            <Spinner />
                        </div>
                    )}
                    {!permsLoading &&
                        Object.entries(permsByResource).map(([resource, perms]) => (
                            <div key={resource} className="mb-6">
                                <h3
                                    className="text-xs font-semibold uppercase tracking-wider mb-2"
                                    style={{ color: 'var(--text-muted)' }}
                                >
                                    {resource}
                                </h3>
                                <div
                                    className="rounded-xl border overflow-hidden"
                                    style={{ borderColor: 'var(--border)' }}
                                >
                                    <table className="w-full text-sm">
                                        <thead>
                                            <tr style={{ backgroundColor: 'var(--bg-subtle)' }}>
                                                <th
                                                    className="px-4 py-2 text-left text-xs font-medium"
                                                    style={{ color: 'var(--text-muted)' }}
                                                >
                                                    Action
                                                </th>
                                                <th
                                                    className="px-4 py-2 text-left text-xs font-medium"
                                                    style={{ color: 'var(--text-muted)' }}
                                                >
                                                    Name
                                                </th>
                                                <th
                                                    className="px-4 py-2 text-left text-xs font-medium"
                                                    style={{ color: 'var(--text-muted)' }}
                                                >
                                                    Description
                                                </th>
                                            </tr>
                                        </thead>
                                        <tbody>
                                            {perms.map((perm, i) => (
                                                <tr
                                                    key={perm.id}
                                                    style={{ borderTop: i > 0 ? '1px solid var(--border)' : undefined }}
                                                >
                                                    <td
                                                        className="px-4 py-2.5 font-mono text-xs"
                                                        style={{ color: 'var(--text-secondary)' }}
                                                    >
                                                        {perm.action}
                                                    </td>
                                                    <td
                                                        className="px-4 py-2.5"
                                                        style={{ color: 'var(--text-primary)' }}
                                                    >
                                                        {perm.name}
                                                    </td>
                                                    <td className="px-4 py-2.5" style={{ color: 'var(--text-muted)' }}>
                                                        {perm.description}
                                                    </td>
                                                </tr>
                                            ))}
                                        </tbody>
                                    </table>
                                </div>
                            </div>
                        ))}
                    {!permsLoading && Object.keys(permsByResource).length === 0 && (
                        <p className="text-sm py-8 text-center" style={{ color: 'var(--text-muted)' }}>
                            No permissions found.
                        </p>
                    )}
                </div>
            )}

            {/* Create Role */}
            <Modal isOpen={createOpen} onClose={() => setCreateOpen(false)} title="New Role">
                <div className="space-y-4">
                    <Input
                        label="Name"
                        value={formData.name}
                        onChange={(e) => setFormData((d) => ({ ...d, name: e.target.value }))}
                        placeholder="e.g. developer"
                    />
                    <div>
                        <label
                            htmlFor="create-role-description"
                            className="block text-sm font-medium mb-1"
                            style={{ color: 'var(--text-secondary)' }}
                        >
                            Description
                        </label>
                        <textarea
                            id="create-role-description"
                            value={formData.description}
                            onChange={(e) => setFormData((d) => ({ ...d, description: e.target.value }))}
                            rows={3}
                            className="w-full px-3 py-2 rounded-md border text-sm resize-none"
                            style={{
                                backgroundColor: 'var(--bg-app)',
                                borderColor: 'var(--border-strong)',
                                color: 'var(--text-primary)',
                            }}
                            placeholder="What this role is for"
                        />
                    </div>
                    <AssignableScopeSelect
                        id="create-role-assignable-scope"
                        value={formData.assignable_scope}
                        onChange={(assignable_scope) => setFormData((d) => ({ ...d, assignable_scope }))}
                    />
                    <PermissionChecklist
                        permissions={permissions ?? []}
                        loading={permsLoading}
                        selected={formData.permissions}
                        onChange={(next) => setFormData((d) => ({ ...d, permissions: next }))}
                    />
                    {createMutation.isError && (
                        <p className="text-sm text-red-600">
                            {apiErrorMessage(createMutation.error, 'Failed to create role. Please try again.')}
                        </p>
                    )}
                    <div className="flex justify-end gap-2 pt-2">
                        <Button variant="secondary" onClick={() => setCreateOpen(false)}>
                            Cancel
                        </Button>
                        <Button loading={createMutation.isPending} disabled={!createReady} onClick={handleCreate}>
                            Create
                        </Button>
                    </div>
                </div>
            </Modal>

            {/* Edit Role */}
            <Modal isOpen={editRole !== null} onClose={() => setEditRole(null)} title="Edit Role">
                <div className="space-y-4">
                    {editBuiltIn && (
                        <p className="text-sm" style={{ color: 'var(--text-secondary)' }}>
                            Built-in roles cannot be edited.
                        </p>
                    )}
                    {/* The server has no rename, so Name is shown read-only. */}
                    <Input label="Name" value={formData.name} disabled />
                    <div>
                        <label
                            htmlFor="edit-role-description"
                            className="block text-sm font-medium mb-1"
                            style={{ color: 'var(--text-secondary)' }}
                        >
                            Description
                        </label>
                        <textarea
                            id="edit-role-description"
                            value={formData.description}
                            onChange={(e) => setFormData((d) => ({ ...d, description: e.target.value }))}
                            disabled={editBuiltIn}
                            rows={3}
                            className="w-full px-3 py-2 rounded-md border text-sm resize-none disabled:opacity-60 disabled:cursor-not-allowed"
                            style={{
                                backgroundColor: 'var(--bg-app)',
                                borderColor: 'var(--border-strong)',
                                color: 'var(--text-primary)',
                            }}
                        />
                    </div>
                    <AssignableScopeSelect
                        id="edit-role-assignable-scope"
                        builtIn={editBuiltIn}
                        value={formData.assignable_scope}
                        onChange={(assignable_scope) => setFormData((d) => ({ ...d, assignable_scope }))}
                    />
                    <PermissionChecklist
                        permissions={permissions ?? []}
                        loading={permsLoading}
                        selected={formData.permissions}
                        onChange={(next) => setFormData((d) => ({ ...d, permissions: next }))}
                        disabled={editBuiltIn}
                    />
                    {updateMutation.isError && (
                        <p className="text-sm text-red-600">
                            {apiErrorMessage(updateMutation.error, 'Failed to update role. Please try again.')}
                        </p>
                    )}
                    <div className="flex justify-end gap-2 pt-2">
                        <Button variant="secondary" onClick={() => setEditRole(null)}>
                            Cancel
                        </Button>
                        <Button loading={updateMutation.isPending} disabled={!editReady} onClick={handleUpdate}>
                            Save
                        </Button>
                    </div>
                </div>
            </Modal>

            {/* Manage Permissions */}
            <Modal
                isOpen={manageRoleId !== null}
                onClose={() => setManageRoleId(null)}
                title={manageRole ? `Permissions — ${manageRole.name}` : 'Permissions'}
                size="lg"
            >
                {!manageRole || permsLoading ? (
                    <div className="flex justify-center py-8">
                        <Spinner />
                    </div>
                ) : (
                    <div className="max-h-[55vh] overflow-y-auto space-y-5 pr-1">
                        {Object.entries(permsByResource).map(([resource, perms]) => (
                            <div key={resource}>
                                <h4
                                    className="text-xs font-semibold uppercase tracking-wider mb-2"
                                    style={{ color: 'var(--text-secondary)' }}
                                >
                                    {resource}
                                </h4>
                                <div className="space-y-1">
                                    {perms.map((perm) => {
                                        const assigned = manageRole.permissions.some((p) => p.id === perm.id);
                                        return (
                                            <label
                                                key={perm.id}
                                                className="flex items-center gap-3 rounded-md px-3 py-2 cursor-pointer"
                                                style={{ backgroundColor: 'var(--bg-subtle)' }}
                                            >
                                                <input
                                                    type="checkbox"
                                                    checked={assigned}
                                                    disabled={isMutatingPerm}
                                                    onChange={() => handleTogglePerm(perm)}
                                                    className="h-4 w-4 rounded-sm accent-blue-600"
                                                />
                                                <div className="min-w-0">
                                                    <span
                                                        className="text-sm font-medium"
                                                        style={{ color: 'var(--text-primary)' }}
                                                    >
                                                        {perm.name}
                                                    </span>
                                                    {perm.description && (
                                                        <span
                                                            className="text-xs ml-2"
                                                            style={{ color: 'var(--text-muted)' }}
                                                        >
                                                            {perm.description}
                                                        </span>
                                                    )}
                                                </div>
                                            </label>
                                        );
                                    })}
                                </div>
                            </div>
                        ))}
                        {Object.keys(permsByResource).length === 0 && (
                            <p className="text-sm text-center py-4" style={{ color: 'var(--text-muted)' }}>
                                No permissions available.
                            </p>
                        )}
                    </div>
                )}
                <div className="flex justify-end pt-4 mt-2 border-t" style={{ borderColor: 'var(--border)' }}>
                    <Button variant="secondary" onClick={() => setManageRoleId(null)}>
                        Close
                    </Button>
                </div>
            </Modal>

            {/* Delete Role */}
            <Modal
                isOpen={deleteRole !== null}
                onClose={() => {
                    setDeleteRole(null);
                    deleteMutation.reset();
                }}
                title="Delete Role"
                size="sm"
            >
                <div className="space-y-4">
                    <p className="text-sm" style={{ color: 'var(--text-secondary)' }}>
                        Delete role <strong style={{ color: 'var(--text-primary)' }}>{deleteRole?.name}</strong>? This
                        action cannot be undone.
                    </p>
                    {deleteMutation.isError && (
                        <p className="text-sm text-red-600">Failed to delete role. Please try again.</p>
                    )}
                    <div className="flex justify-end gap-2 pt-2">
                        <Button
                            variant="secondary"
                            onClick={() => {
                                setDeleteRole(null);
                                deleteMutation.reset();
                            }}
                        >
                            Cancel
                        </Button>
                        <Button variant="destructive" loading={deleteMutation.isPending} onClick={handleDelete}>
                            Delete
                        </Button>
                    </div>
                </div>
            </Modal>
        </div>
    );
};
