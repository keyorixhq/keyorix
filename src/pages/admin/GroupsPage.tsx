import React, { useState } from 'react';
import { PlusIcon, PencilSquareIcon, TrashIcon, UsersIcon } from '@heroicons/react/24/outline';
import { Button, Modal, Input, Spinner } from '../../components/ui';
import {
    useGroups, useGroupRoles, useRoles,
    useCreateGroup, useUpdateGroup, useDeleteGroup,
    useAssignRoleToGroup, useRemoveRoleFromGroup,
} from '../../features/admin';
import type { Group, Role } from '../../types/rbac';

interface GroupFormData {
    name: string;
    description: string;
}

interface GroupRowProps {
    group: Group;
    onEdit: (group: Group) => void;
    onDelete: (group: Group) => void;
    onManageRoles: (group: Group) => void;
}

const GroupRow: React.FC<GroupRowProps> = ({ group, onEdit, onDelete, onManageRoles }) => {
    const { data: groupRoles } = useGroupRoles(group.id);
    const roles = groupRoles?.roles ?? [];

    return (
        <tr style={{ borderTop: '1px solid var(--border)' }}>
            <td className="px-4 py-3">
                <span className="text-sm font-medium" style={{ color: 'var(--text-primary)' }}>
                    {group.name}
                </span>
            </td>
            <td className="px-4 py-3">
                <span className="text-sm" style={{ color: 'var(--text-secondary)' }}>
                    {group.description || '—'}
                </span>
            </td>
            <td className="px-4 py-3 text-center">
                <span className="text-sm" style={{ color: 'var(--text-muted)' }}>
                    {group.member_count ?? '—'}
                </span>
            </td>
            <td className="px-4 py-3">
                {roles.length === 0 ? (
                    <span className="text-sm" style={{ color: 'var(--text-muted)' }}>None</span>
                ) : (
                    <div className="flex flex-wrap gap-1">
                        {roles.map(r => (
                            <span
                                key={r.id}
                                className="text-xs px-2 py-0.5 rounded-full font-medium"
                                style={{
                                    backgroundColor: 'var(--accent-subtle)',
                                    color: 'var(--accent-text)',
                                }}
                            >
                                {r.name}
                            </span>
                        ))}
                    </div>
                )}
            </td>
            <td className="px-4 py-3">
                <div className="flex items-center gap-1 justify-end">
                    <button
                        type="button"
                        onClick={() => onManageRoles(group)}
                        className="p-1.5 rounded-md transition-colors"
                        style={{ color: 'var(--text-muted)' }}
                        title="Manage roles"
                        onMouseEnter={e => (e.currentTarget as HTMLElement).style.color = 'var(--text-primary)'}
                        onMouseLeave={e => (e.currentTarget as HTMLElement).style.color = 'var(--text-muted)'}
                    >
                        <UsersIcon className="h-4 w-4" />
                    </button>
                    <button
                        type="button"
                        onClick={() => onEdit(group)}
                        className="p-1.5 rounded-md transition-colors"
                        style={{ color: 'var(--text-muted)' }}
                        title="Edit group"
                        onMouseEnter={e => (e.currentTarget as HTMLElement).style.color = 'var(--text-primary)'}
                        onMouseLeave={e => (e.currentTarget as HTMLElement).style.color = 'var(--text-muted)'}
                    >
                        <PencilSquareIcon className="h-4 w-4" />
                    </button>
                    <button
                        type="button"
                        onClick={() => onDelete(group)}
                        className="p-1.5 rounded-md transition-colors"
                        style={{ color: 'var(--text-muted)' }}
                        title="Delete group"
                        onMouseEnter={e => (e.currentTarget as HTMLElement).style.color = '#ef4444'}
                        onMouseLeave={e => (e.currentTarget as HTMLElement).style.color = 'var(--text-muted)'}
                    >
                        <TrashIcon className="h-4 w-4" />
                    </button>
                </div>
            </td>
        </tr>
    );
};

export const GroupsPage: React.FC = () => {
    const [formData, setFormData] = useState<GroupFormData>({ name: '', description: '' });
    const [createOpen, setCreateOpen] = useState(false);
    const [editGroup, setEditGroup] = useState<Group | null>(null);
    const [deleteGroup, setDeleteGroup] = useState<Group | null>(null);
    const [manageGroupId, setManageGroupId] = useState<number | null>(null);

    const { data: groupsData, isLoading: groupsLoading, error: groupsError } = useGroups();
    const { data: allRoles, isLoading: rolesLoading } = useRoles();
    const { data: groupRolesData } = useGroupRoles(manageGroupId);
    const createMutation = useCreateGroup();
    const updateMutation = useUpdateGroup();
    const deleteMutation = useDeleteGroup();
    const assignMutation = useAssignRoleToGroup();
    const removeMutation = useRemoveRoleFromGroup();

    const groups = (groupsData?.data ?? []) as Group[];
    const assignedRoleIds = new Set((groupRolesData?.roles ?? []).map(r => r.id));
    const isMutatingRole = assignMutation.isLoading || removeMutation.isLoading;

    const openCreate = () => {
        setFormData({ name: '', description: '' });
        createMutation.reset();
        setCreateOpen(true);
    };

    const openEdit = (group: Group) => {
        setFormData({ name: group.name, description: group.description });
        updateMutation.reset();
        setEditGroup(group);
    };

    const openDelete = (group: Group) => {
        deleteMutation.reset();
        setDeleteGroup(group);
    };

    const handleCreate = () => {
        if (!formData.name.trim()) return;
        createMutation.mutate(formData, { onSuccess: () => setCreateOpen(false) });
    };

    const handleUpdate = () => {
        if (!editGroup || !formData.name.trim()) return;
        updateMutation.mutate({ id: editGroup.id, body: formData }, { onSuccess: () => setEditGroup(null) });
    };

    const handleDelete = () => {
        if (!deleteGroup) return;
        deleteMutation.mutate(deleteGroup.id, {
            onSuccess: () => { deleteMutation.reset(); setDeleteGroup(null); },
        });
    };

    const handleToggleRole = (role: Role) => {
        if (manageGroupId === null) return;
        if (assignedRoleIds.has(role.id)) {
            removeMutation.mutate({ groupId: manageGroupId, roleId: role.id });
        } else {
            assignMutation.mutate({ groupId: manageGroupId, roleId: role.id });
        }
    };

    return (
        <div className="max-w-5xl mx-auto px-6 py-8">
            <div className="mb-6 flex items-start justify-between">
                <div>
                    <h1 className="text-2xl font-bold tracking-tight" style={{ color: 'var(--text-primary)' }}>
                        Groups
                    </h1>
                    <p className="mt-1 text-sm" style={{ color: 'var(--text-muted)' }}>
                        Organise users into groups and assign roles at the group level.
                    </p>
                </div>
                <Button size="sm" onClick={openCreate} icon={PlusIcon}>
                    New Group
                </Button>
            </div>

            {/* Table */}
            <div className="rounded-xl border overflow-hidden" style={{ borderColor: 'var(--border)' }}>
                <table className="w-full text-sm">
                    <thead>
                        <tr style={{ backgroundColor: 'var(--bg-subtle)' }}>
                            <th className="px-4 py-3 text-left text-xs font-medium"
                                style={{ color: 'var(--text-muted)' }}>Name</th>
                            <th className="px-4 py-3 text-left text-xs font-medium"
                                style={{ color: 'var(--text-muted)' }}>Description</th>
                            <th className="px-4 py-3 text-center text-xs font-medium"
                                style={{ color: 'var(--text-muted)' }}>Members</th>
                            <th className="px-4 py-3 text-left text-xs font-medium"
                                style={{ color: 'var(--text-muted)' }}>Roles</th>
                            <th className="px-4 py-3 text-right text-xs font-medium"
                                style={{ color: 'var(--text-muted)' }}>Actions</th>
                        </tr>
                    </thead>
                    <tbody>
                        {groupsLoading && (
                            <tr>
                                <td colSpan={5} className="px-4 py-12 text-center">
                                    <Spinner className="mx-auto" />
                                </td>
                            </tr>
                        )}
                        {groupsError !== null && (
                            <tr>
                                <td colSpan={5} className="px-4 py-8 text-center text-sm"
                                    style={{ color: 'var(--text-muted)' }}>
                                    Failed to load groups. Please try again.
                                </td>
                            </tr>
                        )}
                        {!groupsLoading && !groupsError && groups.length === 0 && (
                            <tr>
                                <td colSpan={5} className="px-4 py-8 text-center text-sm"
                                    style={{ color: 'var(--text-muted)' }}>
                                    No groups yet. Create one to get started.
                                </td>
                            </tr>
                        )}
                        {!groupsLoading && !groupsError && groups.map(group => (
                            <GroupRow
                                key={group.id}
                                group={group}
                                onEdit={openEdit}
                                onDelete={openDelete}
                                onManageRoles={g => setManageGroupId(g.id)}
                            />
                        ))}
                    </tbody>
                </table>
            </div>

            {/* Create Group */}
            <Modal isOpen={createOpen} onClose={() => setCreateOpen(false)} title="New Group">
                <div className="space-y-4">
                    <Input
                        label="Name"
                        value={formData.name}
                        onChange={e => setFormData(d => ({ ...d, name: e.target.value }))}
                        placeholder="e.g. platform-team"
                    />
                    <div>
                        <label className="block text-sm font-medium mb-1"
                            style={{ color: 'var(--text-secondary)' }}>
                            Description
                        </label>
                        <textarea
                            value={formData.description}
                            onChange={e => setFormData(d => ({ ...d, description: e.target.value }))}
                            rows={3}
                            className="w-full px-3 py-2 rounded-md border text-sm resize-none"
                            style={{
                                backgroundColor: 'var(--bg-app)',
                                borderColor: 'var(--border-strong)',
                                color: 'var(--text-primary)',
                            }}
                            placeholder="What this group is for"
                        />
                    </div>
                    {createMutation.isError && (
                        <p className="text-sm text-red-600">Failed to create group. Please try again.</p>
                    )}
                    <div className="flex justify-end gap-2 pt-2">
                        <Button variant="secondary" onClick={() => setCreateOpen(false)}>Cancel</Button>
                        <Button
                            loading={createMutation.isLoading}
                            disabled={!formData.name.trim()}
                            onClick={handleCreate}
                        >
                            Create
                        </Button>
                    </div>
                </div>
            </Modal>

            {/* Edit Group */}
            <Modal isOpen={editGroup !== null} onClose={() => setEditGroup(null)} title="Edit Group">
                <div className="space-y-4">
                    <Input
                        label="Name"
                        value={formData.name}
                        onChange={e => setFormData(d => ({ ...d, name: e.target.value }))}
                    />
                    <div>
                        <label className="block text-sm font-medium mb-1"
                            style={{ color: 'var(--text-secondary)' }}>
                            Description
                        </label>
                        <textarea
                            value={formData.description}
                            onChange={e => setFormData(d => ({ ...d, description: e.target.value }))}
                            rows={3}
                            className="w-full px-3 py-2 rounded-md border text-sm resize-none"
                            style={{
                                backgroundColor: 'var(--bg-app)',
                                borderColor: 'var(--border-strong)',
                                color: 'var(--text-primary)',
                            }}
                        />
                    </div>
                    {updateMutation.isError && (
                        <p className="text-sm text-red-600">Failed to update group. Please try again.</p>
                    )}
                    <div className="flex justify-end gap-2 pt-2">
                        <Button variant="secondary" onClick={() => setEditGroup(null)}>Cancel</Button>
                        <Button
                            loading={updateMutation.isLoading}
                            disabled={!formData.name.trim()}
                            onClick={handleUpdate}
                        >
                            Save
                        </Button>
                    </div>
                </div>
            </Modal>

            {/* Manage Roles */}
            <Modal
                isOpen={manageGroupId !== null}
                onClose={() => setManageGroupId(null)}
                title="Manage Roles"
                size="sm"
            >
                {rolesLoading ? (
                    <div className="flex justify-center py-8">
                        <Spinner />
                    </div>
                ) : (
                    <div className="space-y-1 max-h-[55vh] overflow-y-auto pr-1">
                        {(allRoles ?? []).map(role => {
                            const assigned = assignedRoleIds.has(role.id);
                            return (
                                <label
                                    key={role.id}
                                    className="flex items-center gap-3 rounded-md px-3 py-2.5 cursor-pointer"
                                    style={{ backgroundColor: 'var(--bg-subtle)' }}
                                >
                                    <input
                                        type="checkbox"
                                        checked={assigned}
                                        disabled={isMutatingRole}
                                        onChange={() => handleToggleRole(role)}
                                        className="h-4 w-4 rounded accent-blue-600"
                                    />
                                    <div className="min-w-0">
                                        <span className="text-sm font-medium block"
                                            style={{ color: 'var(--text-primary)' }}>
                                            {role.name}
                                        </span>
                                        {role.description && (
                                            <span className="text-xs"
                                                style={{ color: 'var(--text-muted)' }}>
                                                {role.description}
                                            </span>
                                        )}
                                    </div>
                                </label>
                            );
                        })}
                        {(allRoles ?? []).length === 0 && (
                            <p className="text-sm text-center py-4" style={{ color: 'var(--text-muted)' }}>
                                No roles available.
                            </p>
                        )}
                    </div>
                )}
                <div className="flex justify-end pt-4 mt-2 border-t" style={{ borderColor: 'var(--border)' }}>
                    <Button variant="secondary" onClick={() => setManageGroupId(null)}>Close</Button>
                </div>
            </Modal>

            {/* Delete Group */}
            <Modal
                isOpen={deleteGroup !== null}
                onClose={() => { setDeleteGroup(null); deleteMutation.reset(); }}
                title="Delete Group"
                size="sm"
            >
                <div className="space-y-4">
                    <p className="text-sm" style={{ color: 'var(--text-secondary)' }}>
                        Delete group{' '}
                        <strong style={{ color: 'var(--text-primary)' }}>{deleteGroup?.name}</strong>?
                        This action cannot be undone.
                    </p>
                    {deleteMutation.isError && (
                        <p className="text-sm text-red-600">Failed to delete group. Please try again.</p>
                    )}
                    <div className="flex justify-end gap-2 pt-2">
                        <Button variant="secondary" onClick={() => { setDeleteGroup(null); deleteMutation.reset(); }}>
                            Cancel
                        </Button>
                        <Button variant="danger" loading={deleteMutation.isLoading} onClick={handleDelete}>
                            Delete
                        </Button>
                    </div>
                </div>
            </Modal>
        </div>
    );
};
