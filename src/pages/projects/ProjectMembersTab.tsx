import React, { useMemo, useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import { UserCircleIcon, TrashIcon, PlusIcon } from '@heroicons/react/24/outline';
import { usersApi } from '../../services/users';
import { PROJECT_ROLES } from '../../services/projects';
import {
    useProjectMembers,
    useAddProjectMember,
    useUpdateProjectMemberRole,
    useRemoveProjectMember,
} from '../../features/projects/api';

interface ProjectMembersTabProps {
    projectId: number;
}

// "project_developer" → "Developer"
const roleLabel = (role: string) =>
    role.replace(/^project_/, '').replace(/^\w/, c => c.toUpperCase());

/**
 * ADR-021 Members tab. Project-scoped membership: shows the users who hold a
 * role in *this* project, with controls to add members, change their project
 * role, and remove them. System-level user provisioning stays on the admin
 * User Management page.
 */
export const ProjectMembersTab: React.FC<ProjectMembersTabProps> = ({ projectId }) => {
    const { data: members = [], isLoading } = useProjectMembers(projectId);
    const { data: usersResp } = useQuery({
        queryKey: ['users-list-members'],
        queryFn: () => usersApi.list({ pageSize: 200 }),
        staleTime: 60_000,
    });

    const addMember = useAddProjectMember(projectId);
    const updateRole = useUpdateProjectMemberRole(projectId);
    const removeMember = useRemoveProjectMember(projectId);

    const [newUserId, setNewUserId] = useState('');
    const [newRole, setNewRole] = useState<string>(PROJECT_ROLES[2]); // project_viewer
    const [error, setError] = useState('');

    const memberIds = useMemo(() => new Set(members.map(m => m.userId)), [members]);
    const candidates = useMemo(
        () => (usersResp?.data ?? []).filter((u: any) => !memberIds.has(u.id)),
        [usersResp, memberIds]
    );

    const handleAdd = () => {
        if (!newUserId) return;
        setError('');
        addMember.mutate(
            { userId: Number(newUserId), role: newRole },
            {
                onSuccess: () => setNewUserId(''),
                onError: (err: any) =>
                    setError(err?.response?.data?.error ?? err?.response?.data?.message ?? 'Failed to add member.'),
            }
        );
    };

    const selectStyle: React.CSSProperties = {
        backgroundColor: 'var(--bg-app)',
        border: '1px solid var(--border)',
        color: 'var(--text-primary)',
    };

    return (
        <div>
            <div className="mb-4">
                <h2 className="text-sm font-semibold" style={{ color: 'var(--text-primary)' }}>Members</h2>
                <p className="text-xs mt-0.5" style={{ color: 'var(--text-muted)' }}>
                    Users with a role in this project. Add existing users and assign a project role;
                    create new user accounts from Access Control → Users.
                </p>
            </div>

            {error && (
                <div className="rounded-lg px-3 py-2 text-sm mb-3" style={{ backgroundColor: 'var(--error-subtle)', color: 'var(--error)' }}>
                    {error}
                </div>
            )}

            {/* Add member */}
            <div className="rounded-lg border p-3 mb-4 flex flex-wrap items-center gap-2"
                style={{ borderColor: 'var(--border)', backgroundColor: 'var(--bg-surface)' }}>
                <select
                    value={newUserId}
                    onChange={e => setNewUserId(e.target.value)}
                    className="flex-1 min-w-[12rem] rounded-lg px-3 py-1.5 text-sm outline-hidden"
                    style={selectStyle}
                >
                    <option value="">Select a user to add…</option>
                    {candidates.map((u: any) => (
                        <option key={u.id} value={u.id}>
                            {(u.displayName ?? u.username)}{u.email ? ` (${u.email})` : ''}
                        </option>
                    ))}
                </select>
                <select
                    value={newRole}
                    onChange={e => setNewRole(e.target.value)}
                    className="rounded-lg px-3 py-1.5 text-sm outline-hidden"
                    style={selectStyle}
                >
                    {PROJECT_ROLES.map(r => (
                        <option key={r} value={r}>{roleLabel(r)}</option>
                    ))}
                </select>
                <button
                    onClick={handleAdd}
                    disabled={!newUserId || addMember.isPending}
                    className="flex items-center gap-1 px-3 py-1.5 rounded-lg text-sm font-medium disabled:opacity-50"
                    style={{ backgroundColor: 'var(--accent)', color: '#fff' }}
                >
                    <PlusIcon className="h-4 w-4" />Add
                </button>
            </div>

            {/* Member list */}
            <div className="rounded-lg border" style={{ borderColor: 'var(--border)', backgroundColor: 'var(--bg-surface)' }}>
                {isLoading ? (
                    <div className="p-6 space-y-3">
                        {[1, 2, 3].map(i => (
                            <div key={i} className="flex items-center gap-3 animate-pulse">
                                <div className="h-8 w-8 rounded-full" style={{ backgroundColor: 'var(--bg-muted)' }} />
                                <div className="flex-1">
                                    <div className="h-3 w-32 rounded-sm mb-1.5" style={{ backgroundColor: 'var(--bg-muted)' }} />
                                    <div className="h-2.5 w-48 rounded-sm" style={{ backgroundColor: 'var(--bg-muted)' }} />
                                </div>
                            </div>
                        ))}
                    </div>
                ) : members.length === 0 ? (
                    <div className="p-10 text-center">
                        <UserCircleIcon className="h-10 w-10 mx-auto mb-3" style={{ color: 'var(--text-muted)' }} />
                        <p className="text-sm" style={{ color: 'var(--text-muted)' }}>
                            No members yet. Add a user above to grant project access.
                        </p>
                    </div>
                ) : (
                    <ul className="divide-y" style={{ borderColor: 'var(--border)' }}>
                        {members.map(m => (
                            <li key={m.userId} className="flex items-center gap-3 px-4 py-3">
                                <div className="h-8 w-8 rounded-full flex items-center justify-center shrink-0 text-xs font-semibold"
                                    style={{ backgroundColor: 'var(--accent-subtle)', color: 'var(--accent-text)' }}>
                                    {(m.displayName || m.username || '?').charAt(0).toUpperCase()}
                                </div>
                                <div className="flex-1 min-w-0">
                                    <p className="text-sm font-medium truncate" style={{ color: 'var(--text-primary)' }}>
                                        {m.displayName || m.username}
                                    </p>
                                    <p className="text-xs truncate" style={{ color: 'var(--text-muted)' }}>{m.email}</p>
                                </div>
                                <select
                                    value={m.roleName}
                                    onChange={e => updateRole.mutate({ userId: m.userId, role: e.target.value })}
                                    disabled={updateRole.isPending}
                                    className="rounded-lg px-2 py-1 text-xs outline-hidden shrink-0"
                                    style={selectStyle}
                                >
                                    {/* Include the current role even if it's outside the standard set (e.g. a custom or system role). */}
                                    {!PROJECT_ROLES.includes(m.roleName as any) && (
                                        <option value={m.roleName}>{roleLabel(m.roleName)}</option>
                                    )}
                                    {PROJECT_ROLES.map(r => (
                                        <option key={r} value={r}>{roleLabel(r)}</option>
                                    ))}
                                </select>
                                <button
                                    onClick={() => removeMember.mutate(m.userId)}
                                    disabled={removeMember.isPending}
                                    className="p-1.5 rounded-sm transition-colors hover:bg-red-50 disabled:opacity-50 shrink-0"
                                    style={{ color: 'var(--error)' }}
                                    title="Remove from project"
                                >
                                    <TrashIcon className="h-4 w-4" />
                                </button>
                            </li>
                        ))}
                    </ul>
                )}
            </div>
        </div>
    );
};
