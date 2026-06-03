import React from 'react';
import { useQuery } from '@tanstack/react-query';
import { usersApi } from '../../services/users';
import { UserCircleIcon } from '@heroicons/react/24/outline';

interface ProjectMembersTabProps {
    projectId: number;
}

/**
 * Phase 3D — Members tab.
 * RBAC is global so "members" = all active users.
 * Shows a simple read-only roster. Role assignment is a backlog item.
 */
export const ProjectMembersTab: React.FC<ProjectMembersTabProps> = ({ projectId: _projectId }) => {
    const { data, isLoading } = useQuery({
        queryKey: ['users-list-members'],
        queryFn: () => usersApi.list({ pageSize: 100 }),
        staleTime: 60_000,
    });

    const users = data?.data ?? [];

    return (
        <div>
            <div className="flex items-center justify-between mb-4">
                <div>
                    <h2 className="text-sm font-semibold" style={{ color: 'var(--text-primary)' }}>
                        Members
                    </h2>
                    <p className="text-xs mt-0.5" style={{ color: 'var(--text-muted)' }}>
                        Access control is global. All users with system access can access this project.
                    </p>
                </div>
            </div>

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
                ) : users.length === 0 ? (
                    <div className="p-10 text-center">
                        <UserCircleIcon className="h-10 w-10 mx-auto mb-3" style={{ color: 'var(--text-muted)' }} />
                        <p className="text-sm" style={{ color: 'var(--text-muted)' }}>No users found.</p>
                    </div>
                ) : (
                    <ul className="divide-y" style={{ borderColor: 'var(--border)' }}>
                        {users.map((user: any) => (
                            <li key={user.id} className="flex items-center gap-3 px-4 py-3">
                                <div className="h-8 w-8 rounded-full flex items-center justify-center shrink-0 text-xs font-semibold"
                                    style={{ backgroundColor: 'var(--accent-subtle)', color: 'var(--accent-text)' }}>
                                    {(user.displayName ?? user.username ?? '?').charAt(0).toUpperCase()}
                                </div>
                                <div className="flex-1 min-w-0">
                                    <p className="text-sm font-medium truncate" style={{ color: 'var(--text-primary)' }}>
                                        {user.displayName ?? user.username}
                                    </p>
                                    <p className="text-xs truncate" style={{ color: 'var(--text-muted)' }}>
                                        {user.email}
                                    </p>
                                </div>
                                <span className="text-xs px-2 py-0.5 rounded-full shrink-0"
                                    style={{
                                        backgroundColor: user.isActive !== false ? 'var(--success-subtle)' : 'var(--bg-muted)',
                                        color: user.isActive !== false ? 'var(--success)' : 'var(--text-muted)',
                                    }}>
                                    {user.isActive !== false ? 'Active' : 'Inactive'}
                                </span>
                            </li>
                        ))}
                    </ul>
                )}
            </div>

            <p className="text-xs mt-3" style={{ color: 'var(--text-muted)' }}>
                Project-scoped role assignments are on the roadmap. For now, manage access via Access Control → Users.
            </p>
        </div>
    );
};
