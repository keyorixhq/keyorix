import React from 'react';
import { Link } from 'react-router-dom';
import {
    KeyIcon,
    ServerStackIcon,
    UsersIcon,
    CheckCircleIcon,
    ExclamationTriangleIcon,
    ArrowsRightLeftIcon,
} from '@heroicons/react/24/outline';
import { useProject, useProjectMembers, useProjectDrift } from '../../features/projects/api';

interface ProjectOverviewTabProps {
    projectId: number;
}

// Stat card: icon + large number + label — mirrors SummaryStat in ProjectDriftTab.
const StatCard: React.FC<{
    icon: React.ElementType;
    label: string;
    value: number | undefined;
    loading: boolean;
}> = ({ icon: Icon, label, value, loading }) => (
    <div
        className="rounded-lg border px-4 py-5 flex items-center gap-4"
        style={{ borderColor: 'var(--border)', backgroundColor: 'var(--bg-surface)' }}
    >
        <div
            className="h-10 w-10 rounded-lg flex items-center justify-center shrink-0"
            style={{ backgroundColor: 'var(--accent-subtle)' }}
        >
            <Icon className="h-5 w-5" style={{ color: 'var(--accent)' }} />
        </div>
        <div>
            {loading ? (
                <div className="h-7 w-12 rounded-sm animate-pulse" style={{ backgroundColor: 'var(--bg-muted)' }} />
            ) : (
                <div className="text-2xl font-semibold" style={{ color: 'var(--text-primary)' }}>
                    {value ?? '—'}
                </div>
            )}
            <div className="text-xs mt-0.5" style={{ color: 'var(--text-muted)' }}>
                {label}
            </div>
        </div>
    </div>
);

/**
 * ADR-020 Overview tab. Surfaces the project's description, created date,
 * three headline stats (secrets / environments / members), and a one-line
 * environment-sync status that links through to the Drift tab on problems.
 */
export const ProjectOverviewTab: React.FC<ProjectOverviewTabProps> = ({ projectId }) => {
    // useProject result is already cached by the parent page; no extra fetch.
    const { data: project, isLoading: projectLoading } = useProject(projectId);
    const { data: members = [], isLoading: membersLoading } = useProjectMembers(projectId);
    const { data: drift, isLoading: driftLoading } = useProjectDrift(projectId);

    const drifted = drift?.driftedKeys ?? [];
    const envCount = drift?.environments?.length ?? 0;

    return (
        <div>
            {/* Description and created date */}
            {(projectLoading || project?.description || project?.createdAt) && (
                <div
                    className="rounded-lg border px-4 py-3 mb-5"
                    style={{ borderColor: 'var(--border)', backgroundColor: 'var(--bg-surface)' }}
                >
                    {projectLoading ? (
                        <div className="space-y-2 animate-pulse">
                            <div className="h-3 w-3/4 rounded-sm" style={{ backgroundColor: 'var(--bg-muted)' }} />
                            <div className="h-2.5 w-1/4 rounded-sm" style={{ backgroundColor: 'var(--bg-muted)' }} />
                        </div>
                    ) : (
                        <>
                            {project?.description && (
                                <p className="text-sm mb-1" style={{ color: 'var(--text-secondary)' }}>
                                    {project.description}
                                </p>
                            )}
                            {project?.createdAt && (
                                <p className="text-xs" style={{ color: 'var(--text-muted)' }}>
                                    Created{' '}
                                    {new Date(project.createdAt).toLocaleDateString(undefined, {
                                        year: 'numeric',
                                        month: 'long',
                                        day: 'numeric',
                                    })}
                                </p>
                            )}
                        </>
                    )}
                </div>
            )}

            {/* Stat cards */}
            <div className="grid grid-cols-1 sm:grid-cols-3 gap-3 mb-5">
                <StatCard icon={KeyIcon} label="Secrets" value={project?.secretCount} loading={projectLoading} />
                <StatCard
                    icon={ServerStackIcon}
                    label="Environments"
                    value={project?.environmentCount}
                    loading={projectLoading}
                />
                <StatCard
                    icon={UsersIcon}
                    label="Members"
                    value={membersLoading ? undefined : members.length}
                    loading={membersLoading}
                />
            </div>

            {/* Environment sync status */}
            <div>
                <h2 className="text-sm font-semibold mb-2" style={{ color: 'var(--text-primary)' }}>
                    Environment sync
                </h2>

                {driftLoading ? (
                    <div
                        className="rounded-lg border p-4 animate-pulse"
                        style={{ borderColor: 'var(--border)', backgroundColor: 'var(--bg-surface)' }}
                    >
                        <div className="h-4 w-56 rounded-sm" style={{ backgroundColor: 'var(--bg-muted)' }} />
                    </div>
                ) : !drift || envCount < 2 ? (
                    <div
                        className="rounded-lg border px-4 py-3 flex items-center gap-3"
                        style={{ borderColor: 'var(--border)', backgroundColor: 'var(--bg-surface)' }}
                    >
                        <ArrowsRightLeftIcon className="h-4 w-4 shrink-0" style={{ color: 'var(--text-muted)' }} />
                        <p className="text-sm" style={{ color: 'var(--text-muted)' }}>
                            Add at least two environments to enable drift detection.
                        </p>
                    </div>
                ) : drifted.length === 0 ? (
                    <div
                        className="rounded-lg border px-4 py-3 flex items-center gap-3"
                        style={{ borderColor: 'var(--border)', backgroundColor: 'var(--bg-surface)' }}
                    >
                        <CheckCircleIcon className="h-5 w-5 shrink-0" style={{ color: 'var(--success)' }} />
                        <p className="text-sm font-medium" style={{ color: 'var(--success)' }}>
                            All {envCount} environments in sync
                        </p>
                    </div>
                ) : (
                    <div
                        className="rounded-lg border px-4 py-3"
                        style={{ borderColor: 'var(--warning)', backgroundColor: 'var(--warning-subtle)' }}
                    >
                        <div className="flex items-center gap-3">
                            <ExclamationTriangleIcon className="h-5 w-5 shrink-0" style={{ color: 'var(--warning)' }} />
                            <p className="text-sm font-medium" style={{ color: 'var(--warning)' }}>
                                {drifted.length} key{drifted.length !== 1 ? 's' : ''} out of sync
                            </p>
                            <Link
                                to={`/projects/${projectId}/drift`}
                                className="ml-auto text-xs underline shrink-0"
                                style={{ color: 'var(--warning)' }}
                            >
                                View Drift →
                            </Link>
                        </div>
                        <ul className="mt-2 space-y-1">
                            {drifted.slice(0, 5).map((key) => (
                                <li
                                    key={key.name}
                                    className="text-xs font-mono"
                                    style={{ color: 'var(--text-secondary)' }}
                                >
                                    {key.name} —{' '}
                                    {key.status === 'missing_in_some'
                                        ? 'missing in some environments'
                                        : 'settings differ'}
                                </li>
                            ))}
                            {drifted.length > 5 && (
                                <li className="text-xs" style={{ color: 'var(--text-muted)' }}>
                                    +{drifted.length - 5} more…
                                </li>
                            )}
                        </ul>
                    </div>
                )}
            </div>
        </div>
    );
};
