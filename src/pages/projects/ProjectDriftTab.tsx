import React from 'react';
import { ArrowsRightLeftIcon, CheckCircleIcon } from '@heroicons/react/24/outline';
import { useProjectDrift } from '../../features/projects/api';
import type { DriftKey } from '../../services/projects';

interface ProjectDriftTabProps {
    projectId: number;
}

type Badge = { bg: string; text: string; label: string };

const FALLBACK_BADGE: Badge = { bg: 'var(--warning-subtle)', text: 'var(--warning)', label: 'Settings differ' };

const STATUS_BADGE: Record<string, Badge> = {
    missing_in_some: { bg: 'var(--error-subtle)', text: 'var(--error)', label: 'Missing' },
    metadata_drift: FALLBACK_BADGE,
};

const SummaryStat: React.FC<{ label: string; value: number; tone?: string | undefined }> = ({ label, value, tone }) => (
    <div
        className="rounded-lg border px-4 py-3"
        style={{ borderColor: 'var(--border)', backgroundColor: 'var(--bg-surface)' }}
    >
        <div className="text-2xl font-semibold" style={{ color: tone ?? 'var(--text-primary)' }}>
            {value}
        </div>
        <div className="text-xs mt-0.5" style={{ color: 'var(--text-muted)' }}>
            {label}
        </div>
    </div>
);

/**
 * Cross-environment drift tab (M2). Shows which secret keys are missing from
 * some environments or carry diverging settings across the project's
 * environments. A key × environment presence matrix makes the gaps visible.
 */
export const ProjectDriftTab: React.FC<ProjectDriftTabProps> = ({ projectId }) => {
    const { data, isLoading, isError } = useProjectDrift(projectId);

    const envs = data?.environments ?? [];
    const keys = data?.driftedKeys ?? [];
    const summary = data?.summary;

    const cellHas = (key: DriftKey, envId: number) => key.presentIn.includes(envId);

    return (
        <div>
            <div className="mb-4">
                <h2 className="text-sm font-semibold" style={{ color: 'var(--text-primary)' }}>
                    Environment Drift
                </h2>
                <p className="text-xs mt-0.5" style={{ color: 'var(--text-muted)' }}>
                    Secret keys that are missing from some environments, or present everywhere with diverging settings.
                    No secret values are read.
                </p>
            </div>

            {summary && !isLoading && !isError && (
                <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 mb-5">
                    <SummaryStat label="Keys" value={summary.totalKeys} />
                    <SummaryStat label="Consistent" value={summary.consistentKeys} tone="var(--success)" />
                    <SummaryStat
                        label="Missing in some"
                        value={summary.missingInSome}
                        tone={summary.missingInSome > 0 ? 'var(--error)' : undefined}
                    />
                    <SummaryStat
                        label="Settings differ"
                        value={summary.metadataDrift}
                        tone={summary.metadataDrift > 0 ? 'var(--warning)' : undefined}
                    />
                </div>
            )}

            <div
                className="rounded-lg border"
                style={{ borderColor: 'var(--border)', backgroundColor: 'var(--bg-surface)' }}
            >
                {isLoading ? (
                    <div className="p-6 space-y-3">
                        {[1, 2, 3, 4].map((i) => (
                            <div key={i} className="flex items-center gap-3 animate-pulse">
                                <div className="h-3 w-40 rounded-sm" style={{ backgroundColor: 'var(--bg-muted)' }} />
                                <div className="h-3 flex-1 rounded-sm" style={{ backgroundColor: 'var(--bg-muted)' }} />
                            </div>
                        ))}
                    </div>
                ) : isError ? (
                    <div className="p-6 text-center">
                        <p className="text-sm" style={{ color: 'var(--error)' }}>
                            Failed to load drift report.
                        </p>
                    </div>
                ) : envs.length < 2 ? (
                    <div className="p-10 text-center">
                        <ArrowsRightLeftIcon
                            className="h-10 w-10 mx-auto mb-3"
                            style={{ color: 'var(--text-muted)' }}
                        />
                        <p className="text-sm font-medium mb-1" style={{ color: 'var(--text-secondary)' }}>
                            Need at least two environments
                        </p>
                        <p className="text-xs" style={{ color: 'var(--text-muted)' }}>
                            Drift compares secret keys across a project's environments.
                        </p>
                    </div>
                ) : keys.length === 0 ? (
                    <div className="p-10 text-center">
                        <CheckCircleIcon className="h-10 w-10 mx-auto mb-3" style={{ color: 'var(--success)' }} />
                        <p className="text-sm font-medium mb-1" style={{ color: 'var(--text-secondary)' }}>
                            No drift detected
                        </p>
                        <p className="text-xs" style={{ color: 'var(--text-muted)' }}>
                            Every secret key is present in all {envs.length} environments with matching settings.
                        </p>
                    </div>
                ) : (
                    <div className="overflow-x-auto">
                        <table className="min-w-full divide-y" style={{ borderColor: 'var(--border)' }}>
                            <thead style={{ backgroundColor: 'var(--bg-subtle)' }}>
                                <tr>
                                    <th
                                        className="px-4 py-3 text-left text-xs font-medium uppercase tracking-wider"
                                        style={{ color: 'var(--text-muted)' }}
                                    >
                                        Key
                                    </th>
                                    {envs.map((env) => (
                                        <th
                                            key={env.id}
                                            className="px-4 py-3 text-center text-xs font-medium uppercase tracking-wider"
                                            style={{ color: 'var(--text-muted)' }}
                                        >
                                            {env.name}
                                        </th>
                                    ))}
                                    <th
                                        className="px-4 py-3 text-left text-xs font-medium uppercase tracking-wider"
                                        style={{ color: 'var(--text-muted)' }}
                                    >
                                        Issue
                                    </th>
                                </tr>
                            </thead>
                            <tbody className="divide-y" style={{ borderColor: 'var(--border)' }}>
                                {keys.map((key) => {
                                    const badge = STATUS_BADGE[key.status] ?? FALLBACK_BADGE;
                                    return (
                                        <tr key={key.name}>
                                            <td
                                                className="px-4 py-3 whitespace-nowrap font-mono text-xs"
                                                style={{ color: 'var(--text-primary)' }}
                                            >
                                                {key.name}
                                            </td>
                                            {envs.map((env) => {
                                                const present = cellHas(key, env.id);
                                                return (
                                                    <td key={env.id} className="px-4 py-3 text-center">
                                                        <span
                                                            className="inline-block h-2.5 w-2.5 rounded-full"
                                                            title={present ? 'present' : 'missing'}
                                                            style={{
                                                                backgroundColor: present
                                                                    ? 'var(--success)'
                                                                    : 'var(--error)',
                                                            }}
                                                        />
                                                    </td>
                                                );
                                            })}
                                            <td className="px-4 py-3 whitespace-nowrap">
                                                <span
                                                    className="text-xs font-medium px-2 py-0.5 rounded-full"
                                                    style={{ backgroundColor: badge.bg, color: badge.text }}
                                                >
                                                    {badge.label}
                                                </span>
                                                {key.driftFields.length > 0 && (
                                                    <span
                                                        className="text-xs ml-2"
                                                        style={{ color: 'var(--text-muted)' }}
                                                    >
                                                        {key.driftFields.join(', ')}
                                                    </span>
                                                )}
                                            </td>
                                        </tr>
                                    );
                                })}
                            </tbody>
                        </table>
                    </div>
                )}
            </div>
        </div>
    );
};
