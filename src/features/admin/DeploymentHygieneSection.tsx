import React, { useState } from 'react';
import { SparklesIcon, XMarkIcon } from '@heroicons/react/24/outline';
import { useDeploymentHygiene, type HygieneCounts } from './api';

const SIGNALS: { key: keyof HygieneCounts; label: string }[] = [
    { key: 'orphaned_secrets', label: 'Orphaned' },
    { key: 'unused_secrets', label: 'Unused' },
    { key: 'expiring_secrets', label: 'Expiring' },
    { key: 'stale_machine_identities', label: 'Stale MI' },
    { key: 'rotation_overdue', label: 'Rotation overdue' },
];

const totalDebt = (c: HygieneCounts) => SIGNALS.reduce((sum, s) => sum + (c[s.key] ?? 0), 0);

/**
 * Deployment-wide secret-hygiene rollup (#365), the install-wide counterpart to the
 * per-project hygiene posture card. Surfaces install-wide totals of the 5 cleanup
 * signals plus the projects that carry debt, so an admin overseeing many projects sees
 * total cleanup debt in one place — beside the PAT/machine-token hygiene panels.
 * Admin-only (system.read); a 403 yields the empty rollup, so non-admins (and a fully
 * clean deployment) render nothing. Read-only awareness surface.
 */
export const DeploymentHygieneSection: React.FC = () => {
    const { data } = useDeploymentHygiene();
    const [dismissed, setDismissed] = useState(false);

    if (dismissed || !data || totalDebt(data.totals) === 0) return null;

    return (
        <div
            className="rounded-lg border mb-4 overflow-hidden"
            style={{ borderColor: 'var(--warning, #d97706)', backgroundColor: 'var(--warning-subtle, #fffbeb)' }}
        >
            <div className="flex items-center justify-between px-4 py-2.5">
                <div className="flex items-center gap-2" style={{ color: 'var(--warning, #92400e)' }}>
                    <SparklesIcon className="h-5 w-5 shrink-0" />
                    <span className="text-sm font-semibold">
                        Secret-hygiene debt across {data.projects.length} project{data.projects.length !== 1 ? 's' : ''}
                    </span>
                </div>
                <button
                    type="button"
                    onClick={() => setDismissed(true)}
                    className="p-1 rounded-sm hover:opacity-70"
                    style={{ color: 'var(--warning, #92400e)' }}
                    title="Dismiss"
                >
                    <XMarkIcon className="h-4 w-4" />
                </button>
            </div>

            {/* Install-wide totals */}
            <div className="grid grid-cols-2 sm:grid-cols-5 gap-2 px-4 pb-3">
                {SIGNALS.map((s) => {
                    const n = data.totals[s.key] ?? 0;
                    return (
                        <div
                            key={s.key}
                            className="rounded-md px-2.5 py-2"
                            style={{ backgroundColor: 'var(--bg-surface)' }}
                        >
                            <p
                                className="text-lg font-semibold"
                                style={{ color: n > 0 ? 'var(--warning, #92400e)' : 'var(--text-muted)' }}
                            >
                                {n}
                            </p>
                            <p className="text-xs" style={{ color: 'var(--text-muted)' }}>
                                {s.label}
                            </p>
                        </div>
                    );
                })}
            </div>

            {/* Per-project breakdown */}
            <ul className="divide-y" style={{ borderColor: 'var(--border)' }}>
                {data.projects.map((p) => (
                    <li
                        key={p.project_id}
                        className="flex items-center gap-3 px-4 py-2.5"
                        style={{ backgroundColor: 'var(--bg-surface)' }}
                    >
                        <div className="flex-1 min-w-0">
                            <p className="text-sm font-medium truncate" style={{ color: 'var(--text-primary)' }}>
                                {p.project_name}{' '}
                                <span className="font-normal" style={{ color: 'var(--text-muted)' }}>
                                    #{p.project_id}
                                </span>
                            </p>
                            <p className="text-xs truncate" style={{ color: 'var(--text-muted)' }}>
                                {SIGNALS.filter((s) => (p[s.key] ?? 0) > 0)
                                    .map((s) => `${p[s.key]} ${s.label.toLowerCase()}`)
                                    .join(' · ')}
                            </p>
                        </div>
                        <span
                            className="px-2 py-0.5 rounded-full text-xs font-medium shrink-0"
                            style={{ backgroundColor: 'var(--bg-muted)', color: 'var(--warning, #92400e)' }}
                        >
                            {totalDebt(p)} total
                        </span>
                    </li>
                ))}
            </ul>
        </div>
    );
};
