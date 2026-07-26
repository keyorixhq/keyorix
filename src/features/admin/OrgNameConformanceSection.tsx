import React, { useState } from 'react';
import { TagIcon, XMarkIcon } from '@heroicons/react/24/outline';
import { useDeploymentNameConformance } from './api';

/**
 * Org-wide naming-policy conformance (keyorix #372), the install-wide counterpart to the
 * per-project "Naming-policy violations" panel on Project Settings. Lists every live
 * secret across all projects whose name violates the current (global) naming policy, each
 * with its project and the reason — so an admin who added or tightened the policy sees all
 * the stragglers to rename in one place, beside the hygiene/inventory panels.
 * Admin-only (system.read); a 403 yields an empty report, so non-admins — and a clean
 * deployment, or one with no policy configured — render nothing. Read-only awareness surface.
 */
export const OrgNameConformanceSection: React.FC = () => {
    const { data } = useDeploymentNameConformance();
    const [dismissed, setDismissed] = useState(false);

    const violations = data?.violations ?? [];
    if (dismissed || !data || !data.policy_enabled || violations.length === 0) return null;

    return (
        <div
            className="rounded-lg border mb-4 overflow-hidden"
            style={{ borderColor: 'var(--warning, #d97706)', backgroundColor: 'var(--warning-subtle, #fffbeb)' }}
        >
            <div className="flex items-center justify-between px-4 py-2.5">
                <div className="flex items-center gap-2" style={{ color: 'var(--warning, #92400e)' }}>
                    <TagIcon className="h-5 w-5 shrink-0" />
                    <span className="text-sm font-semibold">
                        {violations.length} secret{violations.length !== 1 ? 's' : ''} violating the naming policy of{' '}
                        {data.total_secrets}
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

            <ul className="divide-y" style={{ borderColor: 'var(--border)' }}>
                {violations.map((v) => (
                    <li
                        key={`${v.project_id}-${v.id}`}
                        className="flex items-center gap-3 px-4 py-2.5"
                        style={{ backgroundColor: 'var(--bg-surface)' }}
                    >
                        <div className="flex-1 min-w-0">
                            <p className="text-sm font-medium truncate" style={{ color: 'var(--text-primary)' }}>
                                {v.name}{' '}
                                <span className="font-normal" style={{ color: 'var(--text-muted)' }}>
                                    {v.type}
                                </span>
                            </p>
                            <p className="text-xs truncate" style={{ color: 'var(--error)' }}>
                                {v.reason}
                            </p>
                        </div>
                        <span
                            className="px-2 py-0.5 rounded-full text-xs font-medium shrink-0 truncate max-w-[10rem]"
                            style={{ backgroundColor: 'var(--bg-muted)', color: 'var(--text-muted)' }}
                            title={v.project_name}
                        >
                            {v.project_name}
                        </span>
                    </li>
                ))}
            </ul>
        </div>
    );
};
