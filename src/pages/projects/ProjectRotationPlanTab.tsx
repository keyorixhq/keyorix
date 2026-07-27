import React from 'react';
import { CheckCircleIcon, ArrowPathIcon } from '@heroicons/react/24/outline';
import { useProjectRotationPlan } from '../../features/projects/api';
import type { PlannedRotation } from '../../services/projects';

interface ProjectRotationPlanTabProps {
    projectId: number;
}

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

const statusBadge = (s: PlannedRotation): { bg: string; text: string; label: string } => {
    if (s.status === 'overdue') {
        return { bg: 'var(--error-subtle)', text: 'var(--error)', label: `${s.daysOverdue}d overdue` };
    }
    return { bg: 'var(--warning-subtle)', text: 'var(--warning)', label: `due in ${-s.daysOverdue}d` };
};

const riskTone = (band: string): string => {
    switch (band) {
        case 'high':
            return 'var(--error)';
        case 'medium':
            return 'var(--warning)';
        default:
            return 'var(--text-muted)';
    }
};

/**
 * Automated rotation planning (ADR-053). Shows the project's overdue / due-soon
 * secrets as an ordered, dependency-respecting plan: each "wave" is a set of secrets
 * safe to rotate together, and a secret in a later wave rotates after anything it
 * depends on. Within a wave, the most urgent secrets come first. Metadata only — no
 * secret values are read.
 */
export const ProjectRotationPlanTab: React.FC<ProjectRotationPlanTabProps> = ({ projectId }) => {
    const { data, isLoading, isError } = useProjectRotationPlan(projectId);

    const waves = data?.waves ?? [];

    const bodyContent = isLoading ? (
        <div className="p-6 space-y-3">
            {[1, 2, 3].map((i) => (
                <div key={i} className="flex items-center gap-3 animate-pulse">
                    <div className="h-3 w-40 rounded-sm" style={{ backgroundColor: 'var(--bg-muted)' }} />
                    <div className="h-3 flex-1 rounded-sm" style={{ backgroundColor: 'var(--bg-muted)' }} />
                </div>
            ))}
        </div>
    ) : null;

    const errorContent = isError ? (
        <div className="p-6 text-center">
            <p className="text-sm" style={{ color: 'var(--error)' }}>
                Failed to load the rotation plan.
            </p>
        </div>
    ) : null;

    const emptyContent = !isLoading && !isError && waves.length === 0 ? (
        <div className="p-10 text-center">
            <CheckCircleIcon className="h-10 w-10 mx-auto mb-3" style={{ color: 'var(--success)' }} />
            <p className="text-sm font-medium mb-1" style={{ color: 'var(--text-secondary)' }}>
                Nothing to rotate
            </p>
            <p className="text-xs" style={{ color: 'var(--text-muted)' }}>
                No policy-covered secret in this project is overdue or due soon.
            </p>
        </div>
    ) : null;

    const wavesContent = !isLoading && !isError && waves.length > 0 ? (
        <div className="divide-y" style={{ borderColor: 'var(--border)' }}>
            {waves.map((wave) => (
                <div key={wave.index} className="p-4">
                    <div className="flex items-center gap-2 mb-3">
                        <span
                            className="text-xs font-semibold px-2 py-0.5 rounded-full"
                            style={{ backgroundColor: 'var(--bg-subtle)', color: 'var(--text-secondary)' }}
                        >
                            Wave {wave.index + 1}
                        </span>
                        <span className="text-xs" style={{ color: 'var(--text-muted)' }}>
                            {wave.secrets.length} secret{wave.secrets.length === 1 ? '' : 's'} — safe to
                            rotate together
                        </span>
                    </div>
                    <div className="space-y-2">
                        {wave.secrets.map((s) => {
                            const badge = statusBadge(s);
                            return (
                                <div
                                    key={s.secretId}
                                    className="flex items-start justify-between gap-4 rounded-md px-3 py-2"
                                    style={{ backgroundColor: 'var(--bg-subtle)' }}
                                >
                                    <div className="min-w-0">
                                        <div className="flex items-center gap-2 flex-wrap">
                                            <span
                                                className="font-mono text-xs font-medium"
                                                style={{ color: 'var(--text-primary)' }}
                                            >
                                                {s.secretName}
                                            </span>
                                            <span
                                                className="text-xs px-2 py-0.5 rounded-full"
                                                style={{ backgroundColor: badge.bg, color: badge.text }}
                                            >
                                                {badge.label}
                                            </span>
                                            {s.autoRotate && (
                                                <span
                                                    className="inline-flex items-center gap-1 text-xs"
                                                    style={{ color: 'var(--text-muted)' }}
                                                >
                                                    <ArrowPathIcon className="h-3 w-3" /> self-rotating
                                                </span>
                                            )}
                                        </div>
                                        {s.reasons.length > 0 && (
                                            <div
                                                className="text-xs mt-1"
                                                style={{ color: 'var(--text-muted)' }}
                                            >
                                                {s.reasons.join(' · ')}
                                            </div>
                                        )}
                                    </div>
                                    <div className="text-right shrink-0">
                                        <div
                                            className="text-xs font-medium"
                                            style={{ color: riskTone(s.riskBand) }}
                                        >
                                            {s.riskBand ? `${s.riskBand} risk` : '—'}
                                        </div>
                                        {s.riskScore > 0 && (
                                            <div
                                                className="text-xs tabular-nums"
                                                style={{ color: 'var(--text-muted)' }}
                                            >
                                                score {s.riskScore}
                                            </div>
                                        )}
                                    </div>
                                </div>
                            );
                        })}
                    </div>
                </div>
            ))}
        </div>
    ) : null;

    return (
        <div>
            <div className="mb-4">
                <h2 className="text-sm font-semibold" style={{ color: 'var(--text-primary)' }}>
                    Rotation Plan
                </h2>
                <p className="text-xs mt-0.5" style={{ color: 'var(--text-muted)' }}>
                    The project's overdue and due-soon secrets, ordered into dependency-safe waves. Rotate a wave at a
                    time, top to bottom; within a wave, most urgent first.
                </p>
            </div>

            {data && !isLoading && !isError && (
                <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 mb-5">
                    <SummaryStat label="To rotate" value={data.totalSecrets} />
                    <SummaryStat
                        label="Overdue"
                        value={data.overdueCount}
                        tone={data.overdueCount > 0 ? 'var(--error)' : undefined}
                    />
                    <SummaryStat
                        label="Due soon"
                        value={data.dueSoonCount}
                        tone={data.dueSoonCount > 0 ? 'var(--warning)' : undefined}
                    />
                    <SummaryStat label="Waves" value={waves.length} />
                </div>
            )}

            <div
                className="rounded-lg border"
                style={{ borderColor: 'var(--border)', backgroundColor: 'var(--bg-surface)' }}
            >
                {bodyContent}
                {errorContent}
                {emptyContent}
                {wavesContent}
            </div>
        </div>
    );
};
