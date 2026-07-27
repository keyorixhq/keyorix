import React, { useState } from 'react';
import { ChartBarIcon, FireIcon, MoonIcon } from '@heroicons/react/24/outline';
import { useMostAccessedSecrets, useUnusedSecrets } from '../../features/secrets/useUsageAnalytics';
import { Loading } from '../../components/ui/Loading';

// ── helpers ───────────────────────────────────────────────────────────────────

const fmt = (n: number) => n.toLocaleString();

function relativeFromNow(d: string | null): string {
    if (!d) return 'never';
    const days = Math.floor((Date.now() - new Date(d).getTime()) / 86_400_000);
    if (days <= 0) return 'today';
    if (days === 1) return 'yesterday';
    if (days < 30) return `${days}d ago`;
    const months = Math.floor(days / 30);
    if (months < 12) return `${months}mo ago`;
    return `${Math.floor(days / 365)}y ago`;
}

const WINDOWS = [30, 60, 90] as const;

// ── Section card shell ────────────────────────────────────────────────────────

const SectionCard: React.FC<{ title: string; icon: React.ReactNode; subtitle?: string; children: React.ReactNode }> = ({
    title,
    icon,
    subtitle,
    children,
}) => (
    <div className="bg-surface border border-base rounded-xl shadow-xs">
        <div className="px-6 py-4 border-b border-base">
            <div className="flex items-center gap-2">
                <span style={{ color: 'var(--text-muted)' }}>{icon}</span>
                <h2 className="text-sm font-semibold text-base-primary uppercase tracking-widest">{title}</h2>
            </div>
            {subtitle && <p className="text-xs text-base-muted mt-0.5">{subtitle}</p>}
        </div>
        <div className="px-6 py-4">{children}</div>
    </div>
);

const EmptyState: React.FC<{ message: string }> = ({ message }) => (
    <div className="py-8 text-center text-sm" style={{ color: 'var(--text-muted)' }}>
        {message}
    </div>
);

// ── Main page ─────────────────────────────────────────────────────────────────

export function UsageAnalyticsPage() {
    const [days, setDays] = useState<number>(30);

    const { secrets: mostAccessed, isLoading: maLoading } = useMostAccessedSecrets({ days, limit: 10 });
    const { secrets: unused, isLoading: unusedLoading } = useUnusedSecrets({ days });

    const maxReads = mostAccessed.reduce((m, s) => Math.max(m, s.read_count), 0);

    const mostAccessedContent = mostAccessed.length === 0 ? (
        <EmptyState message="No secret reads recorded in this window." />
    ) : (
        <div className="space-y-3">
            {mostAccessed.map((s, i) => (
                <div key={s.secret_id} className="space-y-1">
                    <div className="flex items-center justify-between text-sm">
                        <span className="flex items-center gap-2 min-w-0">
                            <span
                                className="tabular-nums text-xs w-5 shrink-0"
                                style={{ color: 'var(--text-muted)' }}
                            >
                                {i + 1}.
                            </span>
                            <span
                                className="truncate font-medium"
                                style={{ color: 'var(--text-primary)' }}
                            >
                                {s.secret_name}
                            </span>
                        </span>
                        <span
                            className="tabular-nums shrink-0 ml-3"
                            style={{ color: 'var(--text-secondary)' }}
                        >
                            {fmt(s.read_count)} {s.read_count === 1 ? 'read' : 'reads'}
                        </span>
                    </div>
                    <div
                        className="h-1.5 rounded-full overflow-hidden"
                        style={{ backgroundColor: 'var(--bg-subtle)' }}
                    >
                        <div
                            className="h-full rounded-full transition-all duration-700"
                            style={{
                                width:
                                    maxReads > 0
                                        ? `${Math.round((s.read_count / maxReads) * 100)}%`
                                        : '0%',
                                backgroundColor: '#f59e0b',
                            }}
                        />
                    </div>
                </div>
            ))}
        </div>
    );

    const unusedContent = unused.length === 0 ? (
        <EmptyState message="Every secret has been read recently — nothing stale." />
    ) : (
        <>
            <div className="mb-3 text-xs" style={{ color: 'var(--text-muted)' }}>
                {fmt(unused.length)} secret{unused.length !== 1 ? 's' : ''} candidate
                {unused.length !== 1 ? 's' : ''} for review or retirement
            </div>
            <div className="space-y-1.5 max-h-96 overflow-y-auto">
                {unused.map((s) => (
                    <div
                        key={s.secret_id}
                        className="flex items-center justify-between py-2 px-3 rounded-lg border border-base"
                    >
                        <span
                            className="truncate text-sm font-medium"
                            style={{ color: 'var(--text-primary)' }}
                        >
                            {s.secret_name}
                        </span>
                        <span
                            className="text-xs shrink-0 ml-3 px-2 py-0.5 rounded-full"
                            style={{
                                color: s.last_read ? 'var(--text-muted)' : '#ef4444',
                                backgroundColor: 'var(--bg-subtle)',
                            }}
                        >
                            {s.last_read
                                ? `last read ${relativeFromNow(s.last_read)}`
                                : 'never read'}
                        </span>
                    </div>
                ))}
            </div>
        </>
    );

    return (
        <div className="min-h-screen bg-app">
            <div className="max-w-7xl mx-auto px-6 py-8 space-y-8">
                {/* Header */}
                <div className="flex flex-col sm:flex-row sm:items-end sm:justify-between gap-4">
                    <div>
                        <h1 className="text-2xl font-bold text-base-primary tracking-tight">Usage Analytics</h1>
                        <p className="mt-1 text-sm text-base-muted">
                            Which secrets are hot, and which are dead weight — over the last {days} days
                        </p>
                    </div>
                    {/* Window toggle */}
                    <div className="inline-flex rounded-lg border border-base overflow-hidden self-start">
                        {WINDOWS.map((w) => (
                            <button
                                key={w}
                                type="button"
                                onClick={() => setDays(w)}
                                className="px-3 py-1.5 text-sm font-medium transition-colors"
                                style={{
                                    backgroundColor: days === w ? 'var(--accent)' : 'var(--bg-surface)',
                                    color: days === w ? 'var(--accent-contrast, #fff)' : 'var(--text-secondary)',
                                }}
                            >
                                {w}d
                            </button>
                        ))}
                    </div>
                </div>

                <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
                    {/* Most accessed */}
                    <SectionCard
                        title="Most Accessed"
                        icon={<FireIcon className="h-4 w-4" />}
                        subtitle={`Top secrets by read count in the last ${days} days`}
                    >
                        {maLoading ? <Loading /> : mostAccessedContent}
                    </SectionCard>

                    {/* Unused */}
                    <SectionCard
                        title="Unused Secrets"
                        icon={<MoonIcon className="h-4 w-4" />}
                        subtitle={`Not read in the last ${days} days (or never read)`}
                    >
                        {unusedLoading ? <Loading /> : unusedContent}
                    </SectionCard>
                </div>

                <div className="flex items-center gap-2 text-xs" style={{ color: 'var(--text-muted)' }}>
                    <ChartBarIcon className="h-4 w-4" />
                    Based on recorded secret reads. Rotations and edits are tracked separately and do not count as
                    reads.
                </div>
            </div>
        </div>
    );
}
