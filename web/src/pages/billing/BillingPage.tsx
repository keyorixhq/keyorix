import React, { useMemo, useState } from 'react';
import { BanknotesIcon, LockClosedIcon } from '@heroicons/react/24/outline';
import { useBillingReport } from '../../features/billing';
import type { BillingProjectStat } from '../../services/billing';

// ── date-range presets ──────────────────────────────────────────────────────

type PresetKey = 'this-month' | 'last-month' | 'last-30' | 'last-90' | 'custom';

const PRESETS: { key: PresetKey; label: string }[] = [
    { key: 'this-month', label: 'This month' },
    { key: 'last-month', label: 'Last month' },
    { key: 'last-30', label: 'Last 30 days' },
    { key: 'last-90', label: 'Last 90 days' },
];

const toDateInput = (d: Date): string => d.toISOString().slice(0, 10);

// presetRange returns the [from, to) window for a preset, as Date objects at
// UTC midnight — "to" is exclusive (matches the server's half-open interval).
function presetRange(key: Exclude<PresetKey, 'custom'>, now: Date): { from: Date; to: Date } {
    const startOfUTCDay = (d: Date) => new Date(Date.UTC(d.getUTCFullYear(), d.getUTCMonth(), d.getUTCDate()));
    const today = startOfUTCDay(now);
    switch (key) {
        case 'this-month':
            return { from: new Date(Date.UTC(now.getUTCFullYear(), now.getUTCMonth(), 1)), to: today };
        case 'last-month': {
            const from = new Date(Date.UTC(now.getUTCFullYear(), now.getUTCMonth() - 1, 1));
            const to = new Date(Date.UTC(now.getUTCFullYear(), now.getUTCMonth(), 1));
            return { from, to };
        }
        case 'last-30':
            return { from: new Date(today.getTime() - 30 * 86_400_000), to: today };
        case 'last-90':
            return { from: new Date(today.getTime() - 90 * 86_400_000), to: today };
    }
}

// ── small presentational pieces ─────────────────────────────────────────────

const Tile: React.FC<{ label: string; value: React.ReactNode }> = ({ label, value }) => (
    <div
        className="rounded-lg border px-4 py-3"
        style={{ borderColor: 'var(--border)', backgroundColor: 'var(--bg-app)' }}
    >
        <div className="text-xl font-semibold tabular-nums" style={{ color: 'var(--text-primary)' }}>
            {value}
        </div>
        <div className="text-xs mt-0.5" style={{ color: 'var(--text-muted)' }}>
            {label}
        </div>
    </div>
);

const skeletonPlaceholder = (): React.ReactElement => (
    <div
        className="rounded-xl border p-6"
        style={{ borderColor: 'var(--border)', backgroundColor: 'var(--bg-surface)' }}
    >
        <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 mb-6">
            {[1, 2, 3, 4].map((i) => (
                <div key={i} className="h-16 rounded-lg animate-pulse" style={{ backgroundColor: 'var(--bg-muted)' }} />
            ))}
        </div>
        <div className="h-48 rounded-lg animate-pulse" style={{ backgroundColor: 'var(--bg-muted)' }} />
    </div>
);

const LicenseRequiredNotice: React.FC = () => (
    <div
        className="rounded-xl border p-8 text-center"
        style={{ borderColor: 'var(--border)', backgroundColor: 'var(--bg-surface)' }}
    >
        <LockClosedIcon className="h-8 w-8 mx-auto mb-3" style={{ color: 'var(--text-muted)' }} />
        <p className="text-sm font-semibold" style={{ color: 'var(--text-primary)' }}>
            FinOps billing reports are a commercial feature
        </p>
        <p className="text-sm mt-1 max-w-md mx-auto" style={{ color: 'var(--text-muted)' }}>
            Per-project usage and chargeback reporting requires a Keyorix commercial license with the billing feature
            enabled. Contact your Keyorix representative to enable it.
        </p>
    </div>
);

const GenericErrorNotice: React.FC<{ message: string }> = ({ message }) => (
    <div
        className="rounded-xl border p-6 text-sm text-center"
        style={{ borderColor: 'var(--border)', backgroundColor: 'var(--bg-surface)', color: 'var(--text-muted)' }}
    >
        {message}
    </div>
);

// ── project table ────────────────────────────────────────────────────────

const fmt = (n: number) => n.toLocaleString();

const ProjectTable: React.FC<{ projects: BillingProjectStat[] }> = ({ projects }) => {
    if (projects.length === 0) {
        return (
            <div className="py-10 text-center text-sm" style={{ color: 'var(--text-muted)' }}>
                No secrets or activity recorded for any project in this window.
            </div>
        );
    }
    const sorted = [...projects].sort((a, b) => b.secretReads - a.secretReads);
    return (
        <div className="overflow-x-auto">
            <table className="w-full text-sm">
                <thead>
                    <tr className="text-left border-b" style={{ borderColor: 'var(--border)' }}>
                        {['Project', 'Secrets', 'Reads', 'Writes', 'Rotations', 'Unique users', 'Machine reads'].map(
                            (h, i) => (
                                <th
                                    key={h}
                                    className={`py-2 px-3 text-xs font-semibold uppercase tracking-wider ${i > 0 ? 'text-right' : ''}`}
                                    style={{ color: 'var(--text-muted)' }}
                                >
                                    {h}
                                </th>
                            )
                        )}
                    </tr>
                </thead>
                <tbody className="divide-y" style={{ borderColor: 'var(--border)' }}>
                    {sorted.map((p) => (
                        <tr key={p.projectId}>
                            <td
                                className="py-2 px-3 font-medium truncate max-w-[220px]"
                                style={{ color: 'var(--text-primary)' }}
                            >
                                {p.projectName || `(project ${p.projectId})`}
                            </td>
                            <td
                                className="py-2 px-3 text-right tabular-nums"
                                style={{ color: 'var(--text-secondary)' }}
                            >
                                {fmt(p.secretCount)}
                            </td>
                            <td
                                className="py-2 px-3 text-right tabular-nums"
                                style={{ color: 'var(--text-secondary)' }}
                            >
                                {fmt(p.secretReads)}
                            </td>
                            <td
                                className="py-2 px-3 text-right tabular-nums"
                                style={{ color: 'var(--text-secondary)' }}
                            >
                                {fmt(p.secretWrites)}
                            </td>
                            <td
                                className="py-2 px-3 text-right tabular-nums"
                                style={{ color: 'var(--text-secondary)' }}
                            >
                                {fmt(p.secretRotations)}
                            </td>
                            <td
                                className="py-2 px-3 text-right tabular-nums"
                                style={{ color: 'var(--text-secondary)' }}
                            >
                                {fmt(p.uniqueUsers)}
                            </td>
                            <td
                                className="py-2 px-3 text-right tabular-nums"
                                style={{ color: 'var(--text-secondary)' }}
                            >
                                {fmt(p.machineReads)}
                            </td>
                        </tr>
                    ))}
                </tbody>
            </table>
        </div>
    );
};

// ── page ─────────────────────────────────────────────────────────────────

export const BillingPage: React.FC = () => {
    const now = useMemo(() => new Date(), []);
    const [preset, setPreset] = useState<PresetKey>('this-month');
    const [customFrom, setCustomFrom] = useState(() => toDateInput(presetRange('last-30', now).from));
    const [customTo, setCustomTo] = useState(() => toDateInput(presetRange('last-30', now).to));

    const { from, to } = useMemo(() => {
        if (preset === 'custom') {
            return { from: `${customFrom}T00:00:00Z`, to: `${customTo}T00:00:00Z` };
        }
        const range = presetRange(preset, now);
        return { from: range.from.toISOString(), to: range.to.toISOString() };
    }, [preset, customFrom, customTo, now]);

    const { report, isLoading, isError, error, isLicenseRequired } = useBillingReport({ from, to });

    const onCustomDateChange = (which: 'from' | 'to', value: string) => {
        setPreset('custom');
        if (which === 'from') setCustomFrom(value);
        else setCustomTo(value);
    };

    return (
        <div className="max-w-5xl mx-auto px-6 py-8">
            <div className="mb-6 flex items-start justify-between gap-4 flex-wrap">
                <div>
                    <h1
                        className="text-2xl font-bold tracking-tight flex items-center gap-2"
                        style={{ color: 'var(--text-primary)' }}
                    >
                        <BanknotesIcon className="h-6 w-6" style={{ color: 'var(--text-muted)' }} />
                        Billing
                    </h1>
                    <p className="mt-1 text-sm" style={{ color: 'var(--text-muted)' }}>
                        Per-project secret counts and activity for chargeback and usage reporting.
                    </p>
                </div>
            </div>

            {/* Date range controls */}
            <div className="mb-6 flex flex-wrap items-center gap-2">
                <div className="inline-flex rounded-lg border overflow-hidden" style={{ borderColor: 'var(--border)' }}>
                    {PRESETS.map((p) => (
                        <button
                            key={p.key}
                            type="button"
                            onClick={() => setPreset(p.key)}
                            className="px-3 py-1.5 text-sm font-medium transition-colors"
                            style={{
                                backgroundColor: preset === p.key ? 'var(--accent)' : 'var(--bg-surface)',
                                color: preset === p.key ? 'var(--accent-contrast, #fff)' : 'var(--text-secondary)',
                            }}
                        >
                            {p.label}
                        </button>
                    ))}
                </div>
                <div className="flex items-center gap-2 text-sm" style={{ color: 'var(--text-muted)' }}>
                    <input
                        type="date"
                        value={customFrom}
                        onChange={(e) => onCustomDateChange('from', e.target.value)}
                        aria-label="From date"
                        className="rounded-lg px-2.5 py-1.5 text-sm outline-hidden"
                        style={{
                            backgroundColor: 'var(--bg-app)',
                            border: '1px solid var(--border)',
                            color: 'var(--text-primary)',
                        }}
                    />
                    <span>–</span>
                    <input
                        type="date"
                        value={customTo}
                        onChange={(e) => onCustomDateChange('to', e.target.value)}
                        aria-label="To date"
                        className="rounded-lg px-2.5 py-1.5 text-sm outline-hidden"
                        style={{
                            backgroundColor: 'var(--bg-app)',
                            border: '1px solid var(--border)',
                            color: 'var(--text-primary)',
                        }}
                    />
                </div>
            </div>

            {isLoading && skeletonPlaceholder()}

            {!isLoading && isError && isLicenseRequired && <LicenseRequiredNotice />}
            {!isLoading && isError && !isLicenseRequired && (
                <GenericErrorNotice
                    message={
                        (error as any)?.response?.status === 403
                            ? 'Billing reports are available to administrators (system.read).'
                            : 'Could not load the billing report. Try again shortly.'
                    }
                />
            )}

            {!isLoading && !isError && report && (
                <div
                    className="rounded-xl border overflow-hidden"
                    style={{ borderColor: 'var(--border)', backgroundColor: 'var(--bg-surface)' }}
                >
                    <div className="px-6 py-4 border-b" style={{ borderColor: 'var(--border)' }}>
                        <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
                            <Tile label="Projects" value={fmt(report.totals.projects)} />
                            <Tile label="Secrets" value={fmt(report.totals.secretCount)} />
                            <Tile label="Reads" value={fmt(report.totals.secretReads)} />
                            <Tile label="Writes" value={fmt(report.totals.secretWrites)} />
                            <Tile label="Rotations" value={fmt(report.totals.secretRotations)} />
                            <Tile label="Unique users" value={fmt(report.totals.uniqueUsers)} />
                            <Tile label="Machine reads" value={fmt(report.totals.machineReads)} />
                        </div>
                    </div>
                    <div className="px-2 py-2">
                        <ProjectTable projects={report.projects} />
                    </div>
                </div>
            )}
        </div>
    );
};
