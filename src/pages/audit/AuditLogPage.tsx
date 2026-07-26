import React, { useState } from 'react';
import { useSearchParams } from 'react-router-dom';
import { Loading } from '../../components/ui/Loading';
import { useUIStore } from '../../store/uiStore';
import { Alert } from '../../components/ui/Alert';
import { useAuditLog, AuditLogEntry } from '../../features/audit';
import { useAnomalyAlerts, useAcknowledgeAnomaly } from '../../features/dashboard';
import { AnomalyAlert } from '../../types';
import { humanizeAlertType } from '../../utils/anomaly';

// ─── Audit log helpers ───────────────────────────────────────────────────────

const EVENT_STYLES: Record<
    string,
    { label: string; darkBg: string; darkColor: string; lightBg: string; lightColor: string }
> = {
    'auth.login': {
        label: 'Login',
        darkBg: 'rgba(148,163,184,0.15)',
        darkColor: '#94a3b8',
        lightBg: '#f1f5f9',
        lightColor: '#475569',
    },
    'auth.logout': {
        label: 'Logout',
        darkBg: 'rgba(148,163,184,0.15)',
        darkColor: '#94a3b8',
        lightBg: '#f1f5f9',
        lightColor: '#475569',
    },
    'secret.read': {
        label: 'Read',
        darkBg: 'rgba(251,191,36,0.15)',
        darkColor: '#fbbf24',
        lightBg: '#fef9c3',
        lightColor: '#854d0e',
    },
    'secret.created': {
        label: 'Created',
        darkBg: 'rgba(16,185,129,0.15)',
        darkColor: '#34d399',
        lightBg: '#dcfce7',
        lightColor: '#166534',
    },
    'secret.updated': {
        label: 'Updated',
        darkBg: 'rgba(59,130,246,0.15)',
        darkColor: '#60a5fa',
        lightBg: '#dbeafe',
        lightColor: '#1e40af',
    },
    'secret.deleted': {
        label: 'Deleted',
        darkBg: 'rgba(239,68,68,0.15)',
        darkColor: '#f87171',
        lightBg: '#fee2e2',
        lightColor: '#991b1b',
    },
    'secret.rotated': {
        label: 'Rotated',
        darkBg: 'rgba(168,85,247,0.15)',
        darkColor: '#c084fc',
        lightBg: '#f3e8ff',
        lightColor: '#6b21a8',
    },
    'secret.shared': {
        label: 'Shared',
        darkBg: 'rgba(99,102,241,0.15)',
        darkColor: '#818cf8',
        lightBg: '#e0e7ff',
        lightColor: '#3730a3',
    },
    'share.revoked': {
        label: 'Unshared',
        darkBg: 'rgba(251,146,60,0.15)',
        darkColor: '#fb923c',
        lightBg: '#ffedd5',
        lightColor: '#9a3412',
    },
};

function eventBadge(eventType: string, isDark: boolean) {
    const e = EVENT_STYLES[eventType];
    const label = e?.label ?? eventType;
    const bg = e ? (isDark ? e.darkBg : e.lightBg) : isDark ? 'rgba(148,163,184,0.15)' : '#f1f5f9';
    const color = e ? (isDark ? e.darkColor : e.lightColor) : isDark ? '#94a3b8' : '#475569';
    return (
        <span
            className="inline-flex items-center px-2 py-0.5 rounded-sm text-xs font-medium"
            style={{ backgroundColor: bg, color }}
        >
            {label}
        </span>
    );
}

function fmtTime(ts: string): string {
    const d = new Date(ts);
    if (isNaN(d.getTime())) return ts;
    return d.toLocaleString('en', {
        month: 'short',
        day: 'numeric',
        hour: '2-digit',
        minute: '2-digit',
        second: '2-digit',
    });
}

// ─── Anomaly table helpers ───────────────────────────────────────────────────

type SortField = 'alert_type' | 'secret_name' | 'accessed_by' | 'severity' | 'detected_at';
type SortDir = 'asc' | 'desc';

const SEVERITY_ORDER: Record<string, number> = { critical: 4, high: 3, medium: 2, low: 1 };

const SEV: Record<string, { dark: { bg: string; color: string }; light: { bg: string; color: string } }> = {
    critical: { dark: { bg: 'rgba(239,68,68,0.15)', color: '#f87171' }, light: { bg: '#fee2e2', color: '#991b1b' } },
    high: { dark: { bg: 'rgba(249,115,22,0.15)', color: '#fb923c' }, light: { bg: '#ffedd5', color: '#9a3412' } },
    medium: { dark: { bg: 'rgba(245,158,11,0.15)', color: '#fbbf24' }, light: { bg: '#fef9c3', color: '#92400e' } },
    low: { dark: { bg: 'rgba(148,163,184,0.15)', color: '#94a3b8' }, light: { bg: '#f1f5f9', color: '#475569' } },
};

function sevStyle(severity: string, isDark: boolean) {
    return isDark ? (SEV[severity] ?? SEV['low']!).dark : (SEV[severity] ?? SEV['low']!).light;
}

// ─── AnomalyTable ────────────────────────────────────────────────────────────

interface AnomalyTableProps {
    anomalies: AnomalyAlert[];
    isLoading: boolean;
    isDark: boolean;
    onDismiss: (id: number) => void;
}

const AnomalyTable: React.FC<AnomalyTableProps> = ({ anomalies, isLoading, isDark, onDismiss }) => {
    const [expandedId, setExpandedId] = useState<number | null>(null);
    const [sortField, setSortField] = useState<SortField>('detected_at');
    const [sortDir, setSortDir] = useState<SortDir>('desc');
    const [filterSev, setFilterSev] = useState('all');
    const [filterStatus, setFilterStatus] = useState('open');
    const [filterType, setFilterType] = useState('all');

    // Alert types present in the data, for the type filter.
    const alertTypes = Array.from(new Set(anomalies.map((a) => a.AlertType))).sort();

    const toggleSort = (field: SortField) => {
        if (sortField === field) setSortDir((d) => (d === 'asc' ? 'desc' : 'asc'));
        else {
            setSortField(field);
            setSortDir('desc');
        }
    };

    const sorted = [...anomalies]
        .filter((a) => filterSev === 'all' || a.Severity === filterSev)
        .filter((a) => filterType === 'all' || a.AlertType === filterType)
        .filter((a) => filterStatus === 'all' || (filterStatus === 'open' ? !a.Acknowledged : a.Acknowledged))
        .sort((a, b) => {
            let cmp: number;
            if (sortField === 'severity') cmp = (SEVERITY_ORDER[a.Severity] ?? 0) - (SEVERITY_ORDER[b.Severity] ?? 0);
            else if (sortField === 'alert_type') cmp = a.AlertType.localeCompare(b.AlertType);
            else if (sortField === 'secret_name') cmp = a.SecretName.localeCompare(b.SecretName);
            else if (sortField === 'accessed_by') cmp = a.AccessedBy.localeCompare(b.AccessedBy);
            else cmp = new Date(a.DetectedAt).getTime() - new Date(b.DetectedAt).getTime();
            return sortDir === 'asc' ? cmp : -cmp;
        });

    const ColBtn: React.FC<{ field: SortField; label: string }> = ({ field, label }) => {
        const active = sortField === field;
        return (
            <button
                onClick={() => toggleSort(field)}
                className={`flex items-center gap-1 uppercase tracking-wider text-xs font-semibold transition-colors select-none
                    ${active ? 'text-base-primary' : 'text-base-muted hover:text-base-secondary'}`}
            >
                {label}
                <span className="text-[10px] opacity-60">{active ? (sortDir === 'asc' ? '▲' : '▼') : '⇅'}</span>
            </button>
        );
    };

    if (isLoading)
        return (
            <div className="bg-surface border border-base rounded-xl shadow-xs p-12 flex justify-center">
                <Loading />
            </div>
        );

    if (!anomalies.length)
        return (
            <div className="bg-surface border border-base rounded-xl shadow-xs p-12 text-center">
                <div className="w-10 h-10 rounded-full bg-emerald-100 flex items-center justify-center mx-auto mb-3">
                    <span className="text-emerald-600 text-lg">✓</span>
                </div>
                <p className="text-sm font-medium text-base-primary">No anomalies detected</p>
                <p className="text-xs text-base-muted mt-1">All access patterns look normal.</p>
            </div>
        );

    return (
        <div className="bg-surface border border-base rounded-xl shadow-xs overflow-hidden">
            {/* ── Filters bar ─────────────────────────────────────────── */}
            <div className="px-5 py-3 border-b border-base flex items-center gap-3 flex-wrap">
                <span className="text-xs font-semibold text-base-muted uppercase tracking-wide">Filter:</span>

                {/* Severity pills */}
                <div className="flex gap-1 flex-wrap">
                    {(['all', 'critical', 'high', 'medium', 'low'] as const).map((s) => {
                        const active = filterSev === s;
                        const style = s !== 'all' ? sevStyle(s, isDark) : null;
                        return (
                            <button
                                key={s}
                                onClick={() => setFilterSev(s)}
                                className={`px-2.5 py-1 rounded text-xs font-medium border transition-all duration-100 capitalize
                                    ${
                                        active
                                            ? style
                                                ? ''
                                                : 'bg-surface border-base text-base-primary shadow-xs'
                                            : 'border-transparent text-base-muted hover:text-base-secondary'
                                    }`}
                                style={
                                    active && style
                                        ? {
                                              backgroundColor: style.bg,
                                              color: style.color,
                                              borderColor: style.color + '50',
                                          }
                                        : {}
                                }
                            >
                                {s === 'all' ? 'All' : s}
                            </button>
                        );
                    })}
                </div>

                <div className="w-px h-4 bg-base" />

                {/* Status pills */}
                <div className="flex gap-1">
                    {[
                        { k: 'open', l: 'Open' },
                        { k: 'ack', l: 'Acknowledged' },
                        { k: 'all', l: 'All' },
                    ].map(({ k, l }) => (
                        <button
                            key={k}
                            onClick={() => setFilterStatus(k)}
                            className={`px-2.5 py-1 rounded text-xs font-medium border transition-all duration-100
                                ${
                                    filterStatus === k
                                        ? 'bg-surface border-base text-base-primary shadow-xs'
                                        : 'border-transparent text-base-muted hover:text-base-secondary'
                                }`}
                        >
                            {l}
                        </button>
                    ))}
                </div>

                {alertTypes.length > 1 && (
                    <>
                        <div className="w-px h-4 bg-base" />
                        {/* Alert-type filter */}
                        <select
                            value={filterType}
                            onChange={(e) => setFilterType(e.target.value)}
                            className="px-2 py-1 rounded text-xs font-medium border border-base bg-surface text-base-secondary"
                            aria-label="Filter by alert type"
                        >
                            <option value="all">All types</option>
                            {alertTypes.map((t) => (
                                <option key={t} value={t}>
                                    {humanizeAlertType(t)}
                                </option>
                            ))}
                        </select>
                    </>
                )}

                <span className="ml-auto text-xs text-base-muted tabular-nums">
                    {sorted.length} result{sorted.length !== 1 ? 's' : ''}
                </span>
            </div>

            {/* ── Table ───────────────────────────────────────────────── */}
            {sorted.length === 0 ? (
                <div className="p-10 text-center">
                    <p className="text-sm text-base-muted">No alerts match the current filters.</p>
                </div>
            ) : (
                <div className="overflow-x-auto">
                    <table className="min-w-full">
                        <thead>
                            <tr className="bg-subtle border-b border-base">
                                <th className="pl-4 pr-2 py-3 w-6" />
                                <th className="px-5 py-3 text-left">
                                    <ColBtn field="alert_type" label="Alert Type" />
                                </th>
                                <th className="px-5 py-3 text-left">
                                    <ColBtn field="secret_name" label="Secret" />
                                </th>
                                <th className="px-5 py-3 text-left">
                                    <ColBtn field="accessed_by" label="Actor" />
                                </th>
                                <th className="px-5 py-3 text-left text-xs font-semibold text-base-muted uppercase tracking-wider">
                                    IP Address
                                </th>
                                <th className="px-5 py-3 text-left">
                                    <ColBtn field="severity" label="Severity" />
                                </th>
                                <th className="px-5 py-3 text-left">
                                    <ColBtn field="detected_at" label="Detected" />
                                </th>
                                <th className="px-5 py-3 w-20" />
                            </tr>
                        </thead>
                        <tbody>
                            {sorted.map((a: AnomalyAlert) => {
                                const isExpanded = expandedId === a.ID;
                                const sty = sevStyle(a.Severity, isDark);
                                const isHigh = a.Severity === 'high' || a.Severity === 'critical';
                                return (
                                    <React.Fragment key={a.ID}>
                                        <tr
                                            onClick={() => setExpandedId((p) => (p === a.ID ? null : a.ID))}
                                            className={`border-b border-base cursor-pointer transition-colors duration-75 hover:bg-subtle
                                                ${a.Acknowledged ? 'opacity-50' : ''}`}
                                        >
                                            <td className="pl-4 pr-2 py-3 text-base-muted text-xs select-none">
                                                {isExpanded ? '▾' : '▸'}
                                            </td>
                                            {/* Alert type badge — same colour as severity */}
                                            <td className="px-5 py-3 whitespace-nowrap">
                                                <span
                                                    className="inline-flex items-center px-2 py-0.5 rounded-sm text-xs font-medium"
                                                    style={{ backgroundColor: sty.bg, color: sty.color }}
                                                >
                                                    {humanizeAlertType(a.AlertType)}
                                                </span>
                                            </td>
                                            <td className="px-5 py-3 text-sm font-medium text-base-primary">
                                                {a.SecretName}
                                            </td>
                                            <td className="px-5 py-3 text-sm text-base-muted">{a.AccessedBy}</td>
                                            <td className="px-5 py-3 text-sm text-base-muted tabular-nums">
                                                {a.IPAddress}
                                            </td>
                                            {/* Severity badge */}
                                            <td className="px-5 py-3 whitespace-nowrap">
                                                <span
                                                    className="inline-flex items-center px-2 py-0.5 rounded-sm text-xs font-semibold uppercase"
                                                    style={{ backgroundColor: sty.bg, color: sty.color }}
                                                >
                                                    {a.Severity}
                                                </span>
                                            </td>
                                            <td className="px-5 py-3 text-xs text-base-muted tabular-nums whitespace-nowrap">
                                                {a.DetectedAt ? fmtTime(a.DetectedAt) : '—'}
                                            </td>
                                            <td className="px-5 py-3 text-right">
                                                {!a.Acknowledged && (
                                                    <button
                                                        onClick={(e) => {
                                                            e.stopPropagation();
                                                            onDismiss(a.ID);
                                                        }}
                                                        className="text-xs text-base-muted hover:text-base-secondary transition-colors"
                                                    >
                                                        Dismiss
                                                    </button>
                                                )}
                                            </td>
                                        </tr>

                                        {/* ── Detail row ── */}
                                        {isExpanded && (
                                            <tr className="border-b border-base">
                                                <td
                                                    colSpan={8}
                                                    className="px-8 py-5"
                                                    style={{
                                                        backgroundColor: isDark
                                                            ? isHigh
                                                                ? 'rgba(239,68,68,0.05)'
                                                                : 'rgba(245,158,11,0.05)'
                                                            : isHigh
                                                              ? 'rgba(254,242,242,0.8)'
                                                              : 'rgba(255,251,235,0.8)',
                                                    }}
                                                >
                                                    <div className="grid grid-cols-1 sm:grid-cols-3 gap-4 mb-4">
                                                        <div>
                                                            <p className="text-xs font-semibold text-base-muted uppercase tracking-wide mb-1">
                                                                Detected At
                                                            </p>
                                                            <p className="text-sm text-base-primary tabular-nums">
                                                                {a.DetectedAt ? fmtTime(a.DetectedAt) : '—'}
                                                            </p>
                                                        </div>
                                                        <div>
                                                            <p className="text-xs font-semibold text-base-muted uppercase tracking-wide mb-1">
                                                                Status
                                                            </p>
                                                            <p className="text-sm">
                                                                {a.Acknowledged ? (
                                                                    <span className="text-emerald-600 font-medium">
                                                                        Acknowledged
                                                                    </span>
                                                                ) : (
                                                                    <span className="text-amber-500 font-medium">
                                                                        Open
                                                                    </span>
                                                                )}
                                                            </p>
                                                        </div>
                                                        <div>
                                                            <p className="text-xs font-semibold text-base-muted uppercase tracking-wide mb-1">
                                                                Alert ID
                                                            </p>
                                                            <p className="text-sm text-base-muted tabular-nums">
                                                                #{a.ID}
                                                            </p>
                                                        </div>
                                                    </div>
                                                    {a.Description && (
                                                        <div>
                                                            <p className="text-xs font-semibold text-base-muted uppercase tracking-wide mb-1">
                                                                Description
                                                            </p>
                                                            <p className="text-sm text-base-primary leading-relaxed">
                                                                {a.Description}
                                                            </p>
                                                        </div>
                                                    )}
                                                </td>
                                            </tr>
                                        )}
                                    </React.Fragment>
                                );
                            })}
                        </tbody>
                    </table>
                </div>
            )}
        </div>
    );
};

// ─── Page ────────────────────────────────────────────────────────────────────

export const AuditLogPage: React.FC = () => {
    const [searchParams] = useSearchParams();
    const initialTab = searchParams.get('tab') === 'anomalies' ? 'anomalies' : 'audit';
    const [activeTab, setActiveTab] = useState<'audit' | 'anomalies'>(initialTab);
    const urlFilter = searchParams.get('filter'); // 'failed' | 'reads' | null

    const { data, isLoading, error } = useAuditLog({ pageSize: 200 });
    const { data: anomalyData, isLoading: anomalyLoading } = useAnomalyAlerts(false);
    const acknowledgeAnomaly = useAcknowledgeAnomaly();
    const { theme } = useUIStore();
    const isDark =
        theme === 'dark' || (theme === 'system' && window.matchMedia('(prefers-color-scheme: dark)').matches);

    const anomalies: AnomalyAlert[] = anomalyData?.data?.alerts ?? [];
    const openCount = anomalies.filter((a) => !a.Acknowledged).length;

    return (
        <div className="min-h-screen bg-app">
            <div className="max-w-7xl mx-auto px-6 py-8 space-y-6">
                <div>
                    <h1 className="text-2xl font-bold text-base-primary tracking-tight">Audit Log</h1>
                    <p className="mt-1 text-sm text-base-muted">
                        Complete record of all secret access and system events
                        {data?.total ? ` · ${data.total} events` : ''}
                    </p>
                </div>

                {/* ── Tab toggle ─────────────────────────────────────────── */}
                <div className="flex gap-1 p-1 bg-subtle rounded-lg w-fit border border-base">
                    <button
                        onClick={() => setActiveTab('audit')}
                        className={`px-4 py-1.5 rounded-md text-sm font-medium transition-all duration-100 ${
                            activeTab === 'audit'
                                ? 'bg-surface text-base-primary shadow-xs border border-base'
                                : 'text-base-muted hover:text-base-secondary'
                        }`}
                    >
                        Audit Log
                    </button>
                    <button
                        onClick={() => setActiveTab('anomalies')}
                        className={`px-4 py-1.5 rounded-md text-sm font-medium transition-all duration-100 flex items-center gap-2 ${
                            activeTab === 'anomalies'
                                ? 'bg-surface text-base-primary shadow-xs border border-base'
                                : 'text-base-muted hover:text-base-secondary'
                        }`}
                    >
                        Anomaly Alerts
                        {openCount > 0 && (
                            <span className="inline-flex items-center justify-center w-4 h-4 rounded-full bg-red-500 text-white text-xs font-bold leading-none">
                                {openCount}
                            </span>
                        )}
                    </button>
                </div>

                {/* ── Audit Log tab ──────────────────────────────────────── */}
                {activeTab === 'audit' && (
                    <>
                        {!!error && (
                            <Alert
                                type="error"
                                title="Failed to load audit log"
                                message="There was an error loading the audit log. Please try again."
                            />
                        )}
                        <div className="bg-surface border border-base rounded-xl shadow-xs overflow-hidden">
                            {isLoading ? (
                                <div className="p-12 flex justify-center">
                                    <Loading />
                                </div>
                            ) : !data?.data?.length ? (
                                <div className="p-12 text-center">
                                    <p className="text-sm text-base-muted">No audit events recorded yet.</p>
                                </div>
                            ) : (
                                <div className="overflow-x-auto">
                                    {urlFilter && (
                                        <div className="px-5 py-2 border-b border-base flex items-center gap-2 bg-subtle">
                                            <span className="text-xs text-base-muted">Filtered:</span>
                                            <span className="text-xs font-medium text-base-secondary">
                                                {urlFilter === 'failed'
                                                    ? 'Failed auth attempts'
                                                    : urlFilter === 'reads'
                                                      ? 'Secret reads'
                                                      : urlFilter === 'logins'
                                                        ? 'Login events'
                                                        : 'Custom filter'}
                                            </span>
                                            <button
                                                onClick={() =>
                                                    window.history.replaceState(
                                                        {},
                                                        '',
                                                        window.location.pathname + '?tab=audit'
                                                    )
                                                }
                                                className="text-xs text-base-muted hover:text-base-secondary ml-auto"
                                            >
                                                ✕ Clear filter
                                            </button>
                                        </div>
                                    )}
                                    <table className="min-w-full divide-y divide-base">
                                        <thead>
                                            <tr className="bg-subtle">
                                                <th className="px-5 py-3 text-left text-xs font-semibold text-base-muted uppercase tracking-wider w-44">
                                                    Time
                                                </th>
                                                <th className="px-5 py-3 text-left text-xs font-semibold text-base-muted uppercase tracking-wider w-32">
                                                    Event
                                                </th>
                                                <th className="px-5 py-3 text-left text-xs font-semibold text-base-muted uppercase tracking-wider w-32">
                                                    Actor
                                                </th>
                                                <th className="px-5 py-3 text-left text-xs font-semibold text-base-muted uppercase tracking-wider">
                                                    Description
                                                </th>
                                            </tr>
                                        </thead>
                                        <tbody className="divide-y divide-base">
                                            {(data.data as AuditLogEntry[])
                                                .filter((entry: AuditLogEntry) => {
                                                    if (urlFilter === 'failed')
                                                        return entry.event_type === 'auth.login_failed';
                                                    if (urlFilter === 'reads')
                                                        return entry.event_type === 'secret.read';
                                                    if (urlFilter === 'logins')
                                                        return entry.event_type === 'auth.login';
                                                    return true;
                                                })
                                                .map((entry: AuditLogEntry) => (
                                                    <tr
                                                        key={entry.id}
                                                        className="hover:bg-subtle transition-colors duration-75"
                                                    >
                                                        <td className="px-5 py-3 whitespace-nowrap text-xs text-base-muted tabular-nums">
                                                            {fmtTime(entry.timestamp)}
                                                        </td>
                                                        <td className="px-5 py-3 whitespace-nowrap">
                                                            {eventBadge(entry.event_type, isDark)}
                                                        </td>
                                                        <td className="px-5 py-3 whitespace-nowrap text-sm font-medium text-base-primary">
                                                            {entry.actor}
                                                        </td>
                                                        <td className="px-5 py-3 text-sm text-base-muted">
                                                            {entry.description}
                                                        </td>
                                                    </tr>
                                                ))}
                                        </tbody>
                                    </table>
                                </div>
                            )}
                        </div>
                    </>
                )}

                {/* ── Anomaly Alerts tab ─────────────────────────────────── */}
                {activeTab === 'anomalies' && (
                    <AnomalyTable
                        anomalies={anomalies}
                        isLoading={anomalyLoading}
                        isDark={isDark}
                        onDismiss={(id) => acknowledgeAnomaly.mutate(id)}
                    />
                )}
            </div>
        </div>
    );
};
