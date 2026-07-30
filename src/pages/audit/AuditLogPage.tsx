import React, { useState, useCallback } from 'react';
import { useSearchParams } from 'react-router-dom';
import { Loading } from '../../components/ui/Loading';
import { useUIStore } from '../../store/uiStore';
import { Alert } from '../../components/ui/Alert';
import { useAuditLog, AuditLogEntry } from '../../features/audit';
import { useAnomalyAlerts, useAcknowledgeAnomaly } from '../../features/dashboard';
import { AnomalyAlert } from '../../types';
import { humanizeAlertType } from '../../utils/anomaly';

// ─── Event badge ─────────────────────────────────────────────────────────────

const EVENT_STYLES: Record<
    string,
    { label: string; darkBg: string; darkColor: string; lightBg: string; lightColor: string }
> = {
    // Auth
    'auth.login': {
        label: 'Login',
        darkBg: 'rgba(148,163,184,0.15)', darkColor: '#94a3b8',
        lightBg: '#f1f5f9', lightColor: '#475569',
    },
    'auth.logout': {
        label: 'Logout',
        darkBg: 'rgba(148,163,184,0.15)', darkColor: '#94a3b8',
        lightBg: '#f1f5f9', lightColor: '#475569',
    },
    'auth.login_failed': {
        label: 'Login Failed',
        darkBg: 'rgba(239,68,68,0.15)', darkColor: '#f87171',
        lightBg: '#fee2e2', lightColor: '#991b1b',
    },
    // Secrets
    'secret.read': {
        label: 'Read',
        darkBg: 'rgba(251,191,36,0.15)', darkColor: '#fbbf24',
        lightBg: '#fef9c3', lightColor: '#854d0e',
    },
    'secret.created': {
        label: 'Created',
        darkBg: 'rgba(16,185,129,0.15)', darkColor: '#34d399',
        lightBg: '#dcfce7', lightColor: '#166534',
    },
    'secret.updated': {
        label: 'Updated',
        darkBg: 'rgba(59,130,246,0.15)', darkColor: '#60a5fa',
        lightBg: '#dbeafe', lightColor: '#1e40af',
    },
    'secret.deleted': {
        label: 'Deleted',
        darkBg: 'rgba(239,68,68,0.15)', darkColor: '#f87171',
        lightBg: '#fee2e2', lightColor: '#991b1b',
    },
    'secret.rotated': {
        label: 'Rotated',
        darkBg: 'rgba(168,85,247,0.15)', darkColor: '#c084fc',
        lightBg: '#f3e8ff', lightColor: '#6b21a8',
    },
    'secret.shared': {
        label: 'Shared',
        darkBg: 'rgba(99,102,241,0.15)', darkColor: '#818cf8',
        lightBg: '#e0e7ff', lightColor: '#3730a3',
    },
    'share.revoked': {
        label: 'Unshared',
        darkBg: 'rgba(251,146,60,0.15)', darkColor: '#fb923c',
        lightBg: '#ffedd5', lightColor: '#9a3412',
    },
    // RBAC — roles
    'rbac.role.created': {
        label: 'Role Created',
        darkBg: 'rgba(99,102,241,0.15)', darkColor: '#818cf8',
        lightBg: '#e0e7ff', lightColor: '#3730a3',
    },
    'rbac.role.updated': {
        label: 'Role Updated',
        darkBg: 'rgba(99,102,241,0.15)', darkColor: '#818cf8',
        lightBg: '#e0e7ff', lightColor: '#3730a3',
    },
    'rbac.role.deleted': {
        label: 'Role Deleted',
        darkBg: 'rgba(239,68,68,0.15)', darkColor: '#f87171',
        lightBg: '#fee2e2', lightColor: '#991b1b',
    },
    'rbac.role.assigned': {
        label: 'Role Assigned',
        darkBg: 'rgba(16,185,129,0.15)', darkColor: '#34d399',
        lightBg: '#dcfce7', lightColor: '#166534',
    },
    'rbac.role.removed': {
        label: 'Role Removed',
        darkBg: 'rgba(239,68,68,0.15)', darkColor: '#f87171',
        lightBg: '#fee2e2', lightColor: '#991b1b',
    },
    // RBAC — permissions
    'rbac.permission.granted': {
        label: 'Permission Granted',
        darkBg: 'rgba(16,185,129,0.15)', darkColor: '#34d399',
        lightBg: '#dcfce7', lightColor: '#166534',
    },
    'rbac.permission.revoked': {
        label: 'Permission Revoked',
        darkBg: 'rgba(239,68,68,0.15)', darkColor: '#f87171',
        lightBg: '#fee2e2', lightColor: '#991b1b',
    },
    // RBAC — groups
    'rbac.group.created': {
        label: 'Group Created',
        darkBg: 'rgba(168,85,247,0.15)', darkColor: '#c084fc',
        lightBg: '#f3e8ff', lightColor: '#6b21a8',
    },
    'rbac.group.updated': {
        label: 'Group Updated',
        darkBg: 'rgba(168,85,247,0.15)', darkColor: '#c084fc',
        lightBg: '#f3e8ff', lightColor: '#6b21a8',
    },
    'rbac.group.deleted': {
        label: 'Group Deleted',
        darkBg: 'rgba(239,68,68,0.15)', darkColor: '#f87171',
        lightBg: '#fee2e2', lightColor: '#991b1b',
    },
    'rbac.group.member.added': {
        label: 'Added to Group',
        darkBg: 'rgba(16,185,129,0.15)', darkColor: '#34d399',
        lightBg: '#dcfce7', lightColor: '#166534',
    },
    'rbac.group.member.removed': {
        label: 'Removed from Group',
        darkBg: 'rgba(239,68,68,0.15)', darkColor: '#f87171',
        lightBg: '#fee2e2', lightColor: '#991b1b',
    },
};

function eventLabel(eventType: string): string {
    return EVENT_STYLES[eventType]?.label ?? eventType;
}

function eventBadge(eventType: string, isDark: boolean) {
    const e = EVENT_STYLES[eventType];
    const label = e?.label ?? eventType;
    const defaultBg = isDark ? 'rgba(148,163,184,0.15)' : '#f1f5f9';
    const eBgInner = isDark ? e?.darkBg : e?.lightBg;
    const eBg = e ? eBgInner : null;
    const bg = eBg ?? defaultBg;
    const defaultColor = isDark ? '#94a3b8' : '#475569';
    const eColorInner = isDark ? e?.darkColor : e?.lightColor;
    const eColor = e ? eColorInner : null;
    const color = eColor ?? defaultColor;
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
    if (Number.isNaN(d.getTime())) return ts;
    return d.toLocaleString('en', {
        month: 'short',
        day: 'numeric',
        hour: '2-digit',
        minute: '2-digit',
        second: '2-digit',
    });
}

// ─── CSV export ───────────────────────────────────────────────────────────────

function exportCSV(entries: AuditLogEntry[], filename: string) {
    const header = ['Timestamp', 'Event', 'Actor', 'Actor Type', 'Description'];
    const rows = entries.map((e) => [
        new Date(e.timestamp).toISOString(),
        e.event_type,
        e.actor,
        e.actor_type ?? 'user',
        `"${(e.description ?? '').replaceAll('"', '""')}"`,
    ]);
    const csv = [header, ...rows].map((r) => r.join(',')).join('\n');
    const blob = new Blob([csv], { type: 'text/csv;charset=utf-8;' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = filename;
    a.click();
    URL.revokeObjectURL(url);
}

// ─── Filter bar ───────────────────────────────────────────────────────────────

type ActorTypeFilter = 'all' | 'user' | 'machine_identity';

interface FilterBarProps {
    actorFilter: string;
    onActorChange: (v: string) => void;
    eventTypeFilter: string;
    onEventTypeChange: (v: string) => void;
    dateFrom: string;
    onDateFromChange: (v: string) => void;
    dateTo: string;
    onDateToChange: (v: string) => void;
    actorTypeFilter: ActorTypeFilter;
    onActorTypeChange: (v: ActorTypeFilter) => void;
    availableTypes: string[];
    resultCount: number;
    onExport: () => void;
}

const ACTOR_TYPE_OPTIONS = [
    { k: 'all', l: 'All' },
    { k: 'user', l: 'Human' },
    { k: 'machine_identity', l: 'Machine' },
] as const;

const FilterBar: React.FC<FilterBarProps> = ({
    actorFilter, onActorChange,
    eventTypeFilter, onEventTypeChange,
    dateFrom, onDateFromChange,
    dateTo, onDateToChange,
    actorTypeFilter, onActorTypeChange,
    availableTypes, resultCount,
    onExport,
}) => (
    <div className="px-5 py-3 border-b border-base flex items-center gap-3 flex-wrap bg-subtle">
        {/* Actor search */}
        <input
            type="text"
            placeholder="Filter by actor…"
            value={actorFilter}
            onChange={(e) => onActorChange(e.target.value)}
            className="px-3 py-1.5 rounded-md text-xs border border-base bg-surface text-base-primary placeholder:text-base-muted focus:outline-none focus:ring-1 focus:ring-accent w-44"
        />

        {/* Event type */}
        <select
            value={eventTypeFilter}
            onChange={(e) => onEventTypeChange(e.target.value)}
            className="px-2.5 py-1.5 rounded-md text-xs border border-base bg-surface text-base-secondary focus:outline-none focus:ring-1 focus:ring-accent"
            aria-label="Filter by event type"
        >
            <option value="all">All event types</option>
            {availableTypes.map((t) => (
                <option key={t} value={t}>{eventLabel(t)}</option>
            ))}
        </select>

        {/* Actor type (ADR-023: human vs. machine identity) */}
        <div className="flex gap-1">
            {ACTOR_TYPE_OPTIONS.map(({ k, l }) => (
                <button
                    type="button"
                    key={k}
                    onClick={() => onActorTypeChange(k)}
                    className={`px-2.5 py-1 rounded text-xs font-medium border transition-all duration-100 ${
                        actorTypeFilter === k
                            ? 'bg-surface border-base text-base-primary shadow-xs'
                            : 'border-transparent text-base-muted hover:text-base-secondary'
                    }`}
                >
                    {l}
                </button>
            ))}
        </div>

        {/* Date range */}
        <div className="flex items-center gap-1.5">
            <input
                type="date"
                value={dateFrom}
                onChange={(e) => onDateFromChange(e.target.value)}
                className="px-2 py-1.5 rounded-md text-xs border border-base bg-surface text-base-secondary focus:outline-none focus:ring-1 focus:ring-accent"
                aria-label="From date"
            />
            <span className="text-xs text-base-muted">–</span>
            <input
                type="date"
                value={dateTo}
                onChange={(e) => onDateToChange(e.target.value)}
                className="px-2 py-1.5 rounded-md text-xs border border-base bg-surface text-base-secondary focus:outline-none focus:ring-1 focus:ring-accent"
                aria-label="To date"
            />
        </div>

        {/* Result count + export */}
        <div className="ml-auto flex items-center gap-3">
            <span className="text-xs text-base-muted tabular-nums">
                {resultCount} event{resultCount !== 1 ? 's' : ''}
            </span>
            <button
                type="button"
                onClick={onExport}
                className="flex items-center gap-1.5 px-3 py-1.5 rounded-md text-xs font-medium border border-base bg-surface text-base-secondary hover:text-base-primary hover:bg-subtle transition-colors"
                title="Export as CSV"
            >
                <svg className="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2}
                        d="M12 10v6m0 0l-3-3m3 3l3-3M3 17V7a2 2 0 012-2h6l2 2h6a2 2 0 012 2v8a2 2 0 01-2 2H5a2 2 0 01-2-2z" />
                </svg>
                Export CSV
            </button>
        </div>
    </div>
);

// ─── Audit table ─────────────────────────────────────────────────────────────

interface AuditTableProps {
    entries: AuditLogEntry[];
    isDark: boolean;
    isLoading: boolean;
    emptyMessage: string;
}

const AuditTable: React.FC<AuditTableProps> = ({ entries, isDark, isLoading, emptyMessage }) => {
    if (isLoading)
        return (
            <div className="p-12 flex justify-center">
                <Loading />
            </div>
        );

    if (!entries.length)
        return (
            <div className="p-12 text-center">
                <p className="text-sm text-base-muted">{emptyMessage}</p>
            </div>
        );

    return (
        <div className="overflow-x-auto">
            <table className="min-w-full divide-y divide-base">
                <thead>
                    <tr className="bg-subtle">
                        <th className="px-5 py-3 text-left text-xs font-semibold text-base-muted uppercase tracking-wider w-44">
                            Time
                        </th>
                        <th className="px-5 py-3 text-left text-xs font-semibold text-base-muted uppercase tracking-wider w-40">
                            Event
                        </th>
                        <th className="px-5 py-3 text-left text-xs font-semibold text-base-muted uppercase tracking-wider w-40">
                            Actor
                        </th>
                        <th className="px-5 py-3 text-left text-xs font-semibold text-base-muted uppercase tracking-wider">
                            Description
                        </th>
                    </tr>
                </thead>
                <tbody className="divide-y divide-base">
                    {entries.map((entry) => (
                        <tr key={entry.id} className="hover:bg-subtle transition-colors duration-75">
                            <td className="px-5 py-3 whitespace-nowrap text-xs text-base-muted tabular-nums">
                                {fmtTime(entry.timestamp)}
                            </td>
                            <td className="px-5 py-3 whitespace-nowrap">
                                {eventBadge(entry.event_type, isDark)}
                            </td>
                            <td className="px-5 py-3 whitespace-nowrap text-sm font-medium text-base-primary">
                                {entry.actor}
                                {entry.actor_type === 'machine_identity' && (
                                    <span className="ml-1.5 px-1.5 py-0.5 rounded text-[10px] font-semibold bg-blue-100 text-blue-800 dark:bg-blue-900/40 dark:text-blue-300">
                                        machine
                                    </span>
                                )}
                            </td>
                            <td className="px-5 py-3 text-sm text-base-muted">
                                {entry.description}
                            </td>
                        </tr>
                    ))}
                </tbody>
            </table>
        </div>
    );
};

// ─── Pagination ───────────────────────────────────────────────────────────────

interface PaginationProps {
    page: number;
    totalPages: number;
    total: number;
    pageSize: number;
    onChange: (p: number) => void;
}

const Pagination: React.FC<PaginationProps> = ({ page, totalPages, total, pageSize, onChange }) => {
    if (totalPages <= 1) return null;
    const from = (page - 1) * pageSize + 1;
    const to = Math.min(page * pageSize, total);
    return (
        <div className="px-5 py-3 border-t border-base flex items-center justify-between">
            <span className="text-xs text-base-muted tabular-nums">
                {from}–{to} of {total}
            </span>
            <div className="flex items-center gap-2">
                <button
                    type="button"
                    onClick={() => onChange(page - 1)}
                    disabled={page <= 1}
                    className="px-3 py-1.5 rounded-md text-xs border border-base bg-surface text-base-secondary hover:bg-subtle disabled:opacity-40 disabled:cursor-not-allowed transition-colors"
                >
                    ← Prev
                </button>
                <span className="text-xs text-base-muted tabular-nums">
                    {page} / {totalPages}
                </span>
                <button
                    type="button"
                    onClick={() => onChange(page + 1)}
                    disabled={page >= totalPages}
                    className="px-3 py-1.5 rounded-md text-xs border border-base bg-surface text-base-secondary hover:bg-subtle disabled:opacity-40 disabled:cursor-not-allowed transition-colors"
                >
                    Next →
                </button>
            </div>
        </div>
    );
};

// ─── Anomaly table helpers ────────────────────────────────────────────────────

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

// ─── ColBtn ───────────────────────────────────────────────────────────────────

interface ColBtnProps {
    field: SortField;
    label: string;
    sortField: SortField;
    sortDir: SortDir;
    onToggle: (field: SortField) => void;
}

const ColBtn: React.FC<ColBtnProps> = ({ field, label, sortField, sortDir, onToggle }) => {
    const active = sortField === field;
    const dirArrow = sortDir === 'asc' ? '▲' : '▼';
    const sortIndicator = active ? dirArrow : '⇅';
    return (
        <button
            type="button"
            onClick={() => onToggle(field)}
            className={`flex items-center gap-1 uppercase tracking-wider text-xs font-semibold transition-colors select-none
                ${active ? 'text-base-primary' : 'text-base-muted hover:text-base-secondary'}`}
        >
            {label}
            <span className="text-[10px] opacity-60">{sortIndicator}</span>
        </button>
    );
};

// ─── AnomalyTable ─────────────────────────────────────────────────────────────

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

    const alertTypes = Array.from(new Set(anomalies.map((a) => a.AlertType))).sort((a, b) => a.localeCompare(b));

    const toggleSort = (field: SortField) => {
        if (sortField === field) setSortDir((d) => (d === 'asc' ? 'desc' : 'asc'));
        else { setSortField(field); setSortDir('desc'); }
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
            {/* Filters bar */}
            <div className="px-5 py-3 border-b border-base flex items-center gap-3 flex-wrap">
                <span className="text-xs font-semibold text-base-muted uppercase tracking-wide">Filter:</span>

                <div className="flex gap-1 flex-wrap">
                    {(['all', 'critical', 'high', 'medium', 'low'] as const).map((s) => {
                        const active = filterSev === s;
                        const style = s !== 'all' ? sevStyle(s, isDark) : null;
                        const activeClass = style ? '' : 'bg-surface border-base text-base-primary shadow-xs';
                        return (
                            <button
                                type="button"
                                key={s}
                                onClick={() => setFilterSev(s)}
                                className={`px-2.5 py-1 rounded text-xs font-medium border transition-all duration-100 capitalize
                                    ${active
                                        ? activeClass
                                        : 'border-transparent text-base-muted hover:text-base-secondary'
                                    }`}
                                style={active && style ? { backgroundColor: style.bg, color: style.color, borderColor: style.color + '50' } : {}}
                            >
                                {s === 'all' ? 'All' : s}
                            </button>
                        );
                    })}
                </div>

                <div className="w-px h-4 bg-base" />

                <div className="flex gap-1">
                    {[{ k: 'open', l: 'Open' }, { k: 'ack', l: 'Acknowledged' }, { k: 'all', l: 'All' }].map(({ k, l }) => (
                        <button
                            type="button"
                            key={k}
                            onClick={() => setFilterStatus(k)}
                            className={`px-2.5 py-1 rounded text-xs font-medium border transition-all duration-100
                                ${filterStatus === k
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
                        <select
                            value={filterType}
                            onChange={(e) => setFilterType(e.target.value)}
                            className="px-2 py-1 rounded text-xs font-medium border border-base bg-surface text-base-secondary"
                            aria-label="Filter by alert type"
                        >
                            <option value="all">All types</option>
                            {alertTypes.map((t) => (
                                <option key={t} value={t}>{humanizeAlertType(t)}</option>
                            ))}
                        </select>
                    </>
                )}

                <span className="ml-auto text-xs text-base-muted tabular-nums">
                    {sorted.length} result{sorted.length !== 1 ? 's' : ''}
                </span>
            </div>

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
                                <th className="px-5 py-3 text-left"><ColBtn field="alert_type" label="Alert Type" sortField={sortField} sortDir={sortDir} onToggle={toggleSort} /></th>
                                <th className="px-5 py-3 text-left"><ColBtn field="secret_name" label="Secret" sortField={sortField} sortDir={sortDir} onToggle={toggleSort} /></th>
                                <th className="px-5 py-3 text-left"><ColBtn field="accessed_by" label="Actor" sortField={sortField} sortDir={sortDir} onToggle={toggleSort} /></th>
                                <th className="px-5 py-3 text-left text-xs font-semibold text-base-muted uppercase tracking-wider">IP Address</th>
                                <th className="px-5 py-3 text-left"><ColBtn field="severity" label="Severity" sortField={sortField} sortDir={sortDir} onToggle={toggleSort} /></th>
                                <th className="px-5 py-3 text-left"><ColBtn field="detected_at" label="Detected" sortField={sortField} sortDir={sortDir} onToggle={toggleSort} /></th>
                                <th className="px-5 py-3 w-20" />
                            </tr>
                        </thead>
                        <tbody>
                            {sorted.map((a: AnomalyAlert) => {
                                const isExpanded = expandedId === a.ID;
                                const sty = sevStyle(a.Severity, isDark);
                                const isHigh = a.Severity === 'high' || a.Severity === 'critical';
                                const expandedBgDark = isHigh ? 'rgba(239,68,68,0.05)' : 'rgba(245,158,11,0.05)';
                                const expandedBgLight = isHigh ? 'rgba(254,242,242,0.8)' : 'rgba(255,251,235,0.8)';
                                const expandedBg = isDark ? expandedBgDark : expandedBgLight;
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
                                            <td className="px-5 py-3 whitespace-nowrap">
                                                <span
                                                    className="inline-flex items-center px-2 py-0.5 rounded-sm text-xs font-medium"
                                                    style={{ backgroundColor: sty.bg, color: sty.color }}
                                                >
                                                    {humanizeAlertType(a.AlertType)}
                                                </span>
                                            </td>
                                            <td className="px-5 py-3 text-sm font-medium text-base-primary">{a.SecretName}</td>
                                            <td className="px-5 py-3 text-sm text-base-muted">{a.AccessedBy}</td>
                                            <td className="px-5 py-3 text-sm text-base-muted tabular-nums">{a.IPAddress}</td>
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
                                                        type="button"
                                                        onClick={(e) => { e.stopPropagation(); onDismiss(a.ID); }}
                                                        className="text-xs text-base-muted hover:text-base-secondary transition-colors"
                                                    >
                                                        Dismiss
                                                    </button>
                                                )}
                                            </td>
                                        </tr>
                                        {isExpanded && (
                                            <tr className="border-b border-base">
                                                <td
                                                    colSpan={8}
                                                    className="px-8 py-5"
                                                    style={{
                                                        backgroundColor: expandedBg,
                                                    }}
                                                >
                                                    <div className="grid grid-cols-1 sm:grid-cols-3 gap-4 mb-4">
                                                        <div>
                                                            <p className="text-xs font-semibold text-base-muted uppercase tracking-wide mb-1">Detected At</p>
                                                            <p className="text-sm text-base-primary tabular-nums">{a.DetectedAt ? fmtTime(a.DetectedAt) : '—'}</p>
                                                        </div>
                                                        <div>
                                                            <p className="text-xs font-semibold text-base-muted uppercase tracking-wide mb-1">Status</p>
                                                            <p className="text-sm">
                                                                {a.Acknowledged
                                                                    ? <span className="text-emerald-600 font-medium">Acknowledged</span>
                                                                    : <span className="text-amber-500 font-medium">Open</span>}
                                                            </p>
                                                        </div>
                                                        <div>
                                                            <p className="text-xs font-semibold text-base-muted uppercase tracking-wide mb-1">Alert ID</p>
                                                            <p className="text-sm text-base-muted tabular-nums">#{a.ID}</p>
                                                        </div>
                                                    </div>
                                                    {a.Description && (
                                                        <div>
                                                            <p className="text-xs font-semibold text-base-muted uppercase tracking-wide mb-1">Description</p>
                                                            <p className="text-sm text-base-primary leading-relaxed">{a.Description}</p>
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

// ─── Page ─────────────────────────────────────────────────────────────────────

type ActiveTab = 'audit' | 'rbac' | 'anomalies';

function resolveInitialTab(tab: string | null): ActiveTab {
    if (tab === 'anomalies') return 'anomalies';
    if (tab === 'rbac') return 'rbac';
    return 'audit';
}

export const AuditLogPage: React.FC = () => {
    const [searchParams] = useSearchParams();
    const [activeTab, setActiveTab] = useState<ActiveTab>(resolveInitialTab(searchParams.get('tab')));
    const urlFilter = searchParams.get('filter');

    // Shared filter state (used by both audit and rbac tabs)
    const [actorFilter, setActorFilter] = useState('');
    const [eventTypeFilter, setEventTypeFilter] = useState('all');
    const [dateFrom, setDateFrom] = useState('');
    const [dateTo, setDateTo] = useState('');
    const [actorTypeFilter, setActorTypeFilter] = useState<ActorTypeFilter>('all');
    const [page, setPage] = useState(1);

    const { data, isLoading, error } = useAuditLog({ page, pageSize: 100 });
    const { data: anomalyData, isLoading: anomalyLoading } = useAnomalyAlerts(false);
    const acknowledgeAnomaly = useAcknowledgeAnomaly();
    const { theme } = useUIStore();
    const isDark = theme === 'dark' || (theme === 'system' && window.matchMedia('(prefers-color-scheme: dark)').matches);

    const anomalies: AnomalyAlert[] = anomalyData?.data?.alerts ?? [];
    const openCount = anomalies.filter((a) => !a.Acknowledged).length;

    const allEntries: AuditLogEntry[] = data?.data ?? [];

    // Apply tab-level pre-filter first, then user filters
    const applyFilters = useCallback((entries: AuditLogEntry[]) => {
        return entries
            .filter((e) => {
                if (urlFilter === 'failed') return e.event_type === 'auth.login_failed';
                if (urlFilter === 'reads') return e.event_type === 'secret.read';
                if (urlFilter === 'logins') return e.event_type === 'auth.login';
                return true;
            })
            .filter((e) => !actorFilter || e.actor.toLowerCase().includes(actorFilter.toLowerCase()))
            .filter((e) => eventTypeFilter === 'all' || e.event_type === eventTypeFilter)
            .filter((e) => actorTypeFilter === 'all' || e.actor_type === actorTypeFilter)
            .filter((e) => !dateFrom || new Date(e.timestamp) >= new Date(dateFrom))
            .filter((e) => !dateTo || new Date(e.timestamp) <= new Date(dateTo + 'T23:59:59'));
    }, [urlFilter, actorFilter, eventTypeFilter, actorTypeFilter, dateFrom, dateTo]);

    const auditEntries = applyFilters(allEntries);
    const rbacEntries = applyFilters(allEntries.filter((e) => e.event_type.startsWith('rbac.')));

    // Unique event types for the dropdown
    const auditTypes = Array.from(new Set(allEntries.map((e) => e.event_type))).sort((a, b) => a.localeCompare(b));
    const rbacTypes = Array.from(new Set(allEntries
        .filter((e) => e.event_type.startsWith('rbac.'))
        .map((e) => e.event_type))).sort((a, b) => a.localeCompare(b));

    const activeEntries = activeTab === 'rbac' ? rbacEntries : auditEntries;
    const activeTypes = activeTab === 'rbac' ? rbacTypes : auditTypes;

    const handleExport = () => {
        const filename = `keyorix-${activeTab}-log-${new Date().toISOString().slice(0, 10)}.csv`;
        exportCSV(activeEntries, filename);
    };

    const resetPageOnTabChange = (tab: ActiveTab) => {
        setActiveTab(tab);
        setPage(1);
        setActorFilter('');
        setEventTypeFilter('all');
        setActorTypeFilter('all');
        setDateFrom('');
        setDateTo('');
    };

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

                {/* Tab toggle */}
                <div className="flex gap-1 p-1 bg-subtle rounded-lg w-fit border border-base">
                    {(
                        [
                            { id: 'audit' as const, label: 'Audit Log', badge: null as number | null },
                            { id: 'rbac' as const, label: 'RBAC Events', badge: null as number | null },
                            { id: 'anomalies' as const, label: 'Anomaly Alerts', badge: openCount > 0 ? openCount : null },
                        ]
                    ).map(({ id, label, badge }) => (
                        <button
                            type="button"
                            key={id}
                            onClick={() => resetPageOnTabChange(id)}
                            className={`px-4 py-1.5 rounded-md text-sm font-medium transition-all duration-100 flex items-center gap-2 ${
                                activeTab === id
                                    ? 'bg-surface text-base-primary shadow-xs border border-base'
                                    : 'text-base-muted hover:text-base-secondary'
                            }`}
                        >
                            {label}
                            {badge != null && badge > 0 && (
                                <span className="inline-flex items-center justify-center w-4 h-4 rounded-full bg-red-500 text-white text-xs font-bold leading-none">
                                    {badge}
                                </span>
                            )}
                        </button>
                    ))}
                </div>

                {/* ── Audit Log tab ── */}
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
                            {urlFilter && (
                                <div className="px-5 py-2 border-b border-base flex items-center gap-2 bg-subtle">
                                    <span className="text-xs text-base-muted">Filtered:</span>
                                    <span className="text-xs font-medium text-base-secondary">
                                        {(() => {
                                            if (urlFilter === 'failed') return 'Failed auth attempts';
                                            if (urlFilter === 'reads') return 'Secret reads';
                                            if (urlFilter === 'logins') return 'Login events';
                                            return 'Custom filter';
                                        })()}
                                    </span>
                                    <button
                                        type="button"
                                        onClick={() => window.history.replaceState({}, '', window.location.pathname + '?tab=audit')}
                                        className="text-xs text-base-muted hover:text-base-secondary ml-auto"
                                    >
                                        ✕ Clear filter
                                    </button>
                                </div>
                            )}
                            <FilterBar
                                actorFilter={actorFilter}
                                onActorChange={setActorFilter}
                                eventTypeFilter={eventTypeFilter}
                                onEventTypeChange={setEventTypeFilter}
                                dateFrom={dateFrom}
                                onDateFromChange={setDateFrom}
                                dateTo={dateTo}
                                onDateToChange={setDateTo}
                                actorTypeFilter={actorTypeFilter}
                                onActorTypeChange={setActorTypeFilter}
                                availableTypes={activeTypes}
                                resultCount={auditEntries.length}
                                onExport={handleExport}
                            />
                            <AuditTable
                                entries={auditEntries}
                                isDark={isDark}
                                isLoading={isLoading}
                                emptyMessage="No audit events match the current filters."
                            />
                            <Pagination
                                page={data?.page ?? 1}
                                totalPages={data?.totalPages ?? 1}
                                total={data?.total ?? 0}
                                pageSize={data?.pageSize ?? 100}
                                onChange={setPage}
                            />
                        </div>
                    </>
                )}

                {/* ── RBAC Events tab ── */}
                {activeTab === 'rbac' && (
                    <div className="space-y-4">
                        <div className="flex items-start gap-3 p-4 rounded-lg bg-indigo-50 border border-indigo-100 dark:bg-indigo-950/20 dark:border-indigo-900/30">
                            <svg className="w-4 h-4 text-indigo-500 mt-0.5 shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2}
                                    d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
                            </svg>
                            <div>
                                <p className="text-xs font-semibold text-indigo-700 dark:text-indigo-300">Access governance events</p>
                                <p className="text-xs text-indigo-600/70 dark:text-indigo-400/70 mt-0.5">
                                    Shows only role assignments, permission changes, and group membership events.
                                    Required for NIS2 Article 21 access control audit trails.
                                </p>
                            </div>
                        </div>

                        {!!error && (
                            <Alert
                                type="error"
                                title="Failed to load audit log"
                                message="There was an error loading the audit log. Please try again."
                            />
                        )}

                        <div className="bg-surface border border-base rounded-xl shadow-xs overflow-hidden">
                            <FilterBar
                                actorFilter={actorFilter}
                                onActorChange={setActorFilter}
                                eventTypeFilter={eventTypeFilter}
                                onEventTypeChange={setEventTypeFilter}
                                dateFrom={dateFrom}
                                onDateFromChange={setDateFrom}
                                dateTo={dateTo}
                                onDateToChange={setDateTo}
                                actorTypeFilter={actorTypeFilter}
                                onActorTypeChange={setActorTypeFilter}
                                availableTypes={activeTypes}
                                resultCount={rbacEntries.length}
                                onExport={handleExport}
                            />
                            <AuditTable
                                entries={rbacEntries}
                                isDark={isDark}
                                isLoading={isLoading}
                                emptyMessage="No RBAC events recorded. Role assignments, permission grants, and group changes will appear here."
                            />
                            <Pagination
                                page={data?.page ?? 1}
                                totalPages={data?.totalPages ?? 1}
                                total={data?.total ?? 0}
                                pageSize={data?.pageSize ?? 100}
                                onChange={setPage}
                            />
                        </div>
                    </div>
                )}

                {/* ── Anomaly Alerts tab ── */}
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
