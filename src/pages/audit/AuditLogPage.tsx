import React from 'react';
import { Loading } from '../../components/ui/Loading';
import { useUIStore } from '../../store/uiStore';
import { Alert } from '../../components/ui/Alert';
import { useAuditLog, AuditLogEntry } from '../../features/audit';

// ─── Helpers ────────────────────────────────────────────────────────────────

// dark: light text on tinted bg; light: darker text on tinted bg
const EVENT_STYLES: Record<string, { label: string; darkBg: string; darkColor: string; lightBg: string; lightColor: string }> = {
    'auth.login':      { label: 'Login',    darkBg: 'rgba(148,163,184,0.15)', darkColor: '#94a3b8', lightBg: '#f1f5f9', lightColor: '#475569' },
    'auth.logout':     { label: 'Logout',   darkBg: 'rgba(148,163,184,0.15)', darkColor: '#94a3b8', lightBg: '#f1f5f9', lightColor: '#475569' },
    'secret.read':     { label: 'Read',     darkBg: 'rgba(251,191,36,0.15)',  darkColor: '#fbbf24', lightBg: '#fef9c3', lightColor: '#854d0e' },
    'secret.created':  { label: 'Created',  darkBg: 'rgba(16,185,129,0.15)',  darkColor: '#34d399', lightBg: '#dcfce7', lightColor: '#166534' },
    'secret.updated':  { label: 'Updated',  darkBg: 'rgba(59,130,246,0.15)',  darkColor: '#60a5fa', lightBg: '#dbeafe', lightColor: '#1e40af' },
    'secret.deleted':  { label: 'Deleted',  darkBg: 'rgba(239,68,68,0.15)',   darkColor: '#f87171', lightBg: '#fee2e2', lightColor: '#991b1b' },
    'secret.rotated':  { label: 'Rotated',  darkBg: 'rgba(168,85,247,0.15)',  darkColor: '#c084fc', lightBg: '#f3e8ff', lightColor: '#6b21a8' },
    'secret.shared':   { label: 'Shared',   darkBg: 'rgba(99,102,241,0.15)',  darkColor: '#818cf8', lightBg: '#e0e7ff', lightColor: '#3730a3' },
    'share.revoked':   { label: 'Unshared', darkBg: 'rgba(251,146,60,0.15)',  darkColor: '#fb923c', lightBg: '#ffedd5', lightColor: '#9a3412' },
};

function eventBadge(eventType: string, isDark: boolean) {
    const e = EVENT_STYLES[eventType];
    const label = e?.label ?? eventType;
    const bg = e ? (isDark ? e.darkBg : e.lightBg) : (isDark ? 'rgba(148,163,184,0.15)' : '#f1f5f9');
    const color = e ? (isDark ? e.darkColor : e.lightColor) : (isDark ? '#94a3b8' : '#475569');
    return (
        <span
            className="inline-flex items-center px-2 py-0.5 rounded text-xs font-medium"
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
        month: 'short', day: 'numeric',
        hour: '2-digit', minute: '2-digit', second: '2-digit',
    });
}

// ─── Page ────────────────────────────────────────────────────────────────────

export const AuditLogPage: React.FC = () => {
    const { data, isLoading, error } = useAuditLog({ pageSize: 50 });
    const { theme } = useUIStore();
    const isDark = theme === 'dark' || (theme === 'system' && window.matchMedia('(prefers-color-scheme: dark)').matches);

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

                {!!error && (
                    <Alert type="error" title="Failed to load audit log"
                        message="There was an error loading the audit log. Please try again." />
                )}

                <div className="bg-surface border border-base rounded-xl shadow-sm overflow-hidden">
                    {isLoading ? (
                        <div className="p-12 flex justify-center"><Loading /></div>
                    ) : !data?.data?.length ? (
                        <div className="p-12 text-center">
                            <p className="text-sm text-base-muted">No audit events recorded yet.</p>
                        </div>
                    ) : (
                        <div className="overflow-x-auto">
                            <table className="min-w-full divide-y divide-base">
                                <thead>
                                    <tr className="bg-subtle">
                                        <th className="px-5 py-3 text-left text-xs font-semibold text-base-muted uppercase tracking-wider w-44">Time</th>
                                        <th className="px-5 py-3 text-left text-xs font-semibold text-base-muted uppercase tracking-wider w-32">Event</th>
                                        <th className="px-5 py-3 text-left text-xs font-semibold text-base-muted uppercase tracking-wider w-32">Actor</th>
                                        <th className="px-5 py-3 text-left text-xs font-semibold text-base-muted uppercase tracking-wider">Description</th>
                                    </tr>
                                </thead>
                                <tbody className="divide-y divide-base">
                                    {data.data.map((entry: AuditLogEntry) => (
                                        <tr key={entry.id} className="hover:bg-subtle transition-colors duration-75">
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

            </div>
        </div>
    );
};
