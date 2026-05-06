import React from 'react';
import { Loading } from '../../components/ui/Loading';
import { Alert } from '../../components/ui/Alert';
import { useAuditLog, AuditLogEntry } from '../../features/audit';

// ─── Helpers ────────────────────────────────────────────────────────────────

const EVENT_LABELS: Record<string, { label: string; color: string }> = {
    'auth.login':      { label: 'Login',       color: 'bg-gray-100 text-gray-700' },
    'auth.logout':     { label: 'Logout',      color: 'bg-gray-100 text-gray-600' },
    'secret.read':     { label: 'Read',        color: 'bg-amber-100 text-amber-700' },
    'secret.created':  { label: 'Created',     color: 'bg-emerald-100 text-emerald-700' },
    'secret.updated':  { label: 'Updated',     color: 'bg-blue-100 text-blue-700' },
    'secret.deleted':  { label: 'Deleted',     color: 'bg-red-100 text-red-700' },
    'secret.rotated':  { label: 'Rotated',     color: 'bg-purple-100 text-purple-700' },
    'secret.shared':   { label: 'Shared',      color: 'bg-indigo-100 text-indigo-700' },
    'share.revoked':   { label: 'Unshared',    color: 'bg-orange-100 text-orange-700' },
};

function eventBadge(eventType: string) {
    const e = EVENT_LABELS[eventType];
    const label = e?.label ?? eventType;
    const color = e?.color ?? 'bg-gray-100 text-gray-600';
    return (
        <span className={`inline-flex items-center px-2 py-0.5 rounded text-xs font-medium ${color}`}>
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

    return (
        <div className="min-h-screen bg-gray-50">
            <div className="max-w-7xl mx-auto px-6 py-8 space-y-6">

                <div>
                    <h1 className="text-2xl font-bold text-gray-900 tracking-tight">Audit Log</h1>
                    <p className="mt-1 text-sm text-gray-500">
                        Complete record of all secret access and system events
                        {data?.total ? ` · ${data.total} events` : ''}
                    </p>
                </div>

                {!!error && (
                    <Alert type="error" title="Failed to load audit log"
                        message="There was an error loading the audit log. Please try again." />
                )}

                <div className="bg-white border border-gray-100 rounded-xl shadow-sm overflow-hidden">
                    {isLoading ? (
                        <div className="p-12 flex justify-center"><Loading /></div>
                    ) : !data?.data?.length ? (
                        <div className="p-12 text-center">
                            <p className="text-sm text-gray-400">No audit events recorded yet.</p>
                        </div>
                    ) : (
                        <div className="overflow-x-auto">
                            <table className="min-w-full divide-y divide-gray-100">
                                <thead>
                                    <tr className="bg-gray-50">
                                        <th className="px-5 py-3 text-left text-xs font-semibold text-gray-400 uppercase tracking-wider w-44">Time</th>
                                        <th className="px-5 py-3 text-left text-xs font-semibold text-gray-400 uppercase tracking-wider w-32">Event</th>
                                        <th className="px-5 py-3 text-left text-xs font-semibold text-gray-400 uppercase tracking-wider w-32">Actor</th>
                                        <th className="px-5 py-3 text-left text-xs font-semibold text-gray-400 uppercase tracking-wider">Description</th>
                                    </tr>
                                </thead>
                                <tbody className="divide-y divide-gray-50">
                                    {data.data.map((entry: AuditLogEntry) => (
                                        <tr key={entry.id} className="hover:bg-gray-50 transition-colors duration-75">
                                            <td className="px-5 py-3 whitespace-nowrap text-xs text-gray-400 tabular-nums">
                                                {fmtTime(entry.timestamp)}
                                            </td>
                                            <td className="px-5 py-3 whitespace-nowrap">
                                                {eventBadge(entry.event_type)}
                                            </td>
                                            <td className="px-5 py-3 whitespace-nowrap text-sm font-medium text-gray-800">
                                                {entry.actor}
                                            </td>
                                            <td className="px-5 py-3 text-sm text-gray-500">
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
