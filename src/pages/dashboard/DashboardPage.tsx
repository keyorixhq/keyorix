import React from 'react';
import { useNavigate } from 'react-router-dom';
import { ROUTES } from '../../constants';
import { useAuthStore } from '../../store/authStore';
import { ActivityItem, AnomalyAlert } from '../../types';
import {
    useDashboardStats,
    useDashboardActivity,
    useSystemInfo,
    useSystemMetrics,
    useAnomalyAlerts,
    useAcknowledgeAnomaly,
} from '../../features/dashboard';

// ─── Helpers ────────────────────────────────────────────────────────────────

const fmt = (n: number) => n.toLocaleString();
const fmtDate = (d: string | Date) =>
    new Intl.DateTimeFormat('en', { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' }).format(new Date(d));

function parseUptime(raw: string): string {
    if (!raw) return '—';
    const h = raw.match(/(\d+)h/)?.[1];
    const m = raw.match(/(\d+)m/)?.[1];
    const s = raw.match(/(\d+)s/)?.[1];
    if (h) return `${h}h ${m ?? '0'}m`;
    if (m) return `${m}m`;
    if (s) return `${s}s`;
    // raw value with no unit — treat as seconds
    const num = parseInt(raw, 10);
    if (!isNaN(num)) return `${num}s`;
    return raw.split('.')[0] ?? '';
}

// ─── Sub-components ─────────────────────────────────────────────────────────

interface StatCardProps {
    label: string;
    value: string | number;
    sub?: string;
    trend?: { value: number; isPositive: boolean };
    prevValue?: number;
    accent: string;
    onClick?: () => void;
}

const StatCard: React.FC<StatCardProps> = ({ label, value, sub, trend, prevValue, accent, onClick }) => {
    const delta = trend && prevValue != null
        ? Math.round((typeof value === 'number' ? value : 0) - prevValue)
        : null;
    return (
    <div
        onClick={onClick}
        className={`relative bg-white border border-gray-100 rounded-xl p-6 flex flex-col gap-2 shadow-sm
            ${onClick ? 'cursor-pointer hover:shadow-md hover:border-gray-200 transition-all duration-150' : ''}`}
    >
        <div className={`absolute left-0 top-4 bottom-4 w-1 rounded-r-full ${accent}`} />
        <span className="text-xs font-semibold text-gray-400 uppercase tracking-widest pl-3">{label}</span>
        <span className="text-4xl font-bold text-gray-900 pl-3 tabular-nums leading-none">
            {typeof value === 'number' ? fmt(value) : value}
        </span>
        <div className="pl-3 flex items-center gap-2 flex-wrap">
            {trend && (
                <span className={`text-xs font-semibold ${trend.isPositive ? 'text-emerald-600' : 'text-red-500'}`}>
                    {trend.isPositive ? '↑' : '↓'} {trend.value}%
                    {delta !== null && (
                        <span className="font-normal opacity-70 ml-1">
                            ({delta > 0 ? '+' : ''}{delta} {label.toLowerCase().replace(/\s*\(.*\)/, '')})
                        </span>
                    )}
                </span>
            )}
            {sub && <span className="text-xs text-gray-400">{sub}</span>}
        </div>
    </div>
    );
};

interface FeaturePillProps {
    label: string;
    active: boolean;
}

const FeaturePill: React.FC<FeaturePillProps> = ({ label, active }) => (
    <div className={`flex items-center gap-1.5 px-3 py-1.5 rounded-full text-xs font-medium border
        ${active
            ? 'bg-emerald-50 border-emerald-200 text-emerald-700'
            : 'bg-gray-50 border-gray-200 text-gray-400'}`}
    >
        <div className={`w-1.5 h-1.5 rounded-full ${active ? 'bg-emerald-500' : 'bg-gray-300'}`} />
        {label}
    </div>
);

const EVENT_STYLES: Record<string, { dot: string; label: string }> = {
    created:      { dot: 'bg-emerald-500', label: 'created secret' },
    updated:      { dot: 'bg-blue-500',    label: 'updated secret' },
    accessed:     { dot: 'bg-amber-500',   label: 'accessed secret' },
    shared:       { dot: 'bg-purple-500',  label: 'shared secret' },
    login:        { dot: 'bg-gray-400',    label: 'logged in' },
    logout:       { dot: 'bg-gray-300',    label: 'logged out' },
    deleted:      { dot: 'bg-red-500',     label: 'deleted secret' },
};

const ActivityRow: React.FC<{ item: ActivityItem }> = ({ item }) => {
    const style = EVENT_STYLES[item.type] ?? { dot: 'bg-gray-400', label: item.type };
    const secretPart = item.secretName ? ` "${item.secretName}"` : '';
    return (
        <div className="flex items-start gap-3 py-3 border-b border-gray-50 last:border-0">
            <div className="mt-1.5 flex-shrink-0">
                <div className={`w-2 h-2 rounded-full ${style.dot}`} />
            </div>
            <div className="flex-1 min-w-0">
                <p className="text-sm text-gray-800">
                    <span className="font-semibold">{item.actor}</span>
                    {' '}<span className="text-gray-500">{style.label}{secretPart}</span>
                </p>
                <p className="text-xs text-gray-400 mt-0.5">{fmtDate(item.timestamp)}</p>
            </div>
        </div>
    );
};

interface SignalCardProps {
    label: string;
    value: number;
    hint: string;
    severity: 'neutral' | 'warn' | 'alert';
    onClick?: () => void;
}

const SignalCard: React.FC<SignalCardProps> = ({ label, value, hint, severity, onClick }) => {
    const colors = {
        neutral: 'bg-gray-50 border-gray-200 text-gray-700',
        warn:    'bg-amber-50 border-amber-200 text-amber-700',
        alert:   'bg-red-50 border-red-200 text-red-700',
    };
    const valueColors = {
        neutral: 'text-gray-900',
        warn:    'text-amber-700',
        alert:   'text-red-700',
    };
    return (
        <div
            onClick={onClick}
            className={`flex items-center justify-between px-4 py-3 rounded-lg border ${colors[severity]}
                ${onClick ? 'cursor-pointer hover:brightness-95 transition-all duration-100' : ''}`}
        >
            <div>
                <p className="text-xs font-semibold uppercase tracking-wide">{label}</p>
                <p className="text-xs opacity-70 mt-0.5">{hint}</p>
            </div>
            <span className={`text-2xl font-bold tabular-nums ${valueColors[severity]}`}>{value}</span>
        </div>
    );
};

// ─── Main Page ───────────────────────────────────────────────────────────────

export const DashboardPage: React.FC = () => {
    const navigate = useNavigate();
    const { user } = useAuthStore();

    const { data: stats, error: statsError } = useDashboardStats();
    const { data: activityData } = useDashboardActivity({ pageSize: 8 });
    const { data: metrics } = useSystemMetrics();
    const { data: sysInfo } = useSystemInfo();
    const { data: anomalyData } = useAnomalyAlerts(true);
    const acknowledgeAnomaly = useAcknowledgeAnomaly();

    const anomalies: AnomalyAlert[] = anomalyData?.data?.alerts ?? [];
    const expiring = stats?.expiringSecrets ?? [];
    const alertCount = anomalies.length + expiring.length;

    const features = sysInfo?.features ?? {};
    const dbMetrics = metrics?.database ?? {};

    const hour = new Date().getHours();
    const greeting = hour < 12 ? 'Good morning' : hour < 18 ? 'Good afternoon' : 'Good evening';

    return (
        <div className="min-h-screen bg-gray-50">
            <div className="max-w-7xl mx-auto px-6 py-8 space-y-8">

                {/* ── Header ─────────────────────────────────────────────── */}
                <div className="flex items-end justify-between">
                    <div>
                        <p className="text-sm text-gray-400 mb-1">{greeting}</p>
                        <h1 className="text-2xl font-bold text-gray-900 tracking-tight">
                            {(user?.displayName || user?.username || 'admin').split(' ')[0]}
                        </h1>
                    </div>
                </div>

                {/* ── Stat Cards ─────────────────────────────────────────── */}
                <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
                    <StatCard
                        label="Total Secrets"
                        value={stats?.totalSecrets ?? 0}
                        {...(stats?.totalSecretsTrend ? { trend: stats.totalSecretsTrend } : {})}
                        {...(stats?.prevTotalSecrets != null ? { prevValue: stats.prevTotalSecrets } : {})}
                        sub={stats?.totalSecretsTrend ? 'vs last snapshot' : 'across all environments'}
                        accent="bg-blue-500"
                        onClick={() => navigate(ROUTES.SECRETS)}
                    />
                    <StatCard
                        label="Active Users"
                        value={stats?.activeUsers ?? 0}
                        sub="registered accounts"
                        accent="bg-purple-500"
                        onClick={() => navigate(ROUTES.ADMIN_USERS)}
                    />
                    <StatCard
                        label="Audit Events (30d)"
                        value={stats?.auditEvents30d ?? 0}
                        sub="all events logged"
                        accent="bg-amber-500"
                        onClick={() => navigate(ROUTES.AUDIT)}
                    />
                    <StatCard
                        label={alertCount > 0 ? `Alerts (${alertCount})` : 'Security'}
                        value={alertCount > 0 ? alertCount : '✓'}
                        sub={alertCount > 0
                            ? `${anomalies.length} anomal${anomalies.length === 1 ? 'y' : 'ies'} · ${expiring.length} expiring`
                            : 'No active alerts'}
                        accent={alertCount > 0 ? 'bg-red-500' : 'bg-emerald-500'}
                        onClick={() => navigate(ROUTES.SECRETS)}
                    />
                </div>

                {/* ── Operational Signals ────────────────────────────────── */}
                <div className="bg-white border border-gray-100 rounded-xl shadow-sm">
                    <div className="px-6 py-4 border-b border-gray-50">
                        <h2 className="text-sm font-semibold text-gray-900 uppercase tracking-widest">Operational Signals</h2>
                    </div>
                    <div className="p-4 grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3">
                        <SignalCard
                            label="Expiring Secrets"
                            value={expiring.length}
                            hint="within 30 days"
                            severity={expiring.length === 0 ? 'neutral' : expiring.some(s => s.daysLeft <= 7) ? 'alert' : 'warn'}
                            onClick={() => navigate(ROUTES.SECRETS)}
                        />
                        <SignalCard
                            label="Failed Auth (24h)"
                            value={stats?.failedAuthAttempts24h ?? 0}
                            hint="unsuccessful attempts"
                            severity={(stats?.failedAuthAttempts24h ?? 0) === 0 ? 'neutral' : (stats?.failedAuthAttempts24h ?? 0) >= 5 ? 'alert' : 'warn'}
                            onClick={() => navigate(ROUTES.AUDIT)}
                        />
                        <SignalCard
                            label="Inactive Users"
                            value={stats?.inactiveUsers ?? 0}
                            hint="no login in 30 days"
                            severity={(stats?.inactiveUsers ?? 0) === 0 ? 'neutral' : 'warn'}
                            onClick={() => navigate(ROUTES.ADMIN_USERS)}
                        />
                        <SignalCard
                            label="Secret Reads (30d)"
                            value={stats?.auditSecretReads30d ?? 0}
                            hint="access events logged"
                            severity="neutral"
                            onClick={() => navigate(ROUTES.AUDIT)}
                        />
                    </div>
                </div>

                {/* ── Main Grid ──────────────────────────────────────────── */}
                <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">

                    {/* Recent Activity */}
                    <div className="lg:col-span-2 bg-white border border-gray-100 rounded-xl shadow-sm">
                        <div className="flex items-center justify-between px-6 py-4 border-b border-gray-50">
                            <h2 className="text-sm font-semibold text-gray-900 uppercase tracking-widest">Recent Activity</h2>
                            <button
                                onClick={() => navigate(ROUTES.AUDIT)}
                                className="text-xs font-medium text-gray-400 hover:text-gray-700 transition-colors"
                            >
                                View all →
                            </button>
                        </div>
                        <div className="px-6 py-2">
                            {!activityData?.data?.length ? (
                                <div className="py-12 text-center">
                                    <p className="text-sm text-gray-400">No activity yet. Create your first secret to get started.</p>
                                </div>
                            ) : (
                                activityData.data.slice(0, 8).map((item: ActivityItem) => (
                                    <ActivityRow key={item.id} item={item} />
                                ))
                            )}
                        </div>
                    </div>

                    {/* Right column */}
                    <div className="space-y-4">

                        {/* System Health */}
                        <div className="bg-white border border-gray-100 rounded-xl shadow-sm">
                            <div className="px-5 py-4 border-b border-gray-50">
                                <h2 className="text-sm font-semibold text-gray-900 uppercase tracking-widest">System Health</h2>
                            </div>
                            <div className="px-5 py-4 space-y-3">
                                <div className="flex items-center justify-between">
                                    <span className="text-sm text-gray-500">Status</span>
                                    <div className="flex items-center gap-1.5">
                                        <div className="w-2 h-2 rounded-full bg-emerald-500 animate-pulse" />
                                        <span className="text-sm font-semibold text-emerald-600">Healthy</span>
                                    </div>
                                </div>
                                <div className="flex items-center justify-between">
                                    <span className="text-sm text-gray-500">Uptime</span>
                                    <span className="text-sm font-medium text-gray-900">
                                        {parseUptime(metrics?.uptime ?? sysInfo?.uptime ?? '')}
                                    </span>
                                </div>
                                <div className="flex items-center justify-between">
                                    <span className="text-sm text-gray-500">DB connections</span>
                                    <span className="text-sm font-medium text-gray-900">
                                        {dbMetrics.connections_active != null
                                            ? `${dbMetrics.connections_active} active`
                                            : '—'}
                                    </span>
                                </div>
                                <div className="flex items-center justify-between">
                                    <span className="text-sm text-gray-500">Encryption</span>
                                    <span className="text-sm font-medium text-gray-900">
                                        {sysInfo?.security?.encryption_method ?? 'AES-256-GCM'}
                                    </span>
                                </div>

                                <div className="pt-2 flex flex-wrap gap-1.5">
                                    <FeaturePill label="Encryption" active={features.encryption_enabled ?? true} />
                                    <FeaturePill label="RBAC" active={features.rbac_enabled ?? true} />
                                    <FeaturePill label="Audit" active={features.audit_enabled ?? true} />
                                    <FeaturePill label="TLS" active={features.tls_enabled ?? true} />
                                </div>
                            </div>
                        </div>

                        {/* Quick Actions removed — duplicates sidebar navigation */}

                        {/* Alerts panel — only if there are alerts */}
                        {alertCount > 0 && (
                            <div className="bg-white border border-red-100 rounded-xl shadow-sm">
                                <div className="px-5 py-4 border-b border-red-50">
                                    <h2 className="text-sm font-semibold text-red-700 uppercase tracking-widest flex items-center gap-2">
                                        <div className="w-2 h-2 rounded-full bg-red-500 animate-pulse" />
                                        Security Alerts ({alertCount})
                                    </h2>
                                </div>
                                <div className="p-4 space-y-2">
                                    {anomalies.map(a => (
                                        <div key={a.ID} className="flex items-start justify-between gap-2 p-3 bg-red-50 rounded-lg">
                                            <div className="flex-1 min-w-0">
                                                <p className="text-xs font-semibold text-red-700">{a.AlertType}</p>
                                                <p className="text-xs text-red-600 mt-0.5 truncate">{a.SecretName}</p>
                                                <p className="text-xs text-gray-500 mt-0.5">{a.AccessedBy} · {a.IPAddress}</p>
                                            </div>
                                            <button
                                                onClick={() => acknowledgeAnomaly.mutate(a.ID)}
                                                className="text-xs text-gray-400 hover:text-gray-600 flex-shrink-0 mt-0.5"
                                                title="Dismiss"
                                            >✓</button>
                                        </div>
                                    ))}
                                    {expiring.map(s => (
                                        <div key={s.id} className="flex items-center justify-between p-3 bg-amber-50 rounded-lg">
                                            <div>
                                                <p className="text-xs font-semibold text-amber-700">{s.name}</p>
                                                <p className="text-xs text-amber-600">{s.environment}</p>
                                            </div>
                                            <span className={`text-xs font-bold ${s.daysLeft <= 7 ? 'text-red-600' : 'text-amber-600'}`}>
                                                {s.daysLeft}d
                                            </span>
                                        </div>
                                    ))}
                                </div>
                            </div>
                        )}

                        {/* Audit Health */}
                        <div className="bg-white border border-gray-100 rounded-xl shadow-sm">
                            <div className="px-5 py-4 border-b border-gray-50 flex items-center justify-between">
                                <h2 className="text-sm font-semibold text-gray-900 uppercase tracking-widest">Audit (30d)</h2>
                                <button
                                    onClick={() => navigate(ROUTES.AUDIT)}
                                    className="text-xs text-gray-400 hover:text-gray-700 transition-colors"
                                >View →</button>
                            </div>
                            <div className="px-5 py-4 space-y-3">
                                <div className="flex items-center justify-between">
                                    <span className="text-sm text-gray-500">Total events</span>
                                    <span className="text-sm font-semibold text-gray-900 tabular-nums">
                                        {fmt(stats?.auditEvents30d ?? 0)}
                                    </span>
                                </div>
                                <div className="flex items-center justify-between">
                                    <span className="text-sm text-gray-500">Logins</span>
                                    <span className="text-sm font-semibold text-blue-600 tabular-nums">
                                        {fmt(stats?.auditLogins30d ?? 0)}
                                    </span>
                                </div>
                                <div className="flex items-center justify-between">
                                    <span className="text-sm text-gray-500">Secret reads</span>
                                    <span className="text-sm font-semibold text-amber-600 tabular-nums">
                                        {fmt(stats?.auditSecretReads30d ?? 0)}
                                    </span>
                                </div>
                                <div className="flex items-center justify-between">
                                    <span className="text-sm text-gray-500">Other events</span>
                                    <span className="text-sm font-semibold text-gray-500 tabular-nums">
                                        {fmt(Math.max(0, (stats?.auditEvents30d ?? 0) - (stats?.auditLogins30d ?? 0) - (stats?.auditSecretReads30d ?? 0)))}
                                    </span>
                                </div>
                            </div>
                        </div>

                    </div>
                </div>

                {!!statsError && (
                    <p className="text-xs text-amber-600 text-center">
                        Some statistics unavailable — other features are unaffected.
                    </p>
                )}

            </div>
        </div>
    );
};
