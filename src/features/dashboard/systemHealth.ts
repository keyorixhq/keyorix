import type { SystemInfo, SystemMetrics } from '../../services/system';

export type SystemHealthSeverity = 'neutral' | 'warn' | 'alert';

// Thresholds for the System Health status. Tunable — these are deliberately
// conservative starting points, not values derived from any SLO.
const HTTP_ERROR_RATE_ALERT = 0.25; // server failing most requests
const HTTP_ERROR_RATE_WARN = 0.05;
const DB_AVG_QUERY_TIME_WARN_MS = 500;
const DB_POOL_SATURATION_ALERT = 0.95; // active/max connections
const DB_POOL_SATURATION_WARN = 0.8;

export function getSystemHealthSeverity(
    metrics: SystemMetrics | undefined,
    sysInfo: SystemInfo | undefined
): SystemHealthSeverity {
    // Not loaded yet — don't flash a false alert while data is still in flight.
    if (!metrics && !sysInfo) return 'neutral';

    const errorRate = metrics?.http?.error_rate ?? 0;
    const avgQueryTime = metrics?.database?.avg_query_time ?? 0;
    const slowQueries = metrics?.database?.slow_queries ?? 0;
    const queriesTotal = metrics?.database?.queries_total ?? 0;
    const slowQueryFraction = queriesTotal > 0 ? slowQueries / queriesTotal : 0;

    const pool = sysInfo?.database?.pool;
    const poolSaturation = pool && pool.max_connections > 0 ? pool.active_connections / pool.max_connections : 0;

    const dbConnected = sysInfo?.database?.connected ?? true;

    if (!dbConnected || errorRate > HTTP_ERROR_RATE_ALERT || poolSaturation > DB_POOL_SATURATION_ALERT) {
        return 'alert';
    }
    if (
        errorRate > HTTP_ERROR_RATE_WARN ||
        avgQueryTime > DB_AVG_QUERY_TIME_WARN_MS ||
        slowQueryFraction > 0.05 ||
        poolSaturation > DB_POOL_SATURATION_WARN
    ) {
        return 'warn';
    }
    return 'neutral';
}

export const HEALTH_STATUS_STYLES: Record<SystemHealthSeverity, { dot: string; text: string; label: string }> = {
    neutral: { dot: 'bg-emerald-500', text: 'text-emerald-600', label: 'Healthy' },
    warn: { dot: 'bg-amber-500', text: 'text-amber-600', label: 'Degraded' },
    alert: { dot: 'bg-red-500', text: 'text-red-600', label: 'Unhealthy' },
};

export function parseUptime(raw: string): string {
    if (!raw) return '—';
    // Go duration format: "2h34m12.456s", "45m3s", "1m3.139s", "30s", or bare integer seconds
    const match = /^(?:(\d+)h)?(?:(\d+)m)?(?:(\d+)(?:\.\d+)?s)?$/.exec(raw);
    const [, h, m, s] = match ?? [];
    if (h !== undefined) return `${h}h ${m ?? '0'}m`;
    if (m !== undefined) return `${m}m ${s ?? '0'}s`;
    if (s !== undefined) return `${s}s`;
    const num = Number.parseInt(raw, 10);
    if (!Number.isNaN(num)) return `${num}s`;
    return raw.split('.')[0] ?? '';
}
