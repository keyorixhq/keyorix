import { describe, it, expect } from 'vitest';
import { getSystemHealthSeverity, HEALTH_STATUS_STYLES, parseUptime } from '../systemHealth';
import type { SystemInfo, SystemMetrics } from '../../../services/system';

const healthyMetrics: SystemMetrics = {
    memory: {} as SystemMetrics['memory'],
    goroutines: 10,
    gc: {} as SystemMetrics['gc'],
    http: { requests_total: 100, requests_per_sec: 1, avg_response_time: 5, error_rate: 0, active_connections: 1 },
    database: {
        queries_total: 100,
        queries_per_sec: 1,
        avg_query_time: 10,
        slow_queries: 0,
        connections_active: 2,
        connections_idle: 3,
    },
    secrets: {} as SystemMetrics['secrets'],
    uptime: '2h34m12.456s',
    timestamp: '2026-01-01T00:00:00Z',
};

const healthySysInfo: SystemInfo = {
    version: '1.0.0',
    build_time: 'unknown',
    git_commit: 'abc123',
    go_version: 'go1.26',
    os: 'linux',
    arch: 'amd64',
    uptime: '2h34m12.456s',
    environment: 'production',
    features: {},
    database: {
        type: 'postgres',
        connected: true,
        version: '',
        pool: { max_connections: 100, active_connections: 2, idle_connections: 3 },
    },
    security: { tls_enabled: true, auth_enabled: true, encryption_method: 'AES-256-GCM', audit_enabled: true },
};

describe('getSystemHealthSeverity', () => {
    it('returns neutral when neither metrics nor sysInfo have loaded yet', () => {
        expect(getSystemHealthSeverity(undefined, undefined)).toBe('neutral');
    });

    it('returns neutral for healthy metrics within all thresholds', () => {
        expect(getSystemHealthSeverity(healthyMetrics, healthySysInfo)).toBe('neutral');
    });

    it('returns alert when the database reports disconnected', () => {
        const sysInfo = { ...healthySysInfo, database: { ...healthySysInfo.database, connected: false } };
        expect(getSystemHealthSeverity(healthyMetrics, sysInfo)).toBe('alert');
    });

    it('returns alert when the HTTP error rate crosses the alert threshold', () => {
        const metrics = { ...healthyMetrics, http: { ...healthyMetrics.http, error_rate: 0.3 } };
        expect(getSystemHealthSeverity(metrics, healthySysInfo)).toBe('alert');
    });

    it('returns alert when the connection pool is nearly saturated', () => {
        const sysInfo = {
            ...healthySysInfo,
            database: {
                ...healthySysInfo.database,
                pool: { max_connections: 100, active_connections: 98, idle_connections: 0 },
            },
        };
        expect(getSystemHealthSeverity(healthyMetrics, sysInfo)).toBe('alert');
    });

    it('returns warn when the HTTP error rate crosses the warn threshold', () => {
        const metrics = { ...healthyMetrics, http: { ...healthyMetrics.http, error_rate: 0.1 } };
        expect(getSystemHealthSeverity(metrics, healthySysInfo)).toBe('warn');
    });

    it('returns warn when average query time crosses the warn threshold', () => {
        const metrics = { ...healthyMetrics, database: { ...healthyMetrics.database, avg_query_time: 600 } };
        expect(getSystemHealthSeverity(metrics, healthySysInfo)).toBe('warn');
    });

    it('returns warn when the slow-query fraction exceeds 5%', () => {
        const metrics = {
            ...healthyMetrics,
            database: { ...healthyMetrics.database, queries_total: 100, slow_queries: 10 },
        };
        expect(getSystemHealthSeverity(metrics, healthySysInfo)).toBe('warn');
    });

    it('returns warn when the connection pool crosses the warn threshold', () => {
        const sysInfo = {
            ...healthySysInfo,
            database: {
                ...healthySysInfo.database,
                pool: { max_connections: 100, active_connections: 85, idle_connections: 0 },
            },
        };
        expect(getSystemHealthSeverity(healthyMetrics, sysInfo)).toBe('warn');
    });

    it('treats a missing pool as zero saturation rather than throwing', () => {
        const sysInfo = { ...healthySysInfo, database: { ...healthySysInfo.database, pool: undefined as any } };
        expect(getSystemHealthSeverity(healthyMetrics, sysInfo)).toBe('neutral');
    });

    it('treats zero queries_total as zero slow-query fraction rather than dividing by zero', () => {
        const metrics = {
            ...healthyMetrics,
            database: { ...healthyMetrics.database, queries_total: 0, slow_queries: 0 },
        };
        expect(getSystemHealthSeverity(metrics, healthySysInfo)).toBe('neutral');
    });

    it('treats a missing sysInfo as connected rather than alerting', () => {
        // Metrics have loaded but sysInfo hasn't yet — dbConnected should default
        // to true instead of flashing an alert while sysInfo is still in flight.
        expect(getSystemHealthSeverity(healthyMetrics, undefined)).toBe('neutral');
    });

    it('treats a missing metrics object as all-zero rather than throwing', () => {
        // sysInfo has loaded but metrics hasn't yet — every metrics-derived value
        // should fall back to 0 via optional chaining instead of throwing.
        expect(getSystemHealthSeverity(undefined, healthySysInfo)).toBe('neutral');
    });
});

describe('HEALTH_STATUS_STYLES', () => {
    it('has a label for every severity', () => {
        expect(HEALTH_STATUS_STYLES.neutral.label).toBe('Healthy');
        expect(HEALTH_STATUS_STYLES.warn.label).toBe('Degraded');
        expect(HEALTH_STATUS_STYLES.alert.label).toBe('Unhealthy');
    });
});

describe('parseUptime', () => {
    it('returns an em dash for an empty string', () => {
        expect(parseUptime('')).toBe('—');
    });

    it('formats hours and minutes', () => {
        expect(parseUptime('2h34m12.456s')).toBe('2h 34m');
    });

    it('defaults minutes to 0 when only hours are present', () => {
        expect(parseUptime('2h')).toBe('2h 0m');
    });

    it('formats minutes and seconds when there are no hours', () => {
        expect(parseUptime('45m3s')).toBe('45m 3s');
    });

    it('defaults seconds to 0 when only minutes are present', () => {
        expect(parseUptime('45m')).toBe('45m 0s');
    });

    it('formats seconds only when there are no hours or minutes', () => {
        expect(parseUptime('30s')).toBe('30s');
    });

    it('formats a bare integer as seconds', () => {
        expect(parseUptime('42')).toBe('42s');
    });

    it('falls back to the integer portion for an unrecognized format', () => {
        expect(parseUptime('not-a-duration')).toBe('not-a-duration');
    });
});
