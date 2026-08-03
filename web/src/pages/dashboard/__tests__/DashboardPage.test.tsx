import React from 'react';
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { render, screen, fireEvent, within } from '../../../test/test-utils';
import { DashboardPage } from '../DashboardPage';
import { useUIStore } from '../../../store/uiStore';

const navigateMock = vi.fn();
vi.mock('react-router-dom', async () => {
    const actual = await vi.importActual<typeof import('react-router-dom')>('react-router-dom');
    return { ...actual, useNavigate: () => navigateMock };
});

const useAuthStore = vi.fn();
vi.mock('../../../store/authStore', () => ({
    useAuthStore: (...args: any[]) => useAuthStore(...args),
}));

const useDashboardStats = vi.fn();
const useDashboardActivity = vi.fn();
const useSystemInfo = vi.fn();
const useSystemMetrics = vi.fn();
const useAnomalyAlerts = vi.fn();
const acknowledgeMutate = vi.fn();

vi.mock('../../../features/dashboard', async (importOriginal) => {
    const actual = await importOriginal<typeof import('../../../features/dashboard')>();
    return {
        ...actual,
        useDashboardStats: (...args: any[]) => useDashboardStats(...args),
        useDashboardActivity: (...args: any[]) => useDashboardActivity(...args),
        useSystemInfo: (...args: any[]) => useSystemInfo(...args),
        useSystemMetrics: (...args: any[]) => useSystemMetrics(...args),
        useAnomalyAlerts: (...args: any[]) => useAnomalyAlerts(...args),
        useAcknowledgeAnomaly: () => ({ mutate: acknowledgeMutate }),
    };
});

const baseStats = {
    totalSecrets: 120,
    activeUsers: 8,
    auditEvents30d: 340,
    auditLogins30d: 50,
    auditSecretReads30d: 200,
    inactiveUsers: 2,
    failedAuthAttempts24h: 3,
    sharedSecrets: 5,
    expiringSecrets: [] as any[],
};

function mockHooks(overrides: { stats?: any; statsError?: unknown; activity?: any[]; anomalies?: any[] } = {}) {
    useDashboardStats.mockReturnValue({ data: overrides.stats ?? baseStats, error: overrides.statsError ?? null });
    useDashboardActivity.mockReturnValue({ data: { data: overrides.activity ?? [] } });
    useSystemInfo.mockReturnValue({
        data: {
            features: { encryption_enabled: true, rbac_enabled: true, audit_enabled: false, tls_enabled: true },
            security: { encryption_method: 'AES-256-GCM' },
        },
    });
    useSystemMetrics.mockReturnValue({ data: { uptime: '2h34m12.456s', database: { connections_active: 5 } } });
    useAnomalyAlerts.mockReturnValue({ data: { data: { alerts: overrides.anomalies ?? [] } } });
}

const initialTheme = useUIStore.getState().theme;

beforeEach(() => {
    vi.clearAllMocks();
    mockHooks();
    useAuthStore.mockReturnValue({ user: { displayName: 'Alice Admin', username: 'alice' } });
});

afterEach(() => {
    useUIStore.setState({ theme: initialTheme });
});

describe('DashboardPage — header', () => {
    it('greets the user by their first name', () => {
        render(<DashboardPage />);
        expect(screen.getByRole('heading', { name: 'Alice' })).toBeInTheDocument();
    });
});

describe('DashboardPage — stat cards', () => {
    it('shows the core stats and navigates on click', () => {
        render(<DashboardPage />);
        expect(screen.getByText('120')).toBeInTheDocument(); // Total Secrets
        expect(screen.getByText('8')).toBeInTheDocument(); // Active Users
        // 340 (Audit Events 30d) appears both as a stat card and in the Audit Health panel's total.
        expect(screen.getAllByText('340')).toHaveLength(2);

        fireEvent.click(screen.getByText('Total Secrets').closest('button')!);
        expect(navigateMock).toHaveBeenCalledWith('/secrets?sort=expiry_asc');

        fireEvent.click(screen.getByText('Active Users').closest('button')!);
        expect(navigateMock).toHaveBeenCalledWith('/admin/users');

        fireEvent.click(screen.getByText('Audit Events (30d)').closest('button')!);
        expect(navigateMock).toHaveBeenCalledWith('/audit');
    });

    it('shows an up trend with a positive delta vs. the previous snapshot', () => {
        mockHooks({
            stats: {
                ...baseStats,
                totalSecrets: 120,
                totalSecretsTrend: { value: 12, isPositive: true },
                prevTotalSecrets: 100,
            },
        });
        render(<DashboardPage />);
        expect(screen.getByText('↑ 12%')).toBeInTheDocument();
        expect(screen.getByText('(+20)')).toBeInTheDocument();
        expect(screen.getByText('vs last snapshot')).toBeInTheDocument();
    });

    it('shows a down trend with a negative delta vs. the previous snapshot', () => {
        mockHooks({
            stats: {
                ...baseStats,
                totalSecrets: 120,
                totalSecretsTrend: { value: 5, isPositive: false },
                prevTotalSecrets: 130,
            },
        });
        render(<DashboardPage />);
        expect(screen.getByText('↓ 5%')).toBeInTheDocument();
        expect(screen.getByText('(-10)')).toBeInTheDocument();
    });

    it('shows the trend without a delta when there is no previous snapshot value', () => {
        mockHooks({
            stats: {
                ...baseStats,
                totalSecrets: 120,
                totalSecretsTrend: { value: 12, isPositive: true },
                prevTotalSecrets: undefined,
            },
        });
        render(<DashboardPage />);
        expect(screen.getByText('↑ 12%')).toBeInTheDocument();
        expect(screen.queryByText(/^\(/)).not.toBeInTheDocument();
    });

    it('shows a checkmark security card when there are no alerts', () => {
        render(<DashboardPage />);
        expect(screen.getByText('Security')).toBeInTheDocument();
        expect(screen.getByText('✓')).toBeInTheDocument();
        expect(screen.getByText('No active alerts')).toBeInTheDocument();
    });

    it('shows an alert count security card when there are anomalies or expiring secrets', () => {
        mockHooks({
            stats: {
                ...baseStats,
                expiringSecrets: [{ id: 1, name: 'db-pass', environment: 'prod', daysLeft: 3, expired: false }],
            },
            anomalies: [
                { ID: 1, AlertType: 'off_hours', SecretName: 'db-pass', AccessedBy: 'bob', IPAddress: '1.2.3.4' },
            ],
        });
        render(<DashboardPage />);
        expect(screen.getByText('Alerts (2)')).toBeInTheDocument();

        fireEvent.click(screen.getByText('Alerts (2)').closest('button')!);
        expect(navigateMock).toHaveBeenCalledWith('/audit?tab=anomalies');
    });
});

describe('DashboardPage — operational signals', () => {
    it('navigates from the failed-auth signal', () => {
        render(<DashboardPage />);
        fireEvent.click(screen.getByText('Failed Auth (24h)').closest('button')!);
        expect(navigateMock).toHaveBeenCalledWith('/audit?tab=audit&filter=failed');
    });

    it('shows the inactive-users count', () => {
        render(<DashboardPage />);
        const card = screen.getByText('Inactive Users').closest('button')!;
        expect(within(card).getByText('2')).toBeInTheDocument();
    });

    it('navigates from the inactive-users signal', () => {
        render(<DashboardPage />);
        fireEvent.click(screen.getByText('Inactive Users').closest('button')!);
        expect(navigateMock).toHaveBeenCalledWith('/admin/users?filter=inactive');
    });

    it('navigates from the expiring-secrets signal', () => {
        render(<DashboardPage />);
        fireEvent.click(screen.getByText('Expiring Secrets').closest('button')!);
        expect(navigateMock).toHaveBeenCalledWith('/secrets?sort=expiry_asc&filter=expiring');
    });

    it('navigates from the secret-reads signal', () => {
        render(<DashboardPage />);
        fireEvent.click(screen.getByText('Secret Reads (30d)').closest('button')!);
        expect(navigateMock).toHaveBeenCalledWith('/audit?tab=audit&filter=reads');
    });

    it('shows a "warn" severity (not urgent, not expired) when a secret expires beyond 7 days', () => {
        mockHooks({
            stats: {
                ...baseStats,
                expiringSecrets: [{ id: 1, name: 'db-pass', environment: 'prod', daysLeft: 20, expired: false }],
            },
        });
        render(<DashboardPage />);
        expect(screen.getByText('within 30 days')).toBeInTheDocument();
    });

    it('shows the expired-count hint when a secret has already expired', () => {
        mockHooks({
            stats: {
                ...baseStats,
                expiringSecrets: [
                    { id: 1, name: 'old-pass', environment: 'prod', daysLeft: -3, expired: true },
                    { id: 2, name: 'soon-pass', environment: 'prod', daysLeft: 20, expired: false },
                ],
            },
        });
        render(<DashboardPage />);
        expect(screen.getByText('1 expired · 1 expiring in 30d')).toBeInTheDocument();
    });
});

describe('DashboardPage — recent activity', () => {
    it('shows an empty state with no activity', () => {
        render(<DashboardPage />);
        expect(screen.getByText(/no activity yet/i)).toBeInTheDocument();
    });

    it('renders activity rows', () => {
        mockHooks({
            activity: [
                { id: 1, type: 'created', actor: 'alice', secretName: 'db-pass', timestamp: '2026-01-01T10:00:00Z' },
            ],
        });
        render(<DashboardPage />);
        expect(screen.getByText('alice')).toBeInTheDocument();
        expect(screen.getByText(/created secret "db-pass"/)).toBeInTheDocument();
    });

    it('navigates to the audit page from "View all"', () => {
        render(<DashboardPage />);
        fireEvent.click(screen.getByText('View all →'));
        expect(navigateMock).toHaveBeenCalledWith('/audit');
    });
});

describe('DashboardPage — system health', () => {
    it('parses uptime and shows DB connections, encryption, and feature pills', () => {
        render(<DashboardPage />);
        expect(screen.getByText('2h 34m')).toBeInTheDocument();
        expect(screen.getByText('5 active')).toBeInTheDocument();
        expect(screen.getByText('AES-256-GCM')).toBeInTheDocument();
        // "Encryption" is both a row label and a feature-pill label; two matches is correct.
        expect(screen.getAllByText('Encryption')).toHaveLength(2);
        expect(screen.getByText('Audit')).toBeInTheDocument(); // shown even though inactive
    });

    it('shows Healthy when metrics are within normal range', () => {
        render(<DashboardPage />);
        expect(screen.getByText('Healthy')).toBeInTheDocument();
    });

    it('shows Degraded when the HTTP error rate crosses the warn threshold', () => {
        useSystemMetrics.mockReturnValue({
            data: {
                uptime: '2h34m12.456s',
                http: { error_rate: 0.1 },
                database: { connections_active: 5, avg_query_time: 10, slow_queries: 0, queries_total: 100 },
            },
        });
        render(<DashboardPage />);
        expect(screen.getByText('Degraded')).toBeInTheDocument();
    });

    it('shows Unhealthy when the database reports disconnected', () => {
        useSystemInfo.mockReturnValue({
            data: {
                features: { encryption_enabled: true, rbac_enabled: true, audit_enabled: false, tls_enabled: true },
                security: { encryption_method: 'AES-256-GCM' },
                database: { connected: false },
            },
        });
        render(<DashboardPage />);
        expect(screen.getByText('Unhealthy')).toBeInTheDocument();
    });

    it('shows Unhealthy when the DB connection pool is nearly saturated', () => {
        useSystemInfo.mockReturnValue({
            data: {
                features: { encryption_enabled: true, rbac_enabled: true, audit_enabled: false, tls_enabled: true },
                security: { encryption_method: 'AES-256-GCM' },
                database: { connected: true, pool: { max_connections: 100, active_connections: 98 } },
            },
        });
        render(<DashboardPage />);
        expect(screen.getByText('Unhealthy')).toBeInTheDocument();
    });

    it('shows Healthy (not a false alert) before metrics have loaded', () => {
        useSystemMetrics.mockReturnValue({ data: undefined });
        useSystemInfo.mockReturnValue({ data: undefined });
        render(<DashboardPage />);
        expect(screen.getByText('Healthy')).toBeInTheDocument();
    });

    it('shows Unknown instead of a false Healthy when the metrics fetch fails', () => {
        useSystemMetrics.mockReturnValue({ data: undefined, isError: true });
        render(<DashboardPage />);
        expect(screen.getByText('Unknown')).toBeInTheDocument();
        expect(screen.queryByText('Healthy')).not.toBeInTheDocument();
    });

    it('shows Unknown instead of a false Healthy when the system info fetch fails', () => {
        useSystemInfo.mockReturnValue({ data: undefined, isError: true });
        render(<DashboardPage />);
        expect(screen.getByText('Unknown')).toBeInTheDocument();
        expect(screen.queryByText('Healthy')).not.toBeInTheDocument();
    });
});

describe('DashboardPage — security alerts panel', () => {
    it('is hidden when there are no alerts', () => {
        render(<DashboardPage />);
        expect(screen.queryByText(/security alerts/i)).not.toBeInTheDocument();
    });

    it('lists anomalies and expiring secrets, and dismisses an anomaly', () => {
        mockHooks({
            stats: {
                ...baseStats,
                expiringSecrets: [{ id: 1, name: 'db-pass', environment: 'prod', daysLeft: 3, expired: false }],
            },
            anomalies: [
                { ID: 7, AlertType: 'off_hours', SecretName: 'api-key', AccessedBy: 'bob', IPAddress: '1.2.3.4' },
            ],
        });
        render(<DashboardPage />);

        expect(screen.getByText('Security Alerts (2)')).toBeInTheDocument();
        expect(screen.getByText('Off-hours')).toBeInTheDocument();
        expect(screen.getByText('3d')).toBeInTheDocument();

        fireEvent.click(screen.getByTitle('Dismiss'));
        expect(acknowledgeMutate).toHaveBeenCalledWith(7);
    });
});

describe('DashboardPage — audit health', () => {
    it('computes totals, logins, reads, and other events', () => {
        render(<DashboardPage />);
        // Audit (30d) panel: 340 total, 50 logins, 200 reads, 90 other (340-50-200).
        expect(screen.getByText('90')).toBeInTheDocument();
    });
});

describe('DashboardPage — stats error', () => {
    it('shows a degraded-stats notice', () => {
        mockHooks({ statsError: new Error('boom') });
        render(<DashboardPage />);
        expect(screen.getByText(/some statistics unavailable/i)).toBeInTheDocument();
    });
});

describe('DashboardPage — active users / audit sub-labels', () => {
    it('uses the singular form when exactly one secret is shared', () => {
        mockHooks({ stats: { ...baseStats, sharedSecrets: 1 } });
        render(<DashboardPage />);
        expect(screen.getByText('1 shared secret')).toBeInTheDocument();
    });

    it('falls back to "registered accounts" when nothing is shared', () => {
        mockHooks({ stats: { ...baseStats, sharedSecrets: 0 } });
        render(<DashboardPage />);
        expect(screen.getByText('registered accounts')).toBeInTheDocument();
    });

    it('falls back to "all events logged" when login/read counts are unavailable', () => {
        mockHooks({ stats: { ...baseStats, auditLogins30d: null, auditSecretReads30d: null } });
        render(<DashboardPage />);
        expect(screen.getByText('all events logged')).toBeInTheDocument();
    });
});

describe('DashboardPage — audit health panel navigation', () => {
    it('navigates to the audit page from the panel\'s "View" link', () => {
        render(<DashboardPage />);
        fireEvent.click(screen.getByText('View →'));
        expect(navigateMock).toHaveBeenCalledWith('/audit');
    });
});

describe('DashboardPage — missing stats and anomaly data', () => {
    it('renders sensible defaults when stats and anomaly data are unavailable', () => {
        useDashboardStats.mockReturnValue({ data: undefined, error: null });
        useAnomalyAlerts.mockReturnValue({ data: undefined });
        render(<DashboardPage />);

        expect(screen.getByText('registered accounts')).toBeInTheDocument();
        expect(screen.getByText('all events logged')).toBeInTheDocument();
        expect(screen.getByText('within 30 days')).toBeInTheDocument();
        expect(screen.getByText('Security')).toBeInTheDocument();
        expect(screen.getByText('✓')).toBeInTheDocument();
    });
});

describe('DashboardPage — greeting name fallback', () => {
    it('falls back to the username when there is no display name', () => {
        useAuthStore.mockReturnValue({ user: { username: 'bob' } });
        render(<DashboardPage />);
        expect(screen.getByRole('heading', { name: 'bob' })).toBeInTheDocument();
    });

    it('falls back to "admin" when there is no user at all', () => {
        useAuthStore.mockReturnValue({ user: null });
        render(<DashboardPage />);
        expect(screen.getByRole('heading', { name: 'admin' })).toBeInTheDocument();
    });
});

describe('DashboardPage — recent activity edge cases', () => {
    it('renders an unmapped activity type with a default dot/label and no secret name', () => {
        mockHooks({
            activity: [{ id: 1, type: 'custom_event', actor: 'carol', timestamp: '2026-01-01T10:00:00Z' }],
        });
        render(<DashboardPage />);
        expect(screen.getByText('carol')).toBeInTheDocument();
        expect(screen.getByText('custom_event')).toBeInTheDocument();
    });
});

describe('DashboardPage — theme variants', () => {
    it('renders correctly in light theme', () => {
        useUIStore.setState({ theme: 'light' });
        render(<DashboardPage />);
        expect(screen.getAllByText('Encryption').length).toBeGreaterThan(0);
    });

    it('renders correctly in system theme', () => {
        useUIStore.setState({ theme: 'system' });
        render(<DashboardPage />);
        expect(screen.getAllByText('Encryption').length).toBeGreaterThan(0);
    });
});
