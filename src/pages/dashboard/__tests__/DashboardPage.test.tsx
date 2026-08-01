import React from 'react';
import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, fireEvent, within } from '../../../test/test-utils';
import { DashboardPage } from '../DashboardPage';

const navigateMock = vi.fn();
vi.mock('react-router-dom', async () => {
    const actual = await vi.importActual<typeof import('react-router-dom')>('react-router-dom');
    return { ...actual, useNavigate: () => navigateMock };
});

vi.mock('../../../store/authStore', () => ({
    useAuthStore: () => ({ user: { displayName: 'Alice Admin', username: 'alice' } }),
}));

const useDashboardStats = vi.fn();
const useDashboardActivity = vi.fn();
const useSystemInfo = vi.fn();
const useSystemMetrics = vi.fn();
const useAnomalyAlerts = vi.fn();
const acknowledgeMutate = vi.fn();

vi.mock('../../../features/dashboard', () => ({
    useDashboardStats: (...args: any[]) => useDashboardStats(...args),
    useDashboardActivity: (...args: any[]) => useDashboardActivity(...args),
    useSystemInfo: (...args: any[]) => useSystemInfo(...args),
    useSystemMetrics: (...args: any[]) => useSystemMetrics(...args),
    useAnomalyAlerts: (...args: any[]) => useAnomalyAlerts(...args),
    useAcknowledgeAnomaly: () => ({ mutate: acknowledgeMutate }),
}));

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

beforeEach(() => {
    vi.clearAllMocks();
    mockHooks();
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
