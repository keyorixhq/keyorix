import React from 'react';
import { describe, it, expect, vi, beforeEach } from 'vitest';
import { renderHook, waitFor } from '@testing-library/react';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { useSecretsHealth } from '../useSecretsHealth';
import { Secret, RotationStatusEntry, AnomalyAlert, DashboardStats, PaginatedResponse } from '../../../types';

const { listMock, useDashboardStatsMock, useAnomalyAlertsMock, useRotationStatusMock } = vi.hoisted(() => ({
    listMock: vi.fn(),
    useDashboardStatsMock: vi.fn(),
    useAnomalyAlertsMock: vi.fn(),
    useRotationStatusMock: vi.fn(),
}));

vi.mock('../../../services/secrets', () => ({
    secretsApi: {
        list: listMock,
    },
}));

vi.mock('../../dashboard', () => ({
    useDashboardStats: useDashboardStatsMock,
    useAnomalyAlerts: useAnomalyAlertsMock,
}));

vi.mock('../useRotationPolicies', () => ({
    useRotationStatus: useRotationStatusMock,
}));

// now is captured once per test run below (a few ms before the hook's own `new
// Date()` call inside its useMemo) — offsets are computed from it in whole days,
// so the sub-millisecond drift between capture and hook execution never crosses
// a day boundary (Math.ceil absorbs it).
const daysFromNow = (days: number): string => new Date(Date.now() + days * 86_400_000).toISOString();

const makeSecret = (overrides: Partial<Secret> = {}): Secret => ({
    id: 1,
    name: 'db-password',
    type: 'password',
    environment: 'production',
    isShared: false,
    shareCount: 0,
    lastModified: '2026-06-14T00:00:00Z',
    owner: 'alice',
    permissions: [],
    metadata: {},
    tags: [],
    Expiration: null,
    ...overrides,
});

const makeRotationEntry = (overrides: Partial<RotationStatusEntry> = {}): RotationStatusEntry => ({
    policy_id: 1,
    policy_name: 'default-90d',
    interval_days: 90,
    alert_days_before: 14,
    secret_id: 1,
    secret_name: 'db-password',
    environment_id: 1,
    last_rotated_at: '2026-01-01T00:00:00Z',
    days_since_rotation: 30,
    days_overdue: 0,
    status: 'ok',
    ...overrides,
});

const makeAnomalyAlert = (overrides: Partial<AnomalyAlert> = {}): AnomalyAlert => ({
    ID: 1,
    SecretName: 'db-password',
    AlertType: 'unusual_access',
    Severity: 'high',
    Description: 'Accessed from a new IP',
    AccessedBy: 'bob',
    IPAddress: '10.0.0.1',
    DetectedAt: '2026-06-14T00:00:00Z',
    Acknowledged: false,
    ...overrides,
});

const makeDashboardStats = (overrides: Partial<DashboardStats> = {}): DashboardStats => ({
    totalSecrets: 10,
    sharedSecrets: 2,
    secretsSharedWithMe: 1,
    activeUsers: 5,
    auditEvents30d: 100,
    auditLogins30d: 50,
    auditSecretReads30d: 6,
    failedAuthAttempts24h: 4,
    inactiveUsers: 2,
    ...overrides,
});

const paginated = (secrets: Secret[]): PaginatedResponse<Secret> => ({
    data: secrets,
    total: secrets.length,
    page: 1,
    pageSize: 500,
    totalPages: 1,
});

function createWrapper(queryClient = new QueryClient({ defaultOptions: { queries: { retry: false } } })) {
    return function Wrapper({ children }: { children: React.ReactNode }) {
        return React.createElement(QueryClientProvider, { client: queryClient }, children);
    };
}

describe('useSecretsHealth', () => {
    beforeEach(() => {
        vi.resetAllMocks();
    });

    it('reports isLoading while the secrets query is still pending', () => {
        listMock.mockReturnValue(new Promise(() => {})); // never resolves
        useDashboardStatsMock.mockReturnValue({ data: undefined, isLoading: false, error: null });
        useAnomalyAlertsMock.mockReturnValue({ data: undefined, isLoading: false });
        useRotationStatusMock.mockReturnValue({ entries: [], isLoading: false, error: null });

        const { result } = renderHook(() => useSecretsHealth(), { wrapper: createWrapper() });

        expect(result.current.isLoading).toBe(true);
        expect(result.current.total).toBe(0);
    });

    it('reports isLoading when only the dashboard-stats hook is loading (secrets/anomaly/rotation already settled)', () => {
        listMock.mockResolvedValue(paginated([]));
        useDashboardStatsMock.mockReturnValue({ data: undefined, isLoading: true, error: null });
        useAnomalyAlertsMock.mockReturnValue({ data: undefined, isLoading: false });
        useRotationStatusMock.mockReturnValue({ entries: [], isLoading: false, error: null });

        const { result } = renderHook(() => useSecretsHealth(), { wrapper: createWrapper() });

        expect(result.current.isLoading).toBe(true);
    });

    it('computes expiry buckets, rotation, access and anomaly metrics against fixture data, and calls the real list endpoint with the query key/params', async () => {
        const secrets = [
            makeSecret({ id: 1, name: 'expired-a', Expiration: daysFromNow(-14) }), // expired
            makeSecret({ id: 2, name: 'expired-b', Expiration: daysFromNow(-5) }), // expired
            makeSecret({ id: 10, name: 'expired-c', Expiration: daysFromNow(-60) }), // expired
            makeSecret({ id: 3, name: 'expiring-1d', Expiration: daysFromNow(1) }), // expiring7d (d=1)
            makeSecret({ id: 4, name: 'expiring-7d', Expiration: daysFromNow(7) }), // expiring7d (d=7, inclusive boundary)
            makeSecret({ id: 5, name: 'expiring-7.5d', Expiration: daysFromNow(7.5) }), // expiring30d (d=8, just past 7d boundary)
            makeSecret({ id: 6, name: 'expiring-30d', Expiration: daysFromNow(30) }), // expiring30d (d=30, inclusive boundary)
            makeSecret({ id: 7, name: 'expiring-30.5d', Expiration: daysFromNow(30.5) }), // healthy (d=31, just past 30d boundary)
            makeSecret({ id: 8, name: 'no-expiration-null', Expiration: null }), // healthy
            makeSecret({ id: 9, name: 'no-expiration-undefined', Expiration: undefined }), // healthy
        ];
        listMock.mockResolvedValue(paginated(secrets));

        const stats = makeDashboardStats({ auditSecretReads30d: 6, failedAuthAttempts24h: 4, inactiveUsers: 2 });
        useDashboardStatsMock.mockReturnValue({ data: stats, isLoading: false, error: null });

        const anomalies = [
            makeAnomalyAlert({ ID: 1, AlertType: 'unusual_access' }),
            makeAnomalyAlert({ ID: 2, AlertType: 'bulk_read', Severity: 'critical' }),
        ];
        useAnomalyAlertsMock.mockReturnValue({ data: { data: { alerts: anomalies } }, isLoading: false });

        const rotationEntries = [
            makeRotationEntry({ secret_id: 101, status: 'overdue' }),
            makeRotationEntry({ secret_id: 102, status: 'overdue' }),
            makeRotationEntry({ secret_id: 103, status: 'due_soon' }),
            makeRotationEntry({ secret_id: 104, status: 'ok' }),
            makeRotationEntry({ secret_id: 105, status: 'ok' }),
        ];
        useRotationStatusMock.mockReturnValue({ entries: rotationEntries, isLoading: false, error: null });

        const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false } } });
        const { result } = renderHook(() => useSecretsHealth(), { wrapper: createWrapper(queryClient) });

        await waitFor(() => expect(result.current.isLoading).toBe(false));

        // Real service call: correct params and (via the query client) the correct key.
        expect(listMock).toHaveBeenCalledWith({ pageSize: 500 });
        expect(queryClient.getQueryData(['secrets', 'health-all'])).toEqual(paginated(secrets));

        // Expiry: 3 expired, 2 within 7d, 2 within 30d, 3 healthy (10 total).
        expect(result.current.total).toBe(10);
        expect(result.current.expiry).toEqual({
            expired: 3,
            expiring7d: 2,
            expiring30d: 2,
            healthy: 3,
            pct: 70, // round((10 - 3) / 10 * 100)
        });

        // Rotation: 5 covered, 2 overdue, 1 due_soon, 2 ok.
        expect(result.current.rotation).toEqual({
            available: true,
            pct: 40, // round(2 / 5 * 100)
            covered: 5,
            overdue: 2,
            dueSoon: 1,
            ok: 2,
            items: rotationEntries,
        });

        // Access: reads30d passthrough, pct against total secrets.
        expect(result.current.access).toEqual({
            reads30d: 6,
            failedAuth24h: 4,
            inactiveUsers: 2,
            pct: 60, // round(6 / 10 * 100)
        });

        // Anomalies: passthrough of the alerts array + count.
        expect(result.current.anomalies).toEqual({ count: 2, items: anomalies });

        // Overall score: weighted 40% expiry / 30% rotation / 30% access.
        expect(result.current.score).toBe(58); // round(70*0.4 + 40*0.3 + 60*0.3) = round(28 + 12 + 18)

        expect(result.current.error).toBeNull();
    });

    it('treats an empty secrets/rotation/anomaly state as fully healthy (all three neutral-100 branches)', async () => {
        listMock.mockResolvedValue(paginated([]));
        useDashboardStatsMock.mockReturnValue({
            data: makeDashboardStats({ auditSecretReads30d: 0 }),
            isLoading: false,
            error: null,
        });
        useAnomalyAlertsMock.mockReturnValue({ data: { data: { alerts: [] } }, isLoading: false });
        useRotationStatusMock.mockReturnValue({ entries: [], isLoading: false, error: null });

        const { result } = renderHook(() => useSecretsHealth(), { wrapper: createWrapper() });

        await waitFor(() => expect(result.current.isLoading).toBe(false));

        expect(result.current.total).toBe(0);
        expect(result.current.expiry.pct).toBe(100); // total === 0 branch
        expect(result.current.rotation).toMatchObject({ available: false, pct: 100, covered: 0 });
        expect(result.current.access.pct).toBe(100); // total === 0 branch
        expect(result.current.score).toBe(100);
    });

    it('clamps access.pct at 100 even when reads30d exceeds the secret count, independent of expiry/rotation math', async () => {
        const secrets = [makeSecret({ id: 1, Expiration: null }), makeSecret({ id: 2, Expiration: null })];
        listMock.mockResolvedValue(paginated(secrets));
        useDashboardStatsMock.mockReturnValue({
            data: makeDashboardStats({ auditSecretReads30d: 100 }), // 100 reads over 2 secrets -> raw 5000%
            isLoading: false,
            error: null,
        });
        useAnomalyAlertsMock.mockReturnValue({ data: { data: { alerts: [] } }, isLoading: false });
        useRotationStatusMock.mockReturnValue({
            entries: [
                makeRotationEntry({ secret_id: 1, status: 'overdue' }),
                makeRotationEntry({ secret_id: 2, status: 'ok' }),
            ],
            isLoading: false,
            error: null,
        });

        const { result } = renderHook(() => useSecretsHealth(), { wrapper: createWrapper() });

        await waitFor(() => expect(result.current.isLoading).toBe(false));

        expect(result.current.access.reads30d).toBe(100); // raw value passed through unclamped
        expect(result.current.access.pct).toBe(100); // but pct clamped via Math.min(100, ...)
        expect(result.current.expiry.pct).toBe(100); // no expirations set on either secret
        expect(result.current.rotation.pct).toBe(50); // round(1 / 2 * 100)
        expect(result.current.score).toBe(85); // round(100*0.4 + 50*0.3 + 100*0.3) = round(40 + 15 + 30)
    });

    it('surfaces the secrets-query error when the list call rejects', async () => {
        const listError = new Error('secrets fetch failed');
        listMock.mockRejectedValue(listError);
        useDashboardStatsMock.mockReturnValue({ data: undefined, isLoading: false, error: null });
        useAnomalyAlertsMock.mockReturnValue({ data: undefined, isLoading: false });
        useRotationStatusMock.mockReturnValue({ entries: [], isLoading: false, error: null });

        const { result } = renderHook(() => useSecretsHealth(), { wrapper: createWrapper() });

        await waitFor(() => expect(result.current.isLoading).toBe(false));

        expect(result.current.error).toBe(listError);
    });

    it('falls back to the dashboard-stats error only when the secrets query itself has no error', async () => {
        listMock.mockResolvedValue(paginated([]));
        const statsError = new Error('dashboard stats failed');
        useDashboardStatsMock.mockReturnValue({ data: undefined, isLoading: false, error: statsError });
        useAnomalyAlertsMock.mockReturnValue({ data: undefined, isLoading: false });
        useRotationStatusMock.mockReturnValue({ entries: [], isLoading: false, error: null });

        const { result } = renderHook(() => useSecretsHealth(), { wrapper: createWrapper() });

        await waitFor(() => expect(result.current.isLoading).toBe(false));

        expect(result.current.error).toBe(statsError);
    });
});
