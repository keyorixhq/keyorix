import React from 'react';
import { describe, it, expect, vi, beforeEach } from 'vitest';
import { renderHook, waitFor, act } from '@testing-library/react';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';

vi.mock('../../../services/dashboard', () => ({ dashboardApi: { getStats: vi.fn(), getActivity: vi.fn() } }));
vi.mock('../../../services/system', () => ({
    systemApi: { getInfo: vi.fn(), getMetrics: vi.fn(), getAuthConfig: vi.fn(), getEncryptionConfig: vi.fn() },
}));
vi.mock('../../../services/audit', () => ({
    auditApi: { getAnomalyAlerts: vi.fn(), acknowledgeAnomalyAlert: vi.fn() },
}));
vi.mock('../../../services/users', () => ({ usersApi: { list: vi.fn(), get: vi.fn() } }));
vi.mock('../../../services/groups', () => ({ groupsApi: { list: vi.fn(), get: vi.fn() } }));

import { dashboardApi } from '../../../services/dashboard';
import { systemApi } from '../../../services/system';
import { auditApi } from '../../../services/audit';
import { usersApi } from '../../../services/users';
import { groupsApi } from '../../../services/groups';
import {
    useDashboardStats,
    useDashboardActivity,
    useSystemInfo,
    useSystemMetrics,
    useAuthConfig,
    useEncryptionConfig,
    useAnomalyAlerts,
    useAcknowledgeAnomaly,
    useUsers,
    useUser,
    useGroups,
    useGroup,
} from '../api';

const mockDashboard = dashboardApi as unknown as {
    getStats: ReturnType<typeof vi.fn>;
    getActivity: ReturnType<typeof vi.fn>;
};
const mockSystem = systemApi as unknown as {
    getInfo: ReturnType<typeof vi.fn>;
    getMetrics: ReturnType<typeof vi.fn>;
    getAuthConfig: ReturnType<typeof vi.fn>;
    getEncryptionConfig: ReturnType<typeof vi.fn>;
};
const mockAudit = auditApi as unknown as {
    getAnomalyAlerts: ReturnType<typeof vi.fn>;
    acknowledgeAnomalyAlert: ReturnType<typeof vi.fn>;
};
const mockUsers = usersApi as unknown as { list: ReturnType<typeof vi.fn>; get: ReturnType<typeof vi.fn> };
const mockGroups = groupsApi as unknown as { list: ReturnType<typeof vi.fn>; get: ReturnType<typeof vi.fn> };

function createWrapper() {
    const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false } } });
    const wrapper = ({ children }: { children: React.ReactNode }) =>
        React.createElement(QueryClientProvider, { client: queryClient }, children);
    return { wrapper, queryClient };
}

beforeEach(() => vi.clearAllMocks());

describe('useDashboardStats', () => {
    it('fetches dashboard stats', async () => {
        mockDashboard.getStats.mockResolvedValueOnce({ total_secrets: 10 });
        const { result } = renderHook(() => useDashboardStats(), { wrapper: createWrapper().wrapper });
        await waitFor(() => expect(result.current.isSuccess).toBe(true));
        expect(result.current.data).toEqual({ total_secrets: 10 });
    });
});

describe('useDashboardActivity', () => {
    it('forwards params to dashboardApi.getActivity', async () => {
        mockDashboard.getActivity.mockResolvedValueOnce({ data: [], total: 0, page: 1, pageSize: 10, totalPages: 1 });
        const { result } = renderHook(() => useDashboardActivity({ page: 2, type: 'secret.read' }), {
            wrapper: createWrapper().wrapper,
        });
        await waitFor(() => expect(result.current.isSuccess).toBe(true));
        expect(mockDashboard.getActivity).toHaveBeenCalledWith({ page: 2, type: 'secret.read' });
    });
});

describe('useSystemInfo / useSystemMetrics', () => {
    it('fetches system info', async () => {
        mockSystem.getInfo.mockResolvedValueOnce({ version: '1.2.3' });
        const { result } = renderHook(() => useSystemInfo(), { wrapper: createWrapper().wrapper });
        await waitFor(() => expect(result.current.isSuccess).toBe(true));
        expect(result.current.data).toEqual({ version: '1.2.3' });
    });

    it('fetches system metrics', async () => {
        mockSystem.getMetrics.mockResolvedValueOnce({ uptime_seconds: 42 });
        const { result } = renderHook(() => useSystemMetrics(), { wrapper: createWrapper().wrapper });
        await waitFor(() => expect(result.current.isSuccess).toBe(true));
        expect(result.current.data).toEqual({ uptime_seconds: 42 });
    });
});

describe('useAuthConfig / useEncryptionConfig', () => {
    it('fetches auth config', async () => {
        mockSystem.getAuthConfig.mockResolvedValueOnce({ require_mfa: true });
        const { result } = renderHook(() => useAuthConfig(), { wrapper: createWrapper().wrapper });
        await waitFor(() => expect(result.current.isSuccess).toBe(true));
        expect(result.current.data).toEqual({ require_mfa: true });
    });

    it('fetches encryption config', async () => {
        mockSystem.getEncryptionConfig.mockResolvedValueOnce({ enabled: true });
        const { result } = renderHook(() => useEncryptionConfig(), { wrapper: createWrapper().wrapper });
        await waitFor(() => expect(result.current.isSuccess).toBe(true));
        expect(result.current.data).toEqual({ enabled: true });
    });
});

describe('useAnomalyAlerts', () => {
    it('defaults to unacknowledged-only', async () => {
        mockAudit.getAnomalyAlerts.mockResolvedValueOnce({ alerts: [] });
        const { result } = renderHook(() => useAnomalyAlerts(), { wrapper: createWrapper().wrapper });
        await waitFor(() => expect(result.current.isSuccess).toBe(true));
        expect(mockAudit.getAnomalyAlerts).toHaveBeenCalledWith(true);
    });

    it('forwards an explicit false', async () => {
        mockAudit.getAnomalyAlerts.mockResolvedValueOnce({ alerts: [] });
        const { result } = renderHook(() => useAnomalyAlerts(false), { wrapper: createWrapper().wrapper });
        await waitFor(() => expect(result.current.isSuccess).toBe(true));
        expect(mockAudit.getAnomalyAlerts).toHaveBeenCalledWith(false);
    });
});

describe('useAcknowledgeAnomaly', () => {
    it('acknowledges an alert and invalidates the anomalyAlerts query', async () => {
        mockAudit.acknowledgeAnomalyAlert.mockResolvedValueOnce({ acknowledged: true });
        const { wrapper, queryClient } = createWrapper();
        const invalidateSpy = vi.spyOn(queryClient, 'invalidateQueries');
        const { result } = renderHook(() => useAcknowledgeAnomaly(), { wrapper });

        act(() => {
            result.current.mutate(7);
        });
        await waitFor(() => expect(result.current.isSuccess).toBe(true));

        expect(mockAudit.acknowledgeAnomalyAlert).toHaveBeenCalledWith(7);
        expect(invalidateSpy).toHaveBeenCalledWith({ queryKey: ['anomalyAlerts'] });
    });
});

describe('useUsers / useUser', () => {
    it('fetches the users list with params', async () => {
        mockUsers.list.mockResolvedValueOnce({ items: [], total: 0 });
        const { result } = renderHook(() => useUsers({ search: 'bob' }), { wrapper: createWrapper().wrapper });
        await waitFor(() => expect(result.current.isSuccess).toBe(true));
        expect(mockUsers.list).toHaveBeenCalledWith({ search: 'bob' });
    });

    it('fetches a single user by id', async () => {
        mockUsers.get.mockResolvedValueOnce({ id: 3, username: 'alice' });
        const { result } = renderHook(() => useUser(3), { wrapper: createWrapper().wrapper });
        await waitFor(() => expect(result.current.isSuccess).toBe(true));
        expect(mockUsers.get).toHaveBeenCalledWith(3);
    });

    it('does not fetch when id <= 0', async () => {
        renderHook(() => useUser(0), { wrapper: createWrapper().wrapper });
        await act(async () => {});
        expect(mockUsers.get).not.toHaveBeenCalled();
    });

    it('does not fetch when enabled is false', async () => {
        renderHook(() => useUser(3, false), { wrapper: createWrapper().wrapper });
        await act(async () => {});
        expect(mockUsers.get).not.toHaveBeenCalled();
    });
});

describe('useGroups / useGroup', () => {
    it('fetches the groups list with params', async () => {
        mockGroups.list.mockResolvedValueOnce({ items: [], total: 0 });
        const { result } = renderHook(() => useGroups({ page: 2 }), { wrapper: createWrapper().wrapper });
        await waitFor(() => expect(result.current.isSuccess).toBe(true));
        expect(mockGroups.list).toHaveBeenCalledWith({ page: 2 });
    });

    it('fetches a single group by id', async () => {
        mockGroups.get.mockResolvedValueOnce({ id: 9, name: 'platform' });
        const { result } = renderHook(() => useGroup(9), { wrapper: createWrapper().wrapper });
        await waitFor(() => expect(result.current.isSuccess).toBe(true));
        expect(mockGroups.get).toHaveBeenCalledWith(9);
    });

    it('does not fetch when id <= 0', async () => {
        renderHook(() => useGroup(-1), { wrapper: createWrapper().wrapper });
        await act(async () => {});
        expect(mockGroups.get).not.toHaveBeenCalled();
    });
});
