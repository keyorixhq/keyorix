import { describe, it, expect, vi, beforeEach } from 'vitest';

vi.mock('../client', () => ({
    apiClient: {
        get: vi.fn(),
    },
}));

import { apiClient } from '../client';
import { dashboardApi } from '../dashboard';

const mock = apiClient as unknown as {
    get: ReturnType<typeof vi.fn>;
};

beforeEach(() => vi.clearAllMocks());

// ── getStats ──────────────────────────────────────────────────────────────────

describe('dashboardApi.getStats', () => {
    it('returns the stats payload', async () => {
        const stats = { total_secrets: 10 };
        mock.get.mockResolvedValueOnce({ data: { data: stats } });
        const result = await dashboardApi.getStats();
        expect(mock.get).toHaveBeenCalledWith('/api/v1/dashboard/stats');
        expect(result).toEqual(stats);
    });
});

// ── getActivity ───────────────────────────────────────────────────────────────

describe('dashboardApi.getActivity', () => {
    it('maps the feed into a paginated response and forwards params', async () => {
        mock.get.mockResolvedValueOnce({
            data: { data: { items: [{ id: 1 }], total: 25, page: 2, pageSize: 10 } },
        });
        const result = await dashboardApi.getActivity({ page: 2, pageSize: 10, type: 'secret.read' });
        expect(mock.get).toHaveBeenCalledWith('/api/v1/dashboard/activity', {
            params: { page: 2, pageSize: 10, type: 'secret.read' },
        });
        expect(result).toEqual({ data: [{ id: 1 }], total: 25, page: 2, pageSize: 10, totalPages: 3 });
    });

    it('defaults items/total/page/pageSize when the feed omits them', async () => {
        mock.get.mockResolvedValueOnce({ data: { data: {} } });
        const result = await dashboardApi.getActivity();
        expect(mock.get).toHaveBeenCalledWith('/api/v1/dashboard/activity', { params: undefined });
        expect(result).toEqual({ data: [], total: 0, page: 1, pageSize: 10, totalPages: 1 });
    });

    it('computes totalPages as at least 1 even when total is 0', async () => {
        mock.get.mockResolvedValueOnce({ data: { data: { items: [], total: 0, page: 1, pageSize: 5 } } });
        const result = await dashboardApi.getActivity();
        expect(result.totalPages).toBe(1);
    });

    it('rounds totalPages up for a partial last page', async () => {
        mock.get.mockResolvedValueOnce({ data: { data: { items: [], total: 21, page: 1, pageSize: 10 } } });
        const result = await dashboardApi.getActivity();
        expect(result.totalPages).toBe(3);
    });
});
