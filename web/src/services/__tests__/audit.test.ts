import { describe, it, expect, vi, beforeEach } from 'vitest';

vi.mock('../client', () => ({
    apiClient: {
        get: vi.fn(),
        post: vi.fn(),
    },
}));

import { apiClient } from '../client';
import { auditApi } from '../audit';

const mock = apiClient as unknown as {
    get: ReturnType<typeof vi.fn>;
    post: ReturnType<typeof vi.fn>;
};

beforeEach(() => vi.clearAllMocks());

// ── getAnomalyAlerts ─────────────────────────────────────────────────────────

describe('auditApi.getAnomalyAlerts', () => {
    it('defaults to unacknowledged-only when called with no arguments', async () => {
        mock.get.mockResolvedValueOnce({ data: { alerts: [] } });
        const result = await auditApi.getAnomalyAlerts();
        expect(mock.get).toHaveBeenCalledWith('/api/v1/audit/anomalies?unacknowledged=true');
        expect(result).toEqual({ alerts: [] });
    });

    it('appends the unacknowledged filter when explicitly true', async () => {
        mock.get.mockResolvedValueOnce({ data: { alerts: [] } });
        await auditApi.getAnomalyAlerts(true);
        expect(mock.get).toHaveBeenCalledWith('/api/v1/audit/anomalies?unacknowledged=true');
    });

    it('omits the filter when explicitly false', async () => {
        mock.get.mockResolvedValueOnce({ data: { alerts: [] } });
        await auditApi.getAnomalyAlerts(false);
        expect(mock.get).toHaveBeenCalledWith('/api/v1/audit/anomalies');
    });
});

// ── acknowledgeAnomalyAlert ──────────────────────────────────────────────────

describe('auditApi.acknowledgeAnomalyAlert', () => {
    it('POSTs to the acknowledge endpoint for the given alert id', async () => {
        mock.post.mockResolvedValueOnce({ data: { acknowledged: true } });
        const result = await auditApi.acknowledgeAnomalyAlert(7);
        expect(mock.post).toHaveBeenCalledWith('/api/v1/audit/anomalies/7/acknowledge');
        expect(result).toEqual({ acknowledged: true });
    });
});
