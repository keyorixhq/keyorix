import { describe, it, expect, vi, beforeEach } from 'vitest';

vi.mock('../client', () => ({
    apiClient: {
        get: vi.fn(),
    },
}));

import { apiClient } from '../client';
import { systemApi } from '../system';

const mock = apiClient as unknown as {
    get: ReturnType<typeof vi.fn>;
};

beforeEach(() => vi.clearAllMocks());

describe('systemApi.getInfo', () => {
    it('returns the info payload', async () => {
        const info = { version: '1.2.3', go_version: 'go1.23' };
        mock.get.mockResolvedValueOnce({ data: { data: info } });
        const result = await systemApi.getInfo();
        expect(mock.get).toHaveBeenCalledWith('/api/v1/system/info');
        expect(result).toEqual(info);
    });
});

describe('systemApi.getMetrics', () => {
    it('returns the metrics payload', async () => {
        const metrics = { uptime_seconds: 12345, goroutines: 42 };
        mock.get.mockResolvedValueOnce({ data: { data: metrics } });
        const result = await systemApi.getMetrics();
        expect(mock.get).toHaveBeenCalledWith('/api/v1/system/metrics');
        expect(result).toEqual(metrics);
    });
});
