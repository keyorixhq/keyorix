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

describe('systemApi.getAuthConfig', () => {
    it('returns the auth config payload', async () => {
        const authConfig = { require_mfa: true, session: { access_ttl: '15m', absolute_ttl: '24h' } };
        mock.get.mockResolvedValueOnce({ data: { data: authConfig } });
        const result = await systemApi.getAuthConfig();
        expect(mock.get).toHaveBeenCalledWith('/api/v1/system/auth-config');
        expect(result).toEqual(authConfig);
    });
});

describe('systemApi.getEncryptionConfig', () => {
    it('returns the encryption config payload', async () => {
        const encryptionConfig = { enabled: true, key_provider: { type: 'shamir', fallback_count: 2 } };
        mock.get.mockResolvedValueOnce({ data: { data: encryptionConfig } });
        const result = await systemApi.getEncryptionConfig();
        expect(mock.get).toHaveBeenCalledWith('/api/v1/system/encryption-config');
        expect(result).toEqual(encryptionConfig);
    });
});
