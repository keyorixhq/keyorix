import { describe, it, expect, vi, beforeEach } from 'vitest';

// Mock the shared axios instance before importing the service under test.
vi.mock('../client', () => ({
    apiClient: {
        get: vi.fn(),
        post: vi.fn(),
        put: vi.fn(),
        patch: vi.fn(),
        delete: vi.fn(),
    },
}));

import { apiClient } from '../client';
import { secretsApi } from '../secrets';

const mocked = apiClient as unknown as {
    get: ReturnType<typeof vi.fn>;
    post: ReturnType<typeof vi.fn>;
    patch: ReturnType<typeof vi.fn>;
};

beforeEach(() => {
    vi.clearAllMocks();
});

describe('secretsApi.list', () => {
    it('maps LastRotatedAt → lastRotatedAt (null when never rotated)', async () => {
        mocked.get.mockResolvedValue({
            data: {
                data: {
                    secrets: [
                        { ID: 1, Name: 'rotated-key', Type: 'api_key', LastRotatedAt: '2026-05-01T00:00:00Z' },
                        { ID: 2, Name: 'never-key', Type: 'password' },
                    ],
                    total: 2,
                    page: 1,
                    page_size: 20,
                    total_pages: 1,
                },
            },
        });

        const out = await secretsApi.list();

        expect(out.data).toHaveLength(2);
        expect(out.data[0]).toMatchObject({ id: 1, name: 'rotated-key', lastRotatedAt: '2026-05-01T00:00:00Z' });
        expect(out.data[1].lastRotatedAt).toBeNull();
    });
});

describe('secretsApi.rotate', () => {
    it('POSTs the new value to the rotate endpoint', async () => {
        mocked.post.mockResolvedValue({ data: { data: { ID: 1 }, message: 'Secret rotated successfully' } });

        await secretsApi.rotate(1, 'new-secret-value');

        expect(mocked.post).toHaveBeenCalledWith('/api/v1/secrets/1/rotate', { new_value: 'new-secret-value' });
    });
});

describe('secretsApi usage analytics', () => {
    it('mostAccessed unwraps {data:{secrets}} and passes window/limit params', async () => {
        mocked.get.mockResolvedValue({
            data: {
                data: {
                    secrets: [{ secret_id: 1, secret_name: 'hot', read_count: 9, last_read: '2026-06-01T00:00:00Z' }],
                    days: 60,
                },
            },
        });

        const out = await secretsApi.mostAccessed({ days: 60, limit: 5 });

        expect(mocked.get).toHaveBeenCalledWith('/api/v1/secrets/usage/most-accessed', {
            params: { days: 60, limit: 5 },
        });
        expect(out).toHaveLength(1);
        expect(out[0]).toMatchObject({ secret_id: 1, read_count: 9 });
    });

    it('unused unwraps secrets and defaults to an empty array', async () => {
        mocked.get.mockResolvedValue({ data: { data: { secrets: null, days: 30 } } });

        const out = await secretsApi.unused({ days: 30 });

        expect(mocked.get).toHaveBeenCalledWith('/api/v1/secrets/usage/unused', { params: { days: 30 } });
        expect(out).toEqual([]);
    });
});

describe('secretsApi.risk', () => {
    it('fetches and unwraps the per-secret risk score', async () => {
        mocked.get.mockResolvedValue({
            data: {
                data: {
                    secret_id: 7,
                    secret_name: 'k',
                    score: 72,
                    band: 'high',
                    factors: [{ key: 'expiry', label: 'Expiry', score: 100, weight: 0.3, detail: 'Expired' }],
                },
            },
        });

        const out = await secretsApi.risk(7);

        expect(mocked.get).toHaveBeenCalledWith('/api/v1/secrets/7/risk');
        expect(out).toMatchObject({ secret_id: 7, score: 72, band: 'high' });
        expect(out.factors).toHaveLength(1);
    });
});

describe('secretsApi.setAutoRotate', () => {
    it('PATCHes the full auto-rotate payload (with defaults filled)', async () => {
        mocked.patch.mockResolvedValue({ data: { message: 'ok' } });
        await secretsApi.setAutoRotate(7, { enabled: true });
        expect(mocked.patch).toHaveBeenCalledWith('/api/v1/secrets/7/auto-rotate', {
            enabled: true,
            length: 0,
            charset: '',
            backend: '',
            ref: '',
        });
    });

    it('passes a backend + ref + generator spec through', async () => {
        mocked.patch.mockResolvedValue({ data: { message: 'ok' } });
        await secretsApi.setAutoRotate(9, {
            enabled: true,
            length: 24,
            charset: 'hex',
            backend: 'prod-pg',
            ref: 'app_svc',
        });
        expect(mocked.patch).toHaveBeenCalledWith('/api/v1/secrets/9/auto-rotate', {
            enabled: true,
            length: 24,
            charset: 'hex',
            backend: 'prod-pg',
            ref: 'app_svc',
        });
    });
});
