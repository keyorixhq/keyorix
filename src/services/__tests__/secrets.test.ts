import { describe, it, expect, vi, beforeEach } from 'vitest';

// Mock the shared axios instance before importing the service under test.
vi.mock('../client', () => ({
    apiClient: {
        get: vi.fn(),
        post: vi.fn(),
        put: vi.fn(),
        delete: vi.fn(),
    },
}));

import { apiClient } from '../client';
import { secretsApi } from '../secrets';

const mocked = apiClient as unknown as {
    get: ReturnType<typeof vi.fn>;
    post: ReturnType<typeof vi.fn>;
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
