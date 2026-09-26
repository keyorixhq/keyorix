import { describe, it, expect, vi, beforeEach } from 'vitest';

vi.mock('../client', () => ({
    apiClient: {
        get: vi.fn(),
    },
}));

import { apiClient } from '../client';
import { environmentsApi } from '../environments';

const mock = apiClient as unknown as {
    get: ReturnType<typeof vi.fn>;
};

beforeEach(() => vi.clearAllMocks());

describe('environmentsApi.list', () => {
    it('maps the snake_case wire fields to id/name', async () => {
        mock.get.mockResolvedValueOnce({
            data: {
                data: {
                    environments: [
                        { id: 1, name: 'production' },
                        { id: 2, name: 'staging' },
                    ],
                },
            },
        });
        const result = await environmentsApi.list();
        expect(mock.get).toHaveBeenCalledWith('/api/v1/environments');
        expect(result).toEqual([
            { id: 1, name: 'production' },
            { id: 2, name: 'staging' },
        ]);
    });

    it('returns [] when environments is missing', async () => {
        mock.get.mockResolvedValueOnce({ data: { data: {} } });
        await expect(environmentsApi.list()).resolves.toEqual([]);
    });
});
