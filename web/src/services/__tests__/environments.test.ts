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
    it('maps Go-serialized ID/Name fields to lowercase id/name', async () => {
        mock.get.mockResolvedValueOnce({
            data: {
                data: {
                    environments: [
                        { ID: 1, Name: 'production' },
                        { ID: 2, Name: 'staging' },
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
