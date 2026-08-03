import { describe, it, expect, vi, beforeEach } from 'vitest';

vi.mock('../client', () => ({
    apiClient: {
        get: vi.fn(),
    },
}));

import { apiClient } from '../client';
import { groupsApi } from '../groups';

const mocked = apiClient as unknown as {
    get: ReturnType<typeof vi.fn>;
};

beforeEach(() => {
    vi.clearAllMocks();
});

describe('groupsApi.list', () => {
    it('hits the groups list endpoint with no params and unwraps the paginated payload', async () => {
        const paginated = {
            data: [
                { id: 1, name: 'engineering' },
                { id: 2, name: 'ops' },
            ],
            total: 2,
            page: 1,
            pageSize: 20,
            totalPages: 1,
        };
        mocked.get.mockResolvedValueOnce({ data: { data: paginated } });

        const result = await groupsApi.list();

        expect(mocked.get).toHaveBeenCalledWith('/api/v1/groups', { params: undefined });
        expect(result).toEqual(paginated);
    });

    it('forwards page/pageSize/search params through to the request', async () => {
        const paginated = { data: [], total: 0, page: 2, pageSize: 10, totalPages: 0 };
        mocked.get.mockResolvedValueOnce({ data: { data: paginated } });

        const params = { page: 2, pageSize: 10, search: 'eng' };
        const result = await groupsApi.list(params);

        expect(mocked.get).toHaveBeenCalledWith('/api/v1/groups', { params });
        expect(result).toEqual(paginated);
    });
});

describe('groupsApi.get', () => {
    it('hits the group-by-id endpoint and unwraps the group', async () => {
        const group = { id: 7, name: 'security', memberCount: 4 };
        mocked.get.mockResolvedValueOnce({ data: { data: group } });

        const result = await groupsApi.get(7);

        expect(mocked.get).toHaveBeenCalledWith('/api/v1/groups/7');
        expect(result).toEqual(group);
    });
});

describe('groupsApi.search', () => {
    it('hits the groups search endpoint with the query param and unwraps the recipient list', async () => {
        const recipients = [
            { id: 3, name: 'platform-team', type: 'group' },
            { id: 4, name: 'security-team', type: 'group', memberCount: 6 },
        ];
        mocked.get.mockResolvedValueOnce({ data: { data: recipients } });

        const result = await groupsApi.search('team');

        expect(mocked.get).toHaveBeenCalledWith('/api/v1/groups/search', { params: { q: 'team' } });
        expect(result).toEqual(recipients);
    });

    it('returns an empty array when no groups match', async () => {
        mocked.get.mockResolvedValueOnce({ data: { data: [] } });

        const result = await groupsApi.search('nonexistent');

        expect(mocked.get).toHaveBeenCalledWith('/api/v1/groups/search', { params: { q: 'nonexistent' } });
        expect(result).toEqual([]);
    });
});
