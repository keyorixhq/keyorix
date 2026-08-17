import { describe, it, expect, vi, beforeEach } from 'vitest';

vi.mock('../client', () => ({
    apiClient: {
        get: vi.fn(),
        post: vi.fn(),
        delete: vi.fn(),
    },
}));

import { apiClient } from '../client';
import { connectApi } from '../connect';

const mock = apiClient as unknown as {
    get: ReturnType<typeof vi.fn>;
    post: ReturnType<typeof vi.fn>;
    delete: ReturnType<typeof vi.fn>;
};

beforeEach(() => vi.clearAllMocks());

// ── listConnectors ───────────────────────────────────────────────────────────

describe('connectApi.listConnectors', () => {
    it('returns the connectors array', async () => {
        mock.get.mockResolvedValueOnce({ data: { data: { connectors: ['vault', 'aws-sm'] } } });
        const result = await connectApi.listConnectors();
        expect(mock.get).toHaveBeenCalledWith('/api/v1/connect/connectors');
        expect(result).toEqual(['vault', 'aws-sm']);
    });

    it('returns [] when connectors is missing', async () => {
        mock.get.mockResolvedValueOnce({ data: { data: {} } });
        await expect(connectApi.listConnectors()).resolves.toEqual([]);
    });
});

// ── readSecret ────────────────────────────────────────────────────────────────

describe('connectApi.readSecret', () => {
    it('POSTs the ref in the request body, not the URL, with a URL-encoded connector', async () => {
        const secret = { connector: 'vault/prod', ref: 'db/password', value: 'hunter2' };
        mock.post.mockResolvedValueOnce({ data: { data: secret } });
        const result = await connectApi.readSecret('vault/prod', 'db/password');
        expect(mock.post).toHaveBeenCalledWith('/api/v1/connect/vault%2Fprod/secret:read', {
            ref: 'db/password',
        });
        expect(mock.get).not.toHaveBeenCalled();
        expect(result).toEqual(secret);
    });
});

// ── listRefGrants ─────────────────────────────────────────────────────────────

describe('connectApi.listRefGrants', () => {
    it('returns the grants array', async () => {
        const grants = [{ id: 1, role_id: 2, connector: 'vault', ref_prefix: 'db/' }];
        mock.get.mockResolvedValueOnce({ data: { data: { grants } } });
        const result = await connectApi.listRefGrants();
        expect(mock.get).toHaveBeenCalledWith('/api/v1/connect/ref-grants');
        expect(result).toEqual(grants);
    });

    it('returns [] when grants is missing', async () => {
        mock.get.mockResolvedValueOnce({ data: { data: {} } });
        await expect(connectApi.listRefGrants()).resolves.toEqual([]);
    });
});

// ── createRefGrant ────────────────────────────────────────────────────────────

describe('connectApi.createRefGrant', () => {
    it('POSTs the grant with snake_case fields and returns the created grant', async () => {
        const grant = { id: 5, role_id: 2, connector: 'vault', ref_prefix: 'db/*' };
        mock.post.mockResolvedValueOnce({ data: { data: grant } });
        const result = await connectApi.createRefGrant(2, 'vault', 'db/*');
        expect(mock.post).toHaveBeenCalledWith('/api/v1/connect/ref-grants', {
            role_id: 2,
            connector: 'vault',
            ref_prefix: 'db/*',
        });
        expect(result).toEqual(grant);
    });
});

// ── deleteRefGrant ────────────────────────────────────────────────────────────

describe('connectApi.deleteRefGrant', () => {
    it('DELETEs the grant by id', async () => {
        mock.delete.mockResolvedValueOnce({ data: {} });
        await connectApi.deleteRefGrant(5);
        expect(mock.delete).toHaveBeenCalledWith('/api/v1/connect/ref-grants/5');
    });
});
