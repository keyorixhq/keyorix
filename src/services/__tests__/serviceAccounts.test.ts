import { describe, it, expect, vi, beforeEach } from 'vitest';

vi.mock('../client', () => ({
    apiClient: {
        get:    vi.fn(),
        post:   vi.fn(),
        put:    vi.fn(),
        delete: vi.fn(),
    },
}));

import { apiClient } from '../client';
import { serviceAccountsApi } from '../serviceAccounts';

const mock = apiClient as unknown as {
    get:    ReturnType<typeof vi.fn>;
    post:   ReturnType<typeof vi.fn>;
    put:    ReturnType<typeof vi.fn>;
    delete: ReturnType<typeof vi.fn>;
};

function ok<T>(data: T) {
    return { data: { data } };
}

beforeEach(() => vi.clearAllMocks());

// ── listServiceAccounts ───────────────────────────────────────────────────────

describe('serviceAccountsApi.listServiceAccounts', () => {
    it('returns a flat array when the backend sends one', async () => {
        const sa = [{ id: 1, name: 'ci-bot' }];
        mock.get.mockResolvedValueOnce(ok(sa));
        await expect(serviceAccountsApi.listServiceAccounts()).resolves.toEqual(sa);
        expect(mock.get).toHaveBeenCalledWith('/api/v1/service-accounts');
    });

    it('unwraps the {service_accounts: [...]} wrapper shape', async () => {
        const sa = [{ id: 2, name: 'deploy-bot' }];
        mock.get.mockResolvedValueOnce(ok({ service_accounts: sa }));
        await expect(serviceAccountsApi.listServiceAccounts()).resolves.toEqual(sa);
    });

    it('returns [] for null data', async () => {
        mock.get.mockResolvedValueOnce(ok(null));
        await expect(serviceAccountsApi.listServiceAccounts()).resolves.toEqual([]);
    });
});

// ── createServiceAccount ──────────────────────────────────────────────────────

describe('serviceAccountsApi.createServiceAccount', () => {
    const body = { name: 'ci-bot', description: 'CI runner', scopes: 'secrets:read' };

    it('returns service_account and client_secret from a direct response', async () => {
        const sa = { id: 1, name: 'ci-bot' };
        mock.post.mockResolvedValueOnce(ok({ service_account: sa, client_secret: 'secret-value' }));
        const result = await serviceAccountsApi.createServiceAccount(body);
        expect(result).toEqual({ service_account: sa, client_secret: 'secret-value' });
        expect(mock.post).toHaveBeenCalledWith('/api/v1/service-accounts', body);
    });

    it('returns empty client_secret when not present', async () => {
        const sa = { id: 2, name: 'deploy-bot' };
        mock.post.mockResolvedValueOnce(ok(sa));
        const result = await serviceAccountsApi.createServiceAccount(body);
        expect(result.client_secret).toBe('');
        expect(result.service_account).toMatchObject({ id: 2 });
    });
});

// ── updateServiceAccount ──────────────────────────────────────────────────────

describe('serviceAccountsApi.updateServiceAccount', () => {
    it('sends a PUT and returns the updated service account', async () => {
        const sa = { id: 1, name: 'ci-bot-v2' };
        mock.put.mockResolvedValueOnce(ok({ service_account: sa }));
        const result = await serviceAccountsApi.updateServiceAccount(1, { name: 'ci-bot-v2' });
        expect(mock.put).toHaveBeenCalledWith('/api/v1/service-accounts/1', { name: 'ci-bot-v2' });
        expect(result).toEqual(sa);
    });

    it('handles a direct (non-wrapped) response', async () => {
        const sa = { id: 3, name: 'direct-bot' };
        mock.put.mockResolvedValueOnce(ok(sa));
        await expect(serviceAccountsApi.updateServiceAccount(3, { name: 'direct-bot' })).resolves.toEqual(sa);
    });
});

// ── deactivateServiceAccount ──────────────────────────────────────────────────

describe('serviceAccountsApi.deactivateServiceAccount', () => {
    it('calls DELETE on the service account endpoint', async () => {
        mock.delete.mockResolvedValueOnce({});
        await serviceAccountsApi.deactivateServiceAccount(5);
        expect(mock.delete).toHaveBeenCalledWith('/api/v1/service-accounts/5');
    });
});

// ── listTokens ────────────────────────────────────────────────────────────────

describe('serviceAccountsApi.listTokens', () => {
    it('returns flat array of tokens', async () => {
        const tokens = [{ id: 1, description: 'prod' }];
        mock.get.mockResolvedValueOnce(ok(tokens));
        await expect(serviceAccountsApi.listTokens(1)).resolves.toEqual(tokens);
        expect(mock.get).toHaveBeenCalledWith('/api/v1/service-accounts/1/tokens');
    });

    it('unwraps {tokens: [...]} wrapper shape', async () => {
        const tokens = [{ id: 2, description: 'ci' }];
        mock.get.mockResolvedValueOnce(ok({ tokens }));
        await expect(serviceAccountsApi.listTokens(1)).resolves.toEqual(tokens);
    });
});

// ── createToken ───────────────────────────────────────────────────────────────

describe('serviceAccountsApi.createToken', () => {
    const body = { description: 'ci token', expires_at: '2027-01-01T00:00:00Z' };

    it('extracts access_token from token_value field', async () => {
        const token = { id: 1, description: 'ci token' };
        mock.post.mockResolvedValueOnce(ok({ token, token_value: 'tok-abc' }));
        const result = await serviceAccountsApi.createToken(1, body);
        expect(result.access_token).toBe('tok-abc');
        expect(result.token).toEqual(token);
    });

    it('extracts access_token from access_token field', async () => {
        const token = { id: 2, description: 'ci token' };
        mock.post.mockResolvedValueOnce(ok({ token, access_token: 'tok-def' }));
        const result = await serviceAccountsApi.createToken(1, body);
        expect(result.access_token).toBe('tok-def');
    });

    it('extracts access_token from plain_token field', async () => {
        const token = { id: 3, description: 'ci token' };
        mock.post.mockResolvedValueOnce(ok({ token, plain_token: 'tok-ghi' }));
        const result = await serviceAccountsApi.createToken(1, body);
        expect(result.access_token).toBe('tok-ghi');
    });

    it('returns empty string when no token value field is present', async () => {
        const token = { id: 4, description: 'ci token' };
        mock.post.mockResolvedValueOnce(ok({ token }));
        const result = await serviceAccountsApi.createToken(1, body);
        expect(result.access_token).toBe('');
    });

    it('posts to the correct URL', async () => {
        mock.post.mockResolvedValueOnce(ok({ token: {}, token_value: 'x' }));
        await serviceAccountsApi.createToken(7, body);
        expect(mock.post).toHaveBeenCalledWith('/api/v1/service-accounts/7/tokens', body);
    });
});

// ── revokeToken ───────────────────────────────────────────────────────────────

describe('serviceAccountsApi.revokeToken', () => {
    it('calls DELETE on the token endpoint', async () => {
        mock.delete.mockResolvedValueOnce({});
        await serviceAccountsApi.revokeToken(99);
        expect(mock.delete).toHaveBeenCalledWith('/api/v1/tokens/99');
    });
});
