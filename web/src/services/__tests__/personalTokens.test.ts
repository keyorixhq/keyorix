import { describe, it, expect, vi, beforeEach } from 'vitest';

// Mock the shared axios instance before importing the service under test.
vi.mock('../client', () => ({
    apiClient: {
        get: vi.fn(),
        post: vi.fn(),
        delete: vi.fn(),
    },
}));

import { apiClient } from '../client';
import { buildCreateTokenBody, personalTokensApi } from '../personalTokens';

const mocked = apiClient as unknown as {
    get: ReturnType<typeof vi.fn>;
    post: ReturnType<typeof vi.fn>;
    delete: ReturnType<typeof vi.fn>;
};

function ok<T>(data: T) {
    return { data: { data } };
}

beforeEach(() => vi.clearAllMocks());

// buildCreateTokenBody applies the ADR-042 least-privilege rules when assembling
// the create-token payload from the My Account form state.
describe('buildCreateTokenBody', () => {
    it('omits scopes/project for a full-access token', () => {
        const body = buildCreateTokenBody({
            name: 'ci',
            limited: false,
            permissions: ['secrets.read'], // ignored when not limited
            extraPermissions: 'secrets.write',
            projectScope: 5,
        });
        expect(body).toEqual({ name: 'ci' });
    });

    it('trims the name and serialises expiry to ISO', () => {
        const body = buildCreateTokenBody({
            name: '  ci  ',
            expiresAt: '2026-12-31',
            limited: false,
            permissions: [],
        });
        expect(body.name).toBe('ci');
        expect(body.expires_at).toBe(new Date('2026-12-31').toISOString());
    });

    it('includes the selected permissions when limited', () => {
        const body = buildCreateTokenBody({
            name: 'reader',
            limited: true,
            permissions: ['secrets.read'],
        });
        expect(body.scopes).toEqual(['secrets.read']);
        expect(body.project_scope).toBeUndefined();
    });

    it('merges preset + advanced permissions, trims, dedupes, drops blanks', () => {
        const body = buildCreateTokenBody({
            name: 't',
            limited: true,
            permissions: ['secrets.read'],
            extraPermissions: 'secrets.read, rotation.write   secrets.* , ',
        });
        // secrets.read deduped; comma/whitespace/newline split; blanks removed.
        expect(body.scopes).toEqual(['secrets.read', 'rotation.write', 'secrets.*']);
    });

    it('includes a project confinement only when > 0', () => {
        expect(buildCreateTokenBody({ name: 't', limited: true, permissions: [], projectScope: 7 }).project_scope).toBe(
            7
        );
        expect(
            buildCreateTokenBody({ name: 't', limited: true, permissions: ['secrets.read'], projectScope: 0 })
                .project_scope
        ).toBeUndefined();
    });

    it('includes an environment confinement only alongside a project', () => {
        // env scope only travels with a project (env ids belong to a project).
        const withEnv = buildCreateTokenBody({
            name: 't',
            limited: true,
            permissions: ['secrets.read'],
            projectScope: 7,
            environmentScope: 3,
        });
        expect(withEnv.project_scope).toBe(7);
        expect(withEnv.environment_scope).toBe(3);

        // An environment with no project is dropped.
        const envNoProject = buildCreateTokenBody({
            name: 't',
            limited: true,
            permissions: ['secrets.read'],
            projectScope: 0,
            environmentScope: 3,
        });
        expect(envNoProject.environment_scope).toBeUndefined();
    });

    it('omits the scopes key entirely when limited but nothing chosen (stays unrestricted)', () => {
        const body = buildCreateTokenBody({
            name: 't',
            limited: true,
            permissions: [],
            extraPermissions: '   ',
            projectScope: 0,
        });
        expect(body.scopes).toBeUndefined();
        expect(body.project_scope).toBeUndefined();
        expect(body).toEqual({ name: 't' });
    });
});

// ── personalTokensApi ─────────────────────────────────────────────────────────

describe('personalTokensApi.listTokens', () => {
    it('GETs the tokens route and returns the flat array', async () => {
        const tokens = [{ id: 1, name: 'ci', token_prefix: 'pat_abc' }];
        mocked.get.mockResolvedValueOnce(ok(tokens));

        const result = await personalTokensApi.listTokens();

        expect(mocked.get).toHaveBeenCalledWith('/api/v1/auth/tokens');
        expect(result).toEqual(tokens);
    });

    it('returns [] when the response payload is not an array', async () => {
        mocked.get.mockResolvedValueOnce(ok(null));

        await expect(personalTokensApi.listTokens()).resolves.toEqual([]);
    });
});

describe('personalTokensApi.createToken', () => {
    it('POSTs the body and returns the one-time token plus its metadata', async () => {
        const pat = { id: 1, name: 'ci', token_prefix: 'pat_abc' };
        mocked.post.mockResolvedValueOnce(ok({ token: 'pat_abc123secret', pat }));

        const result = await personalTokensApi.createToken({ name: 'ci' });

        expect(mocked.post).toHaveBeenCalledWith('/api/v1/auth/tokens', { name: 'ci' });
        expect(result).toEqual({ token: 'pat_abc123secret', pat });
    });
});

describe('personalTokensApi.revokeToken', () => {
    it('DELETEs the token endpoint', async () => {
        mocked.delete.mockResolvedValueOnce({});

        await personalTokensApi.revokeToken(7);

        expect(mocked.delete).toHaveBeenCalledWith('/api/v1/auth/tokens/7');
    });
});
