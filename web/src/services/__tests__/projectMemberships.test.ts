import { describe, it, expect, vi, beforeEach } from 'vitest';

// Mock the shared axios instance before importing the service under test.
vi.mock('../client', () => ({
    apiClient: {
        get: vi.fn(),
        put: vi.fn(),
    },
}));

import { apiClient } from '../client';
import { projectMembershipsApi } from '../projectMemberships';

const mocked = apiClient as unknown as {
    get: ReturnType<typeof vi.fn>;
    put: ReturnType<typeof vi.fn>;
};

beforeEach(() => {
    vi.clearAllMocks();
});

describe('projectMembershipsApi.list', () => {
    it('GETs the memberships route and normalizes PascalCase Go-serialized fields', async () => {
        mocked.get.mockResolvedValue({
            data: {
                data: {
                    memberships: [
                        {
                            ID: 5,
                            ProjectID: 3,
                            UserID: 42,
                            Role: 'project_developer',
                            State: 'active',
                            InvitedAt: '2026-05-01T00:00:00Z',
                            ActivatedAt: '2026-05-03T00:00:00Z',
                        },
                    ],
                },
            },
        });

        const result = await projectMembershipsApi.list(3);

        expect(mocked.get).toHaveBeenCalledWith('/api/v1/projects/3/memberships');
        expect(result).toEqual([
            {
                id: 5,
                projectId: 3,
                userId: 42,
                role: 'project_developer',
                state: 'active',
                invitedAt: '2026-05-01T00:00:00Z',
                activatedAt: '2026-05-03T00:00:00Z',
                revokedAt: undefined,
            },
        ]);
    });

    it('falls back to snake_case/camelCase fields when PascalCase is absent', async () => {
        mocked.get.mockResolvedValue({
            data: {
                data: {
                    memberships: [
                        {
                            id: 6,
                            project_id: 3,
                            user_id: 43,
                            role: 'project_viewer',
                            state: 'invited',
                            invited_at: '2026-05-02T00:00:00Z',
                        },
                    ],
                },
            },
        });

        const result = await projectMembershipsApi.list(3);

        expect(result[0]).toEqual({
            id: 6,
            projectId: 3,
            userId: 43,
            role: 'project_viewer',
            state: 'invited',
            invitedAt: '2026-05-02T00:00:00Z',
            activatedAt: undefined,
            revokedAt: undefined,
        });
    });

    it('falls back to response.data.memberships when response.data.data is absent', async () => {
        mocked.get.mockResolvedValue({
            data: {
                memberships: [{ ID: 1, ProjectID: 2, UserID: 9, Role: 'project_admin', State: 'provisioned' }],
            },
        });

        const result = await projectMembershipsApi.list(2);

        expect(result).toEqual([
            {
                id: 1,
                projectId: 2,
                userId: 9,
                role: 'project_admin',
                state: 'provisioned',
                invitedAt: undefined,
                activatedAt: undefined,
                revokedAt: undefined,
            },
        ]);
    });

    it('returns [] when no memberships key is present anywhere in the payload', async () => {
        mocked.get.mockResolvedValue({ data: { data: {} } });
        await expect(projectMembershipsApi.list(1)).resolves.toEqual([]);
    });

    it('falls back to bare camelCase projectId/userId when neither PascalCase nor snake_case is present', async () => {
        mocked.get.mockResolvedValue({
            data: {
                data: {
                    memberships: [{ id: 9, projectId: 4, userId: 44, role: 'project_admin', state: 'active' }],
                },
            },
        });

        const result = await projectMembershipsApi.list(4);

        expect(result[0]).toMatchObject({ id: 9, projectId: 4, userId: 44 });
    });

    it('defaults role to empty string and state to "invited" when both are missing', async () => {
        mocked.get.mockResolvedValue({
            data: { data: { memberships: [{ ID: 8, ProjectID: 1, UserID: 2 }] } },
        });

        const result = await projectMembershipsApi.list(1);

        expect(result[0]).toMatchObject({ role: '', state: 'invited' });
    });
});

describe('projectMembershipsApi.transition', () => {
    it('PUTs the action and normalizes the returned membership from {data:{membership}}', async () => {
        mocked.put.mockResolvedValue({
            data: {
                data: {
                    membership: {
                        ID: 5,
                        ProjectID: 3,
                        UserID: 42,
                        Role: 'project_developer',
                        State: 'identity_verified',
                    },
                },
            },
        });

        const result = await projectMembershipsApi.transition(3, 5, 'verify');

        expect(mocked.put).toHaveBeenCalledWith('/api/v1/projects/3/memberships/5', { action: 'verify' });
        expect(result).toEqual({
            id: 5,
            projectId: 3,
            userId: 42,
            role: 'project_developer',
            state: 'identity_verified',
            invitedAt: undefined,
            activatedAt: undefined,
            revokedAt: undefined,
        });
    });

    it('falls back to response.data.membership when response.data.data is absent', async () => {
        mocked.put.mockResolvedValue({
            data: { membership: { ID: 5, ProjectID: 3, UserID: 42, Role: 'project_developer', State: 'provisioned' } },
        });

        const result = await projectMembershipsApi.transition(3, 5, 'provision');

        expect(result.state).toBe('provisioned');
    });

    it('falls back to response.data itself when neither data.membership nor membership is present', async () => {
        mocked.put.mockResolvedValue({
            data: { ID: 5, ProjectID: 3, UserID: 42, Role: 'project_developer', State: 'active' },
        });

        const result = await projectMembershipsApi.transition(3, 5, 'activate');

        expect(result.state).toBe('active');
    });

    it('sends the revoke action and normalizes revokedAt', async () => {
        mocked.put.mockResolvedValue({
            data: {
                data: {
                    membership: {
                        ID: 5,
                        ProjectID: 3,
                        UserID: 42,
                        Role: 'project_developer',
                        State: 'revoked',
                        RevokedAt: '2026-06-01T00:00:00Z',
                    },
                },
            },
        });

        const result = await projectMembershipsApi.transition(3, 5, 'revoke');

        expect(mocked.put).toHaveBeenCalledWith('/api/v1/projects/3/memberships/5', { action: 'revoke' });
        expect(result.state).toBe('revoked');
        expect(result.revokedAt).toBe('2026-06-01T00:00:00Z');
    });
});
