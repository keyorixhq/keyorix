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
import { projectInvitationsApi } from '../projectInvitations';

const mocked = apiClient as unknown as {
    get: ReturnType<typeof vi.fn>;
    post: ReturnType<typeof vi.fn>;
    put: ReturnType<typeof vi.fn>;
    delete: ReturnType<typeof vi.fn>;
};

beforeEach(() => {
    vi.clearAllMocks();
});

describe('projectInvitationsApi.listInvitations', () => {
    it('unwraps {data:{invitations}} and normalizes PascalCase keys', async () => {
        mocked.get.mockResolvedValue({
            data: {
                data: {
                    invitations: [
                        {
                            ID: 7,
                            ProjectID: 3,
                            Email: 'bob@example.com',
                            Role: 'project_editor',
                            State: 'pending',
                            InvitedBy: 1,
                            ExpiresAt: '2026-06-19T00:00:00Z',
                            CreatedAt: '2026-06-05T00:00:00Z',
                        },
                    ],
                },
            },
        });

        const out = await projectInvitationsApi.listInvitations(3);

        expect(mocked.get).toHaveBeenCalledWith('/api/v1/projects/3/invitations');
        expect(out).toHaveLength(1);
        expect(out[0]).toMatchObject({
            id: 7,
            projectId: 3,
            email: 'bob@example.com',
            role: 'project_editor',
            state: 'pending',
            invitedBy: 1,
            expiresAt: '2026-06-19T00:00:00Z',
        });
    });

    it('returns [] when the payload has no invitations', async () => {
        mocked.get.mockResolvedValue({ data: { data: {} } });
        expect(await projectInvitationsApi.listInvitations(1)).toEqual([]);
    });

    it('normalizes snake_case/camelCase fields and defaults a sparse invitation', async () => {
        mocked.get.mockResolvedValue({
            data: {
                data: {
                    invitations: [
                        {
                            id: 8,
                            project_id: 4,
                            email: 'sam@x.io',
                            role: 'project_viewer',
                            state: 'accepted',
                            invitedBy: 2,
                            expiresAt: '2026-07-01T00:00:00Z',
                            createdAt: '2026-06-01T00:00:00Z',
                        },
                        {},
                    ],
                },
            },
        });

        const out = await projectInvitationsApi.listInvitations(4);

        expect(out[0]).toMatchObject({
            id: 8,
            projectId: 4,
            email: 'sam@x.io',
            role: 'project_viewer',
            state: 'accepted',
            invitedBy: 2,
            expiresAt: '2026-07-01T00:00:00Z',
            createdAt: '2026-06-01T00:00:00Z',
        });
        expect(out[1]).toMatchObject({
            email: '',
            role: '',
            state: '',
            invitedBy: 0,
            expiresAt: undefined,
            createdAt: undefined,
        });
    });

    it('falls back to bare data.invitations when data.data is absent', async () => {
        mocked.get.mockResolvedValue({ data: { invitations: [{ id: 1, email: 'bare@x.io' }] } });
        const out = await projectInvitationsApi.listInvitations(1);
        expect(out[0]).toMatchObject({ id: 1, email: 'bare@x.io' });
    });
});

describe('projectInvitationsApi.createInvitation', () => {
    it('posts email+role and unwraps {data:{invitation}}', async () => {
        mocked.post.mockResolvedValue({
            data: {
                data: {
                    invitation: { ID: 9, ProjectID: 2, Email: 'a@b.com', Role: 'project_viewer', State: 'pending' },
                },
            },
        });

        const inv = await projectInvitationsApi.createInvitation(2, 'a@b.com', 'project_viewer');

        expect(mocked.post).toHaveBeenCalledWith('/api/v1/projects/2/invitations', {
            email: 'a@b.com',
            role: 'project_viewer',
        });
        expect(inv).toMatchObject({ id: 9, email: 'a@b.com', role: 'project_viewer' });
    });

    it('falls back to data.data when the invitation key is absent', async () => {
        mocked.post.mockResolvedValue({ data: { data: { ID: 10, Email: 'no-wrapper@b.com' } } });
        const inv = await projectInvitationsApi.createInvitation(2, 'no-wrapper@b.com', 'project_viewer');
        expect(inv).toMatchObject({ id: 10, email: 'no-wrapper@b.com' });
    });

    it('falls back to bare response.data when data.data is absent', async () => {
        mocked.post.mockResolvedValue({ data: { ID: 11, Email: 'bare@b.com' } });
        const inv = await projectInvitationsApi.createInvitation(2, 'bare@b.com', 'project_viewer');
        expect(inv).toMatchObject({ id: 11, email: 'bare@b.com' });
    });
});

describe('projectInvitationsApi.createGlobal', () => {
    it('posts email + system role + assignments and unwraps {invitation, setup_link}', async () => {
        mocked.post.mockResolvedValue({
            data: {
                data: {
                    invitation: { ID: 12, ProjectID: 0, Email: 'carol@x.io', State: 'pending' },
                    setup_link: {
                        email: 'carol@x.io',
                        channel: 'out_of_band',
                        delivered: false,
                        link_for_admin: 'https://k/x/abc',
                    },
                },
            },
        });

        const res = await projectInvitationsApi.createGlobal('carol@x.io', 'system_auditor', [
            { project_id: 1, role: 'project_developer' },
        ]);

        expect(mocked.post).toHaveBeenCalledWith('/api/v1/invitations', {
            email: 'carol@x.io',
            role: 'system_auditor',
            project_assignments: [{ project_id: 1, role: 'project_developer' }],
        });
        expect(res.invitation).toMatchObject({ id: 12, projectId: 0, email: 'carol@x.io', state: 'pending' });
        expect(res.setup_link?.link_for_admin).toBe('https://k/x/abc');
    });

    it('omits role and project_assignments when empty (backend defaults apply)', async () => {
        mocked.post.mockResolvedValue({
            data: { data: { invitation: { ID: 13, Email: 'd@x.io', State: 'pending' } } },
        });

        await projectInvitationsApi.createGlobal('d@x.io', '', []);

        expect(mocked.post).toHaveBeenCalledWith('/api/v1/invitations', { email: 'd@x.io' });
    });

    it('surfaces delivery_error when the link could not be sent', async () => {
        mocked.post.mockResolvedValue({
            data: {
                data: { invitation: { ID: 14, Email: 'e@x.io', State: 'pending' }, delivery_error: 'base_url unset' },
            },
        });

        const res = await projectInvitationsApi.createGlobal('e@x.io', '', []);
        expect(res.setup_link).toBeUndefined();
        expect(res.delivery_error).toBe('base_url unset');
    });

    it('falls back to bare response.data when data.data is absent', async () => {
        mocked.post.mockResolvedValue({ data: { ID: 15, Email: 'bare@x.io', State: 'pending' } });

        const res = await projectInvitationsApi.createGlobal('bare@x.io', '', []);

        expect(res.invitation).toMatchObject({ id: 15, email: 'bare@x.io' });
    });

    it('defaults to {} (empty invitation) when response.data itself is absent', async () => {
        mocked.post.mockResolvedValue({});

        const res = await projectInvitationsApi.createGlobal('none@x.io', '', []);

        expect(res.invitation).toMatchObject({ email: '', state: '' });
    });
});

describe('projectInvitationsApi.listAccessRequests', () => {
    it('unwraps {data:{access_requests}} and normalizes UserID/SuggestedRole', async () => {
        mocked.get.mockResolvedValue({
            data: {
                data: {
                    access_requests: [
                        {
                            ID: 4,
                            ProjectID: 3,
                            UserID: 42,
                            SuggestedRole: 'project_viewer',
                            GrantedRole: '',
                            State: 'pending',
                            Reason: 'need read access',
                        },
                    ],
                },
            },
        });

        const out = await projectInvitationsApi.listAccessRequests(3);

        expect(mocked.get).toHaveBeenCalledWith('/api/v1/projects/3/access-requests');
        expect(out[0]).toMatchObject({
            id: 4,
            userId: 42,
            suggestedRole: 'project_viewer',
            state: 'pending',
            reason: 'need read access',
        });
    });

    it('normalizes snake_case fields (no PascalCase present) and defaults unset fields', async () => {
        mocked.get.mockResolvedValue({
            data: {
                data: {
                    access_requests: [
                        {
                            id: 10,
                            project_id: 3,
                            user_id: 42,
                            suggested_role: 'project_viewer',
                            granted_role: 'project_developer',
                            state: 'approved',
                            reason: 'ok',
                        },
                    ],
                },
            },
        });

        const out = await projectInvitationsApi.listAccessRequests(3);

        expect(out[0]).toMatchObject({
            id: 10,
            projectId: 3,
            userId: 42,
            suggestedRole: 'project_viewer',
            grantedRole: 'project_developer',
            state: 'approved',
            reason: 'ok',
        });
    });

    it('falls back to bare data.access_requests, and to [] when neither wrapper is present', async () => {
        mocked.get.mockResolvedValueOnce({ data: { access_requests: [{ id: 1 }] } });
        const bare = await projectInvitationsApi.listAccessRequests(3);
        expect(bare).toHaveLength(1);

        mocked.get.mockResolvedValueOnce({ data: {} });
        await expect(projectInvitationsApi.listAccessRequests(3)).resolves.toEqual([]);
    });
});

describe('projectInvitationsApi.resolveAccessRequest', () => {
    it('approve sends action + granted_role', async () => {
        mocked.put.mockResolvedValue({ data: {} });
        await projectInvitationsApi.resolveAccessRequest(3, 4, 'approve', 'project_developer');
        expect(mocked.put).toHaveBeenCalledWith('/api/v1/projects/3/access-requests/4', {
            action: 'approve',
            granted_role: 'project_developer',
            reason: '',
        });
    });

    it('reject sends action + reason (empty granted_role)', async () => {
        mocked.put.mockResolvedValue({ data: {} });
        await projectInvitationsApi.resolveAccessRequest(3, 5, 'reject', undefined, 'not now');
        expect(mocked.put).toHaveBeenCalledWith('/api/v1/projects/3/access-requests/5', {
            action: 'reject',
            granted_role: '',
            reason: 'not now',
        });
    });
});

describe('projectInvitationsApi mutations hit the right endpoints', () => {
    it('revokeInvitation DELETEs the invitation', async () => {
        mocked.delete.mockResolvedValue({ data: {} });
        await projectInvitationsApi.revokeInvitation(3, 7);
        expect(mocked.delete).toHaveBeenCalledWith('/api/v1/projects/3/invitations/7');
    });

    it('withdrawAccessRequest POSTs the withdraw sub-route', async () => {
        mocked.post.mockResolvedValue({ data: {} });
        await projectInvitationsApi.withdrawAccessRequest(3, 8);
        expect(mocked.post).toHaveBeenCalledWith('/api/v1/projects/3/access-requests/8/withdraw');
    });
});
