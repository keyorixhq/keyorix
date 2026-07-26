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
