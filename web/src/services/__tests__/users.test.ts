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
import { usersApi } from '../users';

const mocked = apiClient as unknown as {
    get: ReturnType<typeof vi.fn>;
    post: ReturnType<typeof vi.fn>;
    put: ReturnType<typeof vi.fn>;
    delete: ReturnType<typeof vi.fn>;
};

beforeEach(() => {
    vi.clearAllMocks();
});

describe('usersApi.list', () => {
    it('passes params through and unwraps data.data', async () => {
        const page = { items: [{ id: 1, username: 'alice' }], total: 1, page: 1, pageSize: 20 };
        mocked.get.mockResolvedValue({ data: { data: page } });

        const result = await usersApi.list({ page: 1, pageSize: 20, search: 'ali' });

        expect(mocked.get).toHaveBeenCalledWith('/api/v1/users', { params: { page: 1, pageSize: 20, search: 'ali' } });
        expect(result).toEqual(page);
    });
});

describe('usersApi.get', () => {
    it('fetches a single user and unwraps data.data', async () => {
        mocked.get.mockResolvedValue({ data: { data: { id: 9, username: 'bob' } } });

        const result = await usersApi.get(9);

        expect(mocked.get).toHaveBeenCalledWith('/api/v1/users/9');
        expect(result).toEqual({ id: 9, username: 'bob' });
    });
});

describe('usersApi.search', () => {
    it('queries with q param and maps rows to Recipient shape', async () => {
        mocked.get.mockResolvedValue({
            data: { data: { users: [{ id: 1, username: 'carol', email: 'c@x.io' }] } },
        });

        const result = await usersApi.search('car');

        expect(mocked.get).toHaveBeenCalledWith('/api/v1/users/search', { params: { q: 'car' } });
        expect(result).toEqual([{ id: 1, name: 'carol', type: 'user', email: 'c@x.io' }]);
    });

    it('returns [] when data.data.users is absent', async () => {
        mocked.get.mockResolvedValue({ data: { data: {} } });
        await expect(usersApi.search('x')).resolves.toEqual([]);
    });
});

describe('usersApi.create', () => {
    it('classic path posts the password and unwraps {data:user}', async () => {
        mocked.post.mockResolvedValue({
            data: { data: { id: 5, username: 'jsmith', email: 'j@x.io' } },
        });

        const res = await usersApi.create({
            username: 'jsmith',
            email: 'j@x.io',
            display_name: 'J Smith',
            password: 'hunter2hunter2',
        });

        expect(mocked.post).toHaveBeenCalledWith('/api/v1/users', {
            username: 'jsmith',
            email: 'j@x.io',
            display_name: 'J Smith',
            password: 'hunter2hunter2',
        });
        // No setup_link on the classic path → the dialog closes immediately.
        expect(res.setup_link).toBeUndefined();
        expect(res).toMatchObject({ id: 5, username: 'jsmith' });
    });

    it('setup-link path posts deliver_setup_link with no password and surfaces the out-of-band link', async () => {
        mocked.post.mockResolvedValue({
            data: {
                data: {
                    user: { id: 6, username: 'dana' },
                    setup_link: {
                        email: 'dana@x.io',
                        channel: 'out_of_band',
                        delivered: false,
                        link_for_admin: 'https://keyorix.test/auth/setup/kx_setup_abc',
                    },
                },
            },
        });

        const res = await usersApi.create({
            username: 'dana',
            email: 'dana@x.io',
            display_name: 'Dana',
            deliver_setup_link: true,
        });

        const body = mocked.post.mock.calls[0][1];
        expect(body).toEqual({
            username: 'dana',
            email: 'dana@x.io',
            display_name: 'Dana',
            deliver_setup_link: true,
        });
        // The admin must NOT have chosen a password on this path.
        expect(body).not.toHaveProperty('password');
        expect(res.setup_link).toMatchObject({
            channel: 'out_of_band',
            delivered: false,
            link_for_admin: 'https://keyorix.test/auth/setup/kx_setup_abc',
        });
    });

    it('setup-link path reports an emailed delivery without a relay link', async () => {
        mocked.post.mockResolvedValue({
            data: {
                data: {
                    user: { id: 7 },
                    setup_link: { email: 'e@x.io', channel: 'smtp', delivered: true },
                },
            },
        });

        const res = await usersApi.create({
            username: 'erin',
            email: 'e@x.io',
            display_name: 'Erin',
            deliver_setup_link: true,
        });

        expect(res.setup_link).toMatchObject({ channel: 'smtp', delivered: true });
        expect(res.setup_link?.link_for_admin).toBeUndefined();
    });

    it('atomic path forwards the system role + project assignments alongside the password', async () => {
        mocked.post.mockResolvedValue({
            data: { data: { id: 11, username: 'ada' } },
        });

        await usersApi.create({
            username: 'ada',
            email: 'ada@x.io',
            display_name: 'Ada',
            password: 'hunter2hunter2',
            role: 'system_auditor',
            project_assignments: [
                { project_id: 1, role: 'project_admin' },
                { project_id: 4, role: 'project_viewer' },
            ],
        });

        expect(mocked.post).toHaveBeenCalledWith('/api/v1/users', {
            username: 'ada',
            email: 'ada@x.io',
            display_name: 'Ada',
            password: 'hunter2hunter2',
            role: 'system_auditor',
            project_assignments: [
                { project_id: 1, role: 'project_admin' },
                { project_id: 4, role: 'project_viewer' },
            ],
        });
    });

    it('one-time-password path posts the flag and unwraps the nested {email, one_time_password}', async () => {
        mocked.post.mockResolvedValue({
            data: {
                data: {
                    user: { id: 9 },
                    one_time_password: { email: 'otto@x.io', one_time_password: 'Xk7-mP2q-Rt9w-Zb4n' },
                },
            },
        });

        const res = await usersApi.create({
            username: 'otto',
            email: 'otto@x.io',
            display_name: 'Otto',
            generate_one_time_password: true,
        });

        expect(mocked.post).toHaveBeenCalledWith('/api/v1/users', {
            username: 'otto',
            email: 'otto@x.io',
            display_name: 'Otto',
            generate_one_time_password: true,
        });
        expect(res.one_time_password?.one_time_password).toBe('Xk7-mP2q-Rt9w-Zb4n');
    });
});

describe('usersApi ADR-025 lifecycle + views', () => {
    it('posts the lifecycle transitions', async () => {
        mocked.post.mockResolvedValue({ data: {} });
        await usersApi.suspend(7);
        expect(mocked.post).toHaveBeenCalledWith('/api/v1/users/7/suspend');
        await usersApi.reactivate(7);
        expect(mocked.post).toHaveBeenCalledWith('/api/v1/users/7/reactivate');
        await usersApi.requirePasswordReset(7);
        expect(mocked.post).toHaveBeenCalledWith('/api/v1/users/7/require-password-reset');
    });

    it('unlock clears an active login lockout', async () => {
        mocked.post.mockResolvedValue({ data: {} });
        await usersApi.unlock(7);
        expect(mocked.post).toHaveBeenCalledWith('/api/v1/users/7/unlock');
    });

    it('revokeSessions force-logs-out the user', async () => {
        mocked.post.mockResolvedValue({ data: {} });
        await usersApi.revokeSessions(7);
        expect(mocked.post).toHaveBeenCalledWith('/api/v1/users/7/revoke-sessions');
    });

    it('resendSetupLink unwraps the delivery outcome', async () => {
        mocked.post.mockResolvedValue({
            data: {
                data: {
                    email: 'e@x.io',
                    channel: 'out_of_band',
                    delivered: false,
                    link_for_admin: 'https://app/setup/abc',
                },
            },
        });
        const res = await usersApi.resendSetupLink(7);
        expect(mocked.post).toHaveBeenCalledWith('/api/v1/users/7/resend-setup-link');
        expect(res.link_for_admin).toBe('https://app/setup/abc');
    });

    it('resendSetupLink falls back to bare response.data when data.data is absent', async () => {
        mocked.post.mockResolvedValue({ data: { email: 'e@x.io', channel: 'smtp', delivered: true } });
        const res = await usersApi.resendSetupLink(7);
        expect(res).toEqual({ email: 'e@x.io', channel: 'smtp', delivered: true });
    });

    it('getMemberships normalizes snake/Pascal keys', async () => {
        mocked.get.mockResolvedValue({
            data: {
                data: {
                    memberships: [
                        { project_id: 3, project_name: 'payments', role: 'project_developer', state: 'active' },
                    ],
                },
            },
        });
        const rows = await usersApi.getMemberships(42);
        expect(mocked.get).toHaveBeenCalledWith('/api/v1/users/42/memberships');
        expect(rows).toEqual([{ project_id: 3, project_name: 'payments', role: 'project_developer', state: 'active' }]);
    });

    it('getMemberships normalizes PascalCase keys and defaults a sparse row', async () => {
        mocked.get.mockResolvedValue({
            data: {
                data: {
                    memberships: [{ ProjectID: 4, ProjectName: 'infra', Role: 'project_viewer', State: 'active' }, {}],
                },
            },
        });
        const rows = await usersApi.getMemberships(42);
        expect(rows[0]).toEqual({ project_id: 4, project_name: 'infra', role: 'project_viewer', state: 'active' });
        expect(rows[1]).toEqual({ project_id: 0, project_name: '', role: '', state: '' });
    });

    it('getMemberships falls back to bare data.memberships, and to [] when neither wrapper is present', async () => {
        mocked.get.mockResolvedValueOnce({ data: { memberships: [{ project_id: 1 }] } });
        const bare = await usersApi.getMemberships(42);
        expect(bare).toHaveLength(1);

        mocked.get.mockResolvedValueOnce({ data: {} });
        await expect(usersApi.getMemberships(42)).resolves.toEqual([]);
    });

    it('getStale passes params and unwraps users', async () => {
        mocked.get.mockResolvedValue({
            data: {
                data: { users: [{ id: 9, username: 'stale', email: 's@x.io', account_state: 'pending_first_login' }] },
            },
        });
        const rows = await usersApi.getStale({ state: 'pending_first_login', days: 7 });
        expect(mocked.get).toHaveBeenCalledWith('/api/v1/users/stale', {
            params: { state: 'pending_first_login', days: 7 },
        });
        expect(rows).toHaveLength(1);
        expect(rows[0].username).toBe('stale');
    });

    it('getStale falls back to bare data.users, and to [] when neither wrapper is present', async () => {
        mocked.get.mockResolvedValueOnce({ data: { users: [{ id: 1, username: 'bare' }] } });
        const bare = await usersApi.getStale();
        expect(bare[0]).toMatchObject({ username: 'bare' });

        mocked.get.mockResolvedValueOnce({ data: {} });
        await expect(usersApi.getStale()).resolves.toEqual([]);
    });
});

describe('usersApi.update / delete / restore', () => {
    it('update PUTs the body and returns the raw response data', async () => {
        mocked.put.mockResolvedValue({ data: { id: 3, username: 'updated' } });
        const result = await usersApi.update(3, { display_name: 'New Name' });
        expect(mocked.put).toHaveBeenCalledWith('/api/v1/users/3', { display_name: 'New Name' });
        expect(result).toEqual({ id: 3, username: 'updated' });
    });

    it('delete DELETEs the user by id', async () => {
        mocked.delete.mockResolvedValue({});
        await usersApi.delete(3);
        expect(mocked.delete).toHaveBeenCalledWith('/api/v1/users/3');
    });

    it('restore POSTs to the restore sub-route', async () => {
        mocked.post.mockResolvedValue({});
        await usersApi.restore(3);
        expect(mocked.post).toHaveBeenCalledWith('/api/v1/users/3/restore');
    });
});

describe('usersApi.create response fallback', () => {
    it('falls back to bare response.data when data.data is absent', async () => {
        mocked.post.mockResolvedValue({ data: { id: 20, username: 'bare' } });
        const res = await usersApi.create({ username: 'bare', email: 'bare@x.io', display_name: 'Bare' });
        expect(res).toMatchObject({ id: 20, username: 'bare' });
    });
});
