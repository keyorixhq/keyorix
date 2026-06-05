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

    it('one-time-password path posts the flag and unwraps the nested {email, one_time_password}', async () => {
        mocked.post.mockResolvedValue({
            data: { data: { user: { id: 9 }, one_time_password: { email: 'otto@x.io', one_time_password: 'Xk7-mP2q-Rt9w-Zb4n' } } },
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

    it('resendSetupLink unwraps the delivery outcome', async () => {
        mocked.post.mockResolvedValue({
            data: { data: { email: 'e@x.io', channel: 'out_of_band', delivered: false, link_for_admin: 'https://app/setup/abc' } },
        });
        const res = await usersApi.resendSetupLink(7);
        expect(mocked.post).toHaveBeenCalledWith('/api/v1/users/7/resend-setup-link');
        expect(res.link_for_admin).toBe('https://app/setup/abc');
    });

    it('getMemberships normalizes snake/Pascal keys', async () => {
        mocked.get.mockResolvedValue({
            data: { data: { memberships: [{ project_id: 3, project_name: 'payments', role: 'project_developer', state: 'active' }] } },
        });
        const rows = await usersApi.getMemberships(42);
        expect(mocked.get).toHaveBeenCalledWith('/api/v1/users/42/memberships');
        expect(rows).toEqual([{ project_id: 3, project_name: 'payments', role: 'project_developer', state: 'active' }]);
    });

    it('getStale passes params and unwraps users', async () => {
        mocked.get.mockResolvedValue({
            data: { data: { users: [{ id: 9, username: 'stale', email: 's@x.io', account_state: 'pending_first_login' }] } },
        });
        const rows = await usersApi.getStale({ state: 'pending_first_login', days: 7 });
        expect(mocked.get).toHaveBeenCalledWith('/api/v1/users/stale', { params: { state: 'pending_first_login', days: 7 } });
        expect(rows).toHaveLength(1);
        expect(rows[0].username).toBe('stale');
    });
});
