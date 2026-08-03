import { describe, it, expect, vi, beforeEach } from 'vitest';

vi.mock('../client', () => ({
    apiClient: {
        get: vi.fn(),
        post: vi.fn(),
        put: vi.fn(),
        delete: vi.fn(),
    },
}));

import { apiClient } from '../client';
import { accountApi } from '../account';

const mock = apiClient as unknown as {
    get: ReturnType<typeof vi.fn>;
    post: ReturnType<typeof vi.fn>;
    put: ReturnType<typeof vi.fn>;
    delete: ReturnType<typeof vi.fn>;
};

function ok<T>(data: T) {
    return { data: { data } };
}

beforeEach(() => vi.clearAllMocks());

// ── updateProfile ────────────────────────────────────────────────────────────

describe('accountApi.updateProfile', () => {
    it('PUTs the profile body and returns the updated profile', async () => {
        const profile = {
            id: 1,
            username: 'alice',
            email: 'alice@example.com',
            display_name: 'Alice',
            is_active: true,
        };
        mock.put.mockResolvedValueOnce(ok(profile));
        const result = await accountApi.updateProfile({ display_name: 'Alice', email: 'alice@example.com' });
        expect(mock.put).toHaveBeenCalledWith('/api/v1/auth/profile', {
            display_name: 'Alice',
            email: 'alice@example.com',
        });
        expect(result).toEqual(profile);
    });
});

// ── changePassword ───────────────────────────────────────────────────────────

describe('accountApi.changePassword', () => {
    it('POSTs the current and new password', async () => {
        mock.post.mockResolvedValueOnce(ok(null));
        await accountApi.changePassword({ current_password: 'old', new_password: 'new' });
        expect(mock.post).toHaveBeenCalledWith('/api/v1/auth/change-password', {
            current_password: 'old',
            new_password: 'new',
        });
    });
});

// ── listSessions ──────────────────────────────────────────────────────────────

describe('accountApi.listSessions', () => {
    it('returns the sessions array', async () => {
        const sessions = [
            {
                id: 1,
                user_agent: 'Chrome',
                ip_address: '1.2.3.4',
                created_at: '2026-01-01T00:00:00Z',
                expires_at: null,
                last_seen_at: null,
                current: true,
            },
        ];
        mock.get.mockResolvedValueOnce(ok(sessions));
        const result = await accountApi.listSessions();
        expect(mock.get).toHaveBeenCalledWith('/api/v1/auth/sessions');
        expect(result).toEqual(sessions);
    });

    it('returns [] when the response data is not an array', async () => {
        mock.get.mockResolvedValueOnce(ok(null));
        await expect(accountApi.listSessions()).resolves.toEqual([]);
    });
});

// ── revokeSession ─────────────────────────────────────────────────────────────

describe('accountApi.revokeSession', () => {
    it('DELETEs the session by id', async () => {
        mock.delete.mockResolvedValueOnce(ok(null));
        await accountApi.revokeSession(42);
        expect(mock.delete).toHaveBeenCalledWith('/api/v1/auth/sessions/42');
    });
});
