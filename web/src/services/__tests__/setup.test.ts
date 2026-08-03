import { describe, it, expect, vi, beforeEach } from 'vitest';

// setupService uses a private axios instance created via axios.create() inside
// setup.ts (mirrors the auth.ts test convention).
const { mockGet, mockPost } = vi.hoisted(() => ({
    mockGet: vi.fn(),
    mockPost: vi.fn(),
}));

vi.mock('axios', async () => {
    const actual = await vi.importActual<typeof import('axios')>('axios');
    return {
        ...actual,
        default: {
            ...actual.default,
            create: vi.fn(() => ({
                get: mockGet,
                post: mockPost,
            })),
            isAxiosError: actual.isAxiosError,
        },
        isAxiosError: actual.isAxiosError,
    };
});

import { setupService } from '../setup';

function ok<T>(data: T) {
    return { data: { data } };
}
function axiosErr(payload: object) {
    return Object.assign(new Error('Request failed'), {
        isAxiosError: true,
        response: { status: 410, data: payload },
    });
}

beforeEach(() => vi.clearAllMocks());

// ── describe ──────────────────────────────────────────────────────────────────

describe('setupService.describe', () => {
    it('GETs the URL-encoded token and returns the token info', async () => {
        const info = { purpose: 'password_setup', email: 'alice@example.com' };
        mockGet.mockResolvedValueOnce(ok(info));
        const result = await setupService.describe('to ken/1');
        expect(mockGet).toHaveBeenCalledWith('/auth/setup/to%20ken%2F1');
        expect(result).toEqual(info);
    });

    it('throws the server error message on a dead link', async () => {
        mockGet.mockRejectedValueOnce(axiosErr({ error: 'Link expired' }));
        await expect(setupService.describe('bad')).rejects.toThrow('Link expired');
    });

    it('falls back to response.data.message when there is no .error', async () => {
        mockGet.mockRejectedValueOnce(axiosErr({ message: 'Token not found' }));
        await expect(setupService.describe('bad')).rejects.toThrow('Token not found');
    });

    it('falls back to the default message for a non-axios error', async () => {
        mockGet.mockRejectedValueOnce(new Error('network down'));
        await expect(setupService.describe('bad')).rejects.toThrow('This setup link is no longer valid');
    });

    it('falls back to the default message when the axios error body has neither .error nor .message', async () => {
        mockGet.mockRejectedValueOnce(axiosErr({}));
        await expect(setupService.describe('bad')).rejects.toThrow('This setup link is no longer valid');
    });
});

// ── consume ───────────────────────────────────────────────────────────────────

describe('setupService.consume', () => {
    it('POSTs the token and password and returns the login response', async () => {
        const login = { token: 't', expires_at: '2030-01-01', user_id: 1, username: 'alice', email: 'a@x.io' };
        mockPost.mockResolvedValueOnce(ok(login));
        const result = await setupService.consume('tok', 'newpass');
        expect(mockPost).toHaveBeenCalledWith('/auth/setup/consume', { token: 'tok', password: 'newpass' });
        expect(result).toEqual(login);
    });

    // NOTE: the missing-user_id branch throws a plain `new Error(response.data.message
    // || 'Setup failed')`, but that throw is caught by this same method's outer
    // try/catch, which re-wraps it via messageFromError(). Since a plain Error isn't
    // an axios error, messageFromError() can't see its message and always falls back
    // to 'Setup failed' — so the server-provided message here is never actually
    // surfaced to the caller. Asserting the real (if likely unintended) behavior.
    it('throws the generic "Setup failed" when the response has no user_id, even if the server sent a message', async () => {
        mockPost.mockResolvedValueOnce({ data: { data: {}, message: 'Password too weak' } });
        await expect(setupService.consume('tok', 'weak')).rejects.toThrow('Setup failed');
    });

    it('throws the default "Setup failed" when neither user_id nor message is present', async () => {
        mockPost.mockResolvedValueOnce({ data: { data: {} } });
        await expect(setupService.consume('tok', 'weak')).rejects.toThrow('Setup failed');
    });

    it('throws the server error message on an axios error', async () => {
        mockPost.mockRejectedValueOnce(axiosErr({ error: 'Token already used' }));
        await expect(setupService.consume('tok', 'newpass')).rejects.toThrow('Token already used');
    });

    it('falls back to the default message for a non-axios error', async () => {
        mockPost.mockRejectedValueOnce(new Error('network down'));
        await expect(setupService.consume('tok', 'newpass')).rejects.toThrow('Setup failed');
    });
});
