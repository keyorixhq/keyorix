import { describe, it, expect, vi, beforeEach } from 'vitest';

// authApi is a private axios instance created via axios.create() inside auth.ts.
// vi.hoisted() runs before the vi.mock() factory so the stubs are in scope there.
const { mockGet, mockPost } = vi.hoisted(() => ({
    mockGet:  vi.fn(),
    mockPost: vi.fn(),
}));

vi.mock('axios', async () => {
    const actual = await vi.importActual<typeof import('axios')>('axios');
    return {
        ...actual,
        default: {
            ...actual.default,
            create: vi.fn(() => ({
                get:  mockGet,
                post: mockPost,
                interceptors: { request: { use: vi.fn() } },
            })),
            isAxiosError: actual.isAxiosError,
        },
        isAxiosError: actual.isAxiosError,
    };
});

import { authService } from '../auth';

function ok<T>(data: T) {
    return { data: { data, message: 'ok' } };
}
function axiosErr(status: number, payload: object) {
    const err = Object.assign(new Error('Request failed'), {
        isAxiosError: true,
        response: { status, data: payload },
    });
    return err;
}

beforeEach(() => {
    vi.clearAllMocks();
});

// ── login ─────────────────────────────────────────────────────────────────────

describe('authService.login', () => {
    const credentials = { username: 'alice', password: 'secret1', rememberMe: false };

    it('returns LoginResponse on success', async () => {
        const payload = {
            token: 't', expires_at: '2030-01-01', user_id: 1,
            username: 'alice', email: 'a@x.io',
        };
        mockPost.mockResolvedValueOnce(ok(payload));
        const result = await authService.login(credentials);
        expect(result).toEqual(payload);
        expect(mockPost).toHaveBeenCalledWith(
            expect.stringContaining('login'),
            { username: 'alice', password: 'secret1', rememberMe: false },
        );
    });

    it('throws with server error message on 401', async () => {
        mockPost.mockRejectedValueOnce(axiosErr(401, { error: 'Invalid credentials' }));
        await expect(authService.login(credentials)).rejects.toThrow('Invalid credentials');
    });

    it('throws generic message when server sends no error text', async () => {
        mockPost.mockRejectedValueOnce(axiosErr(500, {}));
        await expect(authService.login(credentials)).rejects.toThrow('Login failed');
    });

    it('throws generic message when data object is missing', async () => {
        mockPost.mockResolvedValueOnce({ data: {} });
        await expect(authService.login(credentials)).rejects.toThrow('Login failed');
    });

    it('passes rememberMe: true in the request body', async () => {
        const payload = { token: 't', expires_at: '2030-01-01', user_id: 2, username: 'b', email: 'b@x.io' };
        mockPost.mockResolvedValueOnce(ok(payload));
        await authService.login({ ...credentials, rememberMe: true });
        expect(mockPost).toHaveBeenCalledWith(expect.anything(), expect.objectContaining({ rememberMe: true }));
    });
});

// ── logout ────────────────────────────────────────────────────────────────────

describe('authService.logout', () => {
    it('resolves without throwing on success', async () => {
        mockPost.mockResolvedValueOnce({});
        await expect(authService.logout()).resolves.toBeUndefined();
    });

    it('swallows server errors (never throws)', async () => {
        mockPost.mockRejectedValueOnce(new Error('network error'));
        await expect(authService.logout()).resolves.toBeUndefined();
    });
});

// ── refreshToken ──────────────────────────────────────────────────────────────

describe('authService.refreshToken', () => {
    it('returns RefreshTokenResponse on success', async () => {
        const payload = { token: 'new-t', expires_at: '2030-06-01' };
        mockPost.mockResolvedValueOnce(ok(payload));
        const result = await authService.refreshToken();
        expect(result).toEqual(payload);
    });

    it('throws with server message on 401', async () => {
        mockPost.mockRejectedValueOnce(axiosErr(401, { message: 'Session expired' }));
        await expect(authService.refreshToken()).rejects.toThrow('Session expired');
    });

    it('throws generic message when data is absent', async () => {
        mockPost.mockResolvedValueOnce({ data: {} });
        await expect(authService.refreshToken()).rejects.toThrow('Token refresh failed');
    });
});

// ── getProfile ────────────────────────────────────────────────────────────────

describe('authService.getProfile', () => {
    it('returns the user profile', async () => {
        const profile = { id: 1, username: 'alice', email: 'a@x.io', role: 'admin' };
        mockGet.mockResolvedValueOnce(ok(profile));
        await expect(authService.getProfile()).resolves.toMatchObject({ username: 'alice' });
    });

    it('throws with server error message on 404', async () => {
        mockGet.mockRejectedValueOnce(axiosErr(404, { error: 'Not found' }));
        await expect(authService.getProfile()).rejects.toThrow('Not found');
    });

    it('throws generic message when data is absent', async () => {
        mockGet.mockResolvedValueOnce({ data: {} });
        await expect(authService.getProfile()).rejects.toThrow('Failed to get profile');
    });

    it('includes impersonation data when present', async () => {
        const profile = { id: 2, username: 'bob', email: 'b@x.io', impersonation: { admin_id: 1 } };
        mockGet.mockResolvedValueOnce(ok(profile));
        const result = await authService.getProfile();
        expect(result).toMatchObject({ impersonation: { admin_id: 1 } });
    });
});

// ── checkAuth ─────────────────────────────────────────────────────────────────

describe('authService.checkAuth', () => {
    it('returns the user when the session is valid', async () => {
        const profile = { id: 1, username: 'alice', email: 'a@x.io' };
        mockGet.mockResolvedValueOnce(ok(profile));
        await expect(authService.checkAuth()).resolves.toMatchObject({ username: 'alice' });
    });

    it('returns null when getProfile throws (unauthenticated)', async () => {
        mockGet.mockRejectedValueOnce(axiosErr(401, { error: 'Unauthorized' }));
        await expect(authService.checkAuth()).resolves.toBeNull();
    });
});

// ── getSSOProviders ───────────────────────────────────────────────────────────

describe('authService.getSSOProviders', () => {
    it('returns provider list from nested data', async () => {
        mockGet.mockResolvedValueOnce({ data: { data: { providers: ['google', 'github'] } } });
        await expect(authService.getSSOProviders()).resolves.toEqual(['google', 'github']);
    });

    it('returns [] when SSO is not configured (404)', async () => {
        mockGet.mockRejectedValueOnce(axiosErr(404, {}));
        await expect(authService.getSSOProviders()).resolves.toEqual([]);
    });

    it('returns [] when providers field is absent', async () => {
        mockGet.mockResolvedValueOnce({ data: { data: {} } });
        await expect(authService.getSSOProviders()).resolves.toEqual([]);
    });
});

// ── requestPasswordReset ──────────────────────────────────────────────────────

describe('authService.requestPasswordReset', () => {
    it('resolves when the server confirms with a message', async () => {
        mockPost.mockResolvedValueOnce({ data: { message: 'Reset link sent' } });
        await expect(authService.requestPasswordReset({ email: 'a@x.io' })).resolves.toBeUndefined();
    });

    it('throws when the server omits the message field', async () => {
        mockPost.mockResolvedValueOnce({ data: {} });
        await expect(authService.requestPasswordReset({ email: 'a@x.io' })).rejects.toThrow('Password reset request failed');
    });

    it('throws with server message on 422', async () => {
        mockPost.mockRejectedValueOnce(axiosErr(422, { error: 'Unknown email' }));
        await expect(authService.requestPasswordReset({ email: 'x@x.io' })).rejects.toThrow('Unknown email');
    });
});

// ── confirmPasswordReset ──────────────────────────────────────────────────────

describe('authService.confirmPasswordReset', () => {
    it('resolves when the server confirms with a message', async () => {
        mockPost.mockResolvedValueOnce({ data: { message: 'Password updated' } });
        await expect(
            authService.confirmPasswordReset({ token: 'tok', password: 'newpass' }),
        ).resolves.toBeUndefined();
    });

    it('throws when the server omits the message field', async () => {
        mockPost.mockResolvedValueOnce({ data: {} });
        await expect(
            authService.confirmPasswordReset({ token: 'tok', password: 'newpass' }),
        ).rejects.toThrow('Password reset failed');
    });

    it('throws with server error message on 410 (token expired)', async () => {
        mockPost.mockRejectedValueOnce(axiosErr(410, { error: 'Token expired' }));
        await expect(
            authService.confirmPasswordReset({ token: 'bad', password: 'x' }),
        ).rejects.toThrow('Token expired');
    });
});

// ── endImpersonation ──────────────────────────────────────────────────────────

describe('authService.endImpersonation', () => {
    it('calls the end-impersonation endpoint', async () => {
        mockPost.mockResolvedValueOnce({});
        await authService.endImpersonation();
        expect(mockPost).toHaveBeenCalledWith('/api/v1/auth/end-impersonation');
    });

    it('propagates server errors (does not swallow them)', async () => {
        mockPost.mockRejectedValueOnce(new Error('forbidden'));
        await expect(authService.endImpersonation()).rejects.toThrow('forbidden');
    });
});
