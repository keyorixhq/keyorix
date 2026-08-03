import { describe, it, expect, vi, beforeEach } from 'vitest';

vi.mock('../client', () => ({
    apiClient: {
        get: vi.fn(),
        post: vi.fn(),
    },
}));

import { apiClient } from '../client';
import { mfaApi } from '../mfa';

const mock = apiClient as unknown as {
    get: ReturnType<typeof vi.fn>;
    post: ReturnType<typeof vi.fn>;
};

beforeEach(() => vi.clearAllMocks());

// ── enroll ────────────────────────────────────────────────────────────────────

describe('mfaApi.enroll', () => {
    it('POSTs an empty body and returns the otpauth URI and secret', async () => {
        const enrollment = { otpauth_uri: 'otpauth://totp/Keyorix', secret: 'JBSWY3DPEHPK3PXP' };
        mock.post.mockResolvedValueOnce({ data: { data: enrollment } });
        const result = await mfaApi.enroll();
        expect(mock.post).toHaveBeenCalledWith('/api/v1/auth/mfa/enroll', {});
        expect(result).toEqual(enrollment);
    });
});

// ── activate ──────────────────────────────────────────────────────────────────

describe('mfaApi.activate', () => {
    it('POSTs the code and returns the recovery codes', async () => {
        mock.post.mockResolvedValueOnce({ data: { data: { recovery_codes: ['abc123', 'def456'] } } });
        const result = await mfaApi.activate('123456');
        expect(mock.post).toHaveBeenCalledWith('/api/v1/auth/mfa/activate', { code: '123456' });
        expect(result).toEqual(['abc123', 'def456']);
    });

    it('returns [] when recovery_codes is missing', async () => {
        mock.post.mockResolvedValueOnce({ data: { data: {} } });
        await expect(mfaApi.activate('123456')).resolves.toEqual([]);
    });
});

// ── disable ───────────────────────────────────────────────────────────────────

describe('mfaApi.disable', () => {
    it('POSTs the proof as-is', async () => {
        mock.post.mockResolvedValueOnce({ data: {} });
        await mfaApi.disable({ code: '123456' });
        expect(mock.post).toHaveBeenCalledWith('/api/v1/auth/mfa/disable', { code: '123456' });
    });

    it('supports password-based proof', async () => {
        mock.post.mockResolvedValueOnce({ data: {} });
        await mfaApi.disable({ password: 'hunter2' });
        expect(mock.post).toHaveBeenCalledWith('/api/v1/auth/mfa/disable', { password: 'hunter2' });
    });
});

// ── recoveryCodesStatus ───────────────────────────────────────────────────────

describe('mfaApi.recoveryCodesStatus', () => {
    it('returns the remaining/total counts', async () => {
        mock.get.mockResolvedValueOnce({ data: { data: { remaining: 3, total: 10 } } });
        const result = await mfaApi.recoveryCodesStatus();
        expect(mock.get).toHaveBeenCalledWith('/api/v1/auth/mfa/recovery-codes');
        expect(result).toEqual({ remaining: 3, total: 10 });
    });
});

// ── regenerateRecoveryCodes ───────────────────────────────────────────────────

describe('mfaApi.regenerateRecoveryCodes', () => {
    it('POSTs the proof and returns the new recovery codes', async () => {
        mock.post.mockResolvedValueOnce({ data: { data: { recovery_codes: ['new1', 'new2'] } } });
        const result = await mfaApi.regenerateRecoveryCodes({ code: '123456' });
        expect(mock.post).toHaveBeenCalledWith('/api/v1/auth/mfa/recovery-codes/regenerate', { code: '123456' });
        expect(result).toEqual(['new1', 'new2']);
    });

    it('returns [] when recovery_codes is missing', async () => {
        mock.post.mockResolvedValueOnce({ data: { data: {} } });
        await expect(mfaApi.regenerateRecoveryCodes({ password: 'hunter2' })).resolves.toEqual([]);
    });
});
