import React from 'react';
import { describe, it, expect, vi, beforeEach } from 'vitest';
import { renderHook, waitFor, act } from '@testing-library/react';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';

vi.mock('../../../services/account', () => ({
    accountApi: {
        updateProfile: vi.fn(),
        changePassword: vi.fn(),
        listSessions: vi.fn(),
        revokeSession: vi.fn(),
    },
}));
vi.mock('../../../services/personalTokens', () => ({
    personalTokensApi: {
        listTokens: vi.fn(),
        createToken: vi.fn(),
        revokeToken: vi.fn(),
    },
}));
vi.mock('../../../services/mfa', () => ({
    mfaApi: {
        enroll: vi.fn(),
        activate: vi.fn(),
        disable: vi.fn(),
        recoveryCodesStatus: vi.fn(),
        regenerateRecoveryCodes: vi.fn(),
    },
}));

import { accountApi } from '../../../services/account';
import { personalTokensApi } from '../../../services/personalTokens';
import { mfaApi } from '../../../services/mfa';
import {
    useUpdateProfile,
    useChangePassword,
    useSessions,
    useRevokeSession,
    usePersonalTokens,
    useCreatePersonalToken,
    useRevokePersonalToken,
    useMfaRecoveryStatus,
    useEnrollMfa,
    useActivateMfa,
    useDisableMfa,
    useRegenerateRecoveryCodes,
} from '../index';

const accountMock = accountApi as unknown as {
    updateProfile: ReturnType<typeof vi.fn>;
    changePassword: ReturnType<typeof vi.fn>;
    listSessions: ReturnType<typeof vi.fn>;
    revokeSession: ReturnType<typeof vi.fn>;
};
const personalTokensMock = personalTokensApi as unknown as {
    listTokens: ReturnType<typeof vi.fn>;
    createToken: ReturnType<typeof vi.fn>;
    revokeToken: ReturnType<typeof vi.fn>;
};
const mfaMock = mfaApi as unknown as {
    enroll: ReturnType<typeof vi.fn>;
    activate: ReturnType<typeof vi.fn>;
    disable: ReturnType<typeof vi.fn>;
    recoveryCodesStatus: ReturnType<typeof vi.fn>;
    regenerateRecoveryCodes: ReturnType<typeof vi.fn>;
};

function createWrapper() {
    const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false } } });
    const wrapper = ({ children }: { children: React.ReactNode }) =>
        React.createElement(QueryClientProvider, { client: queryClient }, children);
    return { wrapper, queryClient };
}

beforeEach(() => vi.clearAllMocks());

// G28: each of these mutations returns plaintext (a bearer token, a TOTP setup
// secret, or freshly minted recovery codes). Without a short gcTime override,
// react-query's MutationCache would retain the response for the default 5
// minutes after the last observer unmounts.
describe('sensitive mutation cache eviction (G28)', () => {
    it('useCreatePersonalToken does not retain the token after unmount', async () => {
        personalTokensMock.createToken.mockResolvedValueOnce({ token: 'kx_plaintext', pat: { id: 1 } as never });
        const { wrapper, queryClient } = createWrapper();
        const { result, unmount } = renderHook(() => useCreatePersonalToken(), { wrapper });

        act(() => {
            result.current.mutate({ name: 'ci' } as never);
        });
        await waitFor(() => expect(result.current.isSuccess).toBe(true));
        expect(queryClient.getMutationCache().getAll()).toHaveLength(1);

        unmount();
        await waitFor(() => expect(queryClient.getMutationCache().getAll()).toHaveLength(0));
    });

    it('useEnrollMfa does not retain the TOTP setup secret after unmount', async () => {
        mfaMock.enroll.mockResolvedValueOnce({ secret: 'JBSWY3DPEHPK3PXP', otpauth_uri: 'otpauth://totp/x' });
        const { wrapper, queryClient } = createWrapper();
        const { result, unmount } = renderHook(() => useEnrollMfa(), { wrapper });

        act(() => {
            result.current.mutate();
        });
        await waitFor(() => expect(result.current.isSuccess).toBe(true));
        expect(queryClient.getMutationCache().getAll()).toHaveLength(1);

        unmount();
        await waitFor(() => expect(queryClient.getMutationCache().getAll()).toHaveLength(0));
    });

    it('useActivateMfa does not retain the recovery codes after unmount', async () => {
        mfaMock.activate.mockResolvedValueOnce(['code-1', 'code-2']);
        const { wrapper, queryClient } = createWrapper();
        const { result, unmount } = renderHook(() => useActivateMfa(), { wrapper });

        act(() => {
            result.current.mutate('123456');
        });
        await waitFor(() => expect(result.current.isSuccess).toBe(true));
        expect(queryClient.getMutationCache().getAll()).toHaveLength(1);

        unmount();
        await waitFor(() => expect(queryClient.getMutationCache().getAll()).toHaveLength(0));
    });

    it('useRegenerateRecoveryCodes does not retain the new recovery codes after unmount', async () => {
        mfaMock.regenerateRecoveryCodes.mockResolvedValueOnce(['new-1', 'new-2']);
        const { wrapper, queryClient } = createWrapper();
        const { result, unmount } = renderHook(() => useRegenerateRecoveryCodes(), { wrapper });

        act(() => {
            result.current.mutate({ code: '123456' });
        });
        await waitFor(() => expect(result.current.isSuccess).toBe(true));
        expect(queryClient.getMutationCache().getAll()).toHaveLength(1);

        unmount();
        await waitFor(() => expect(queryClient.getMutationCache().getAll()).toHaveLength(0));
    });
});

describe('profile + password mutations', () => {
    it('useUpdateProfile calls accountApi.updateProfile with the given body', async () => {
        accountMock.updateProfile.mockResolvedValueOnce({});
        const { wrapper } = createWrapper();
        const { result } = renderHook(() => useUpdateProfile(), { wrapper });

        act(() => {
            result.current.mutate({ display_name: 'Ada', email: 'ada@example.com' });
        });
        await waitFor(() => expect(result.current.isSuccess).toBe(true));
        expect(accountMock.updateProfile).toHaveBeenCalledWith({ display_name: 'Ada', email: 'ada@example.com' });
    });

    it('useChangePassword calls accountApi.changePassword with the given body', async () => {
        accountMock.changePassword.mockResolvedValueOnce({});
        const { wrapper } = createWrapper();
        const { result } = renderHook(() => useChangePassword(), { wrapper });

        act(() => {
            result.current.mutate({ current_password: 'old', new_password: 'new' });
        });
        await waitFor(() => expect(result.current.isSuccess).toBe(true));
        expect(accountMock.changePassword).toHaveBeenCalledWith({ current_password: 'old', new_password: 'new' });
    });
});

describe('active sessions', () => {
    it('useSessions fetches the session list', async () => {
        accountMock.listSessions.mockResolvedValueOnce([{ id: 1 }]);
        const { wrapper } = createWrapper();
        const { result } = renderHook(() => useSessions(), { wrapper });

        await waitFor(() => expect(result.current.isSuccess).toBe(true));
        expect(result.current.data).toEqual([{ id: 1 }]);
    });

    it('useRevokeSession revokes a session and invalidates the sessions query', async () => {
        accountMock.listSessions.mockResolvedValue([]);
        accountMock.revokeSession.mockResolvedValueOnce({});
        const { wrapper, queryClient } = createWrapper();
        const invalidateSpy = vi.spyOn(queryClient, 'invalidateQueries');
        const { result } = renderHook(() => useRevokeSession(), { wrapper });

        act(() => {
            result.current.mutate(7);
        });
        await waitFor(() => expect(result.current.isSuccess).toBe(true));
        expect(accountMock.revokeSession).toHaveBeenCalledWith(7);
        expect(invalidateSpy).toHaveBeenCalledWith({ queryKey: ['account-sessions'] });
    });
});

describe('personal access tokens', () => {
    it('usePersonalTokens fetches the token list', async () => {
        personalTokensMock.listTokens.mockResolvedValueOnce([{ id: 1 }]);
        const { wrapper } = createWrapper();
        const { result } = renderHook(() => usePersonalTokens(), { wrapper });

        await waitFor(() => expect(result.current.isSuccess).toBe(true));
        expect(result.current.data).toEqual([{ id: 1 }]);
    });

    it('useRevokePersonalToken revokes a token and invalidates the tokens query', async () => {
        personalTokensMock.listTokens.mockResolvedValue([]);
        personalTokensMock.revokeToken.mockResolvedValueOnce({});
        const { wrapper, queryClient } = createWrapper();
        const invalidateSpy = vi.spyOn(queryClient, 'invalidateQueries');
        const { result } = renderHook(() => useRevokePersonalToken(), { wrapper });

        act(() => {
            result.current.mutate(3);
        });
        await waitFor(() => expect(result.current.isSuccess).toBe(true));
        expect(personalTokensMock.revokeToken).toHaveBeenCalledWith(3);
        expect(invalidateSpy).toHaveBeenCalledWith({ queryKey: ['account-tokens'] });
    });
});

describe('MFA self-service', () => {
    it('useMfaRecoveryStatus fetches the recovery-code status', async () => {
        mfaMock.recoveryCodesStatus.mockResolvedValueOnce({ total: 5, remaining: 3 });
        const { wrapper } = createWrapper();
        const { result } = renderHook(() => useMfaRecoveryStatus(), { wrapper });

        await waitFor(() => expect(result.current.isSuccess).toBe(true));
        expect(result.current.data).toEqual({ total: 5, remaining: 3 });
    });

    it('useDisableMfa disables MFA and invalidates the recovery-status query', async () => {
        mfaMock.recoveryCodesStatus.mockResolvedValue({ total: 0, remaining: 0 });
        mfaMock.disable.mockResolvedValueOnce({});
        const { wrapper, queryClient } = createWrapper();
        const invalidateSpy = vi.spyOn(queryClient, 'invalidateQueries');
        const { result } = renderHook(() => useDisableMfa(), { wrapper });

        act(() => {
            result.current.mutate({ code: '123456' });
        });
        await waitFor(() => expect(result.current.isSuccess).toBe(true));
        expect(mfaMock.disable).toHaveBeenCalledWith({ code: '123456' });
        expect(invalidateSpy).toHaveBeenCalledWith({ queryKey: ['account-mfa-recovery'] });
    });
});
