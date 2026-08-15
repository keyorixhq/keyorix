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

import { personalTokensApi } from '../../../services/personalTokens';
import { mfaApi } from '../../../services/mfa';
import { useCreatePersonalToken, useEnrollMfa, useActivateMfa, useRegenerateRecoveryCodes } from '../index';

const personalTokensMock = personalTokensApi as unknown as { createToken: ReturnType<typeof vi.fn> };
const mfaMock = mfaApi as unknown as {
    enroll: ReturnType<typeof vi.fn>;
    activate: ReturnType<typeof vi.fn>;
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
