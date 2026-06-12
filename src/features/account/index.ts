import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { accountApi } from '../../services/account';
import { personalTokensApi, type CreatePersonalTokenBody } from '../../services/personalTokens';

const SESSIONS_KEY = 'account-sessions';
const TOKENS_KEY = 'account-tokens';

// ── Profile + password ──────────────────────────────────────────────────────

export const useUpdateProfile = () =>
    useMutation({
        mutationFn: (body: { display_name: string; email: string }) =>
            accountApi.updateProfile(body),
    });

export const useChangePassword = () =>
    useMutation({
        mutationFn: (body: { current_password: string; new_password: string }) =>
            accountApi.changePassword(body),
    });

// ── Active sessions ───────────────────────────────────────────────────────────

export const useSessions = () =>
    useQuery({
        queryKey: [SESSIONS_KEY],
        queryFn: () => accountApi.listSessions(),
        staleTime: 30 * 1000,
    });

export const useRevokeSession = () => {
    const queryClient = useQueryClient();
    return useMutation({
        mutationFn: (id: number) => accountApi.revokeSession(id),
        onSuccess: () => queryClient.invalidateQueries({ queryKey: [SESSIONS_KEY] }),
    });
};

// ── Personal access tokens ─────────────────────────────────────────────────────

export const usePersonalTokens = () =>
    useQuery({
        queryKey: [TOKENS_KEY],
        queryFn: () => personalTokensApi.listTokens(),
        staleTime: 60 * 1000,
    });

export const useCreatePersonalToken = () => {
    const queryClient = useQueryClient();
    return useMutation({
        mutationFn: (body: CreatePersonalTokenBody) => personalTokensApi.createToken(body),
        onSuccess: () => queryClient.invalidateQueries({ queryKey: [TOKENS_KEY] }),
    });
};

export const useRevokePersonalToken = () => {
    const queryClient = useQueryClient();
    return useMutation({
        mutationFn: (id: number) => personalTokensApi.revokeToken(id),
        onSuccess: () => queryClient.invalidateQueries({ queryKey: [TOKENS_KEY] }),
    });
};
