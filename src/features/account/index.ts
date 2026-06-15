import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { accountApi } from '../../services/account';
import { personalTokensApi, type CreatePersonalTokenBody } from '../../services/personalTokens';
import { mfaApi } from '../../services/mfa';

const SESSIONS_KEY = 'account-sessions';
const TOKENS_KEY = 'account-tokens';
const MFA_RECOVERY_KEY = 'account-mfa-recovery';

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

// ── MFA (TOTP) self-service ─────────────────────────────────────────────────

// Recovery-code status doubles as the MFA-enabled signal: total === 0 ⇒ MFA off
// (no codes), total > 0 ⇒ enabled with `remaining` unused.
export const useMfaRecoveryStatus = () =>
    useQuery({
        queryKey: [MFA_RECOVERY_KEY],
        queryFn: () => mfaApi.recoveryCodesStatus(),
        staleTime: 30 * 1000,
    });

export const useEnrollMfa = () =>
    useMutation({ mutationFn: () => mfaApi.enroll() });

export const useActivateMfa = () => {
    const queryClient = useQueryClient();
    return useMutation({
        mutationFn: (code: string) => mfaApi.activate(code),
        onSuccess: () => queryClient.invalidateQueries({ queryKey: [MFA_RECOVERY_KEY] }),
    });
};

export const useDisableMfa = () => {
    const queryClient = useQueryClient();
    return useMutation({
        mutationFn: (proof: { code?: string; password?: string }) => mfaApi.disable(proof),
        onSuccess: () => queryClient.invalidateQueries({ queryKey: [MFA_RECOVERY_KEY] }),
    });
};

export const useRegenerateRecoveryCodes = () => {
    const queryClient = useQueryClient();
    return useMutation({
        mutationFn: (proof: { code?: string; password?: string }) =>
            mfaApi.regenerateRecoveryCodes(proof),
        onSuccess: () => queryClient.invalidateQueries({ queryKey: [MFA_RECOVERY_KEY] }),
    });
};
