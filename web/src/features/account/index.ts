import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { accountApi } from '../../services/account';
import { personalTokensApi, type CreatePersonalTokenBody } from '../../services/personalTokens';
import { mfaApi } from '../../services/mfa';
import { SENSITIVE_GC_TIME } from '../../lib/queryClient';

const SESSIONS_KEY = 'account-sessions';
const TOKENS_KEY = 'account-tokens';
const MFA_RECOVERY_KEY = 'account-mfa-recovery';

// ── Profile + password ──────────────────────────────────────────────────────

export const useUpdateProfile = () =>
    useMutation({
        mutationFn: (body: { display_name: string; email: string }) => accountApi.updateProfile(body),
    });

export const useChangePassword = () =>
    useMutation({
        mutationFn: (body: { current_password: string; new_password: string }) => accountApi.changePassword(body),
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
        // G28: the response is a one-time bearer token — don't let react-query's
        // MutationCache retain it for the default 5 minutes after unmount.
        gcTime: SENSITIVE_GC_TIME,
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
//
// #2441 (follow-on): `enabled` defaults to true, but MfaSection passes
// `!enrolling` -- this query MUST be inactive for the whole time the
// enrollment modal is open, not just skip an explicit invalidate (see
// useActivateMfa's doc comment for the session-invalidation race this
// avoids). The query client's global `refetchOnWindowFocus: true` default
// refetches EVERY active query -- not just ones explicitly invalidated -- the
// moment the window/tab regains focus, which happened reliably in practice
// (confirmed live: Playwright's own focus handling around a button click was
// enough to trigger it). An inactive (enabled: false) query is excluded from
// that batch entirely, which a deferred invalidateQueries call is not.
export const useMfaRecoveryStatus = (enabled = true) =>
    useQuery({
        queryKey: [MFA_RECOVERY_KEY],
        queryFn: () => mfaApi.recoveryCodesStatus(),
        staleTime: 30 * 1000,
        enabled,
    });

// useInvalidateMfaRecoveryStatus lets a caller refresh the recovery-code
// status on ITS OWN terms, rather than automatically the instant an MFA
// mutation succeeds -- see useActivateMfa's doc comment for why enrollment
// specifically must not auto-invalidate.
export const useInvalidateMfaRecoveryStatus = () => {
    const queryClient = useQueryClient();
    return () => queryClient.invalidateQueries({ queryKey: [MFA_RECOVERY_KEY] });
};

// G28: enroll returns the TOTP setup secret, and activate returns the freshly
// minted recovery codes — both plaintext. Don't let react-query's MutationCache
// retain either for the default 5 minutes after unmount.
export const useEnrollMfa = () => useMutation({ mutationFn: () => mfaApi.enroll(), gcTime: SENSITIVE_GC_TIME });

// #2441 (follow-on): deliberately does NOT invalidate [MFA_RECOVERY_KEY] here.
// internal/core/mfa.go's ActivateMFA invalidates every session minted before
// MFA was enabled -- including the CURRENT one making this very call -- as
// soon as it succeeds (a real, intentional security upgrade: a pre-MFA
// session must not outlive it). MfaSection (the parent of the enrollment
// modal that calls this hook) stays mounted throughout and holds an ACTIVE
// useMfaRecoveryStatus observer on that same query key -- invalidating it
// here triggers an immediate background refetch, which 401s against the
// now-invalid session, which the apiClient response interceptor turns into
// an automatic refresh-then-logout, hard-navigating to /login via
// window.location.href. Confirmed live: that redirect can tear the recovery-
// codes screen down before the user has read or copied their one-time
// codes -- their only chance to save them. The caller (EnrollModal) now
// invalidates this query itself, from its close() handler, once the user has
// actually finished with the codes screen -- see that component's comment.
export const useActivateMfa = () =>
    useMutation({
        // #2441: the account password is required alongside the code -- see
        // mfaApi.activate's own doc comment.
        mutationFn: (proof: { code: string; password: string }) => mfaApi.activate(proof.code, proof.password),
        gcTime: SENSITIVE_GC_TIME,
    });

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
        mutationFn: (proof: { code?: string; password?: string }) => mfaApi.regenerateRecoveryCodes(proof),
        onSuccess: () => queryClient.invalidateQueries({ queryKey: [MFA_RECOVERY_KEY] }),
        // G28: the response is the freshly minted recovery codes (plaintext).
        gcTime: SENSITIVE_GC_TIME,
    });
};
