import { apiClient } from './client';

// Self-service TOTP MFA API (Profile → Security). All endpoints are scoped to the
// authenticated user — see the Go backend's /api/v1/auth/mfa/* routes.

export interface MfaEnrollment {
    otpauth_uri: string;
    secret: string;
}

export interface RecoveryCodesStatus {
    remaining: number;
    total: number;
}

// MfaReauthProof is what the security-factor-change endpoints accept from this UI:
// a current authenticator code, and nothing else. See disable() below.
export interface MfaReauthProof {
    code: string;
}

export const mfaApi = {
    // Begin enrolment: returns the otpauth:// URI (for a QR) and the base32 secret.
    async enroll(): Promise<MfaEnrollment> {
        const response = await apiClient.post('/api/v1/auth/mfa/enroll', {});
        return response.data.data as MfaEnrollment;
    },

    // Confirm enrolment with a TOTP code; returns the one-time recovery codes.
    // Requires the account password too (#2441): server/http/handlers/mfa.go's
    // ActivateMFA re-authenticates the caller via requireReauth, which falls
    // through to the password-compare branch during enrolment (MFAEnabled is
    // still false at this point, so its TOTP-step-up branch never applies) —
    // the code alone proves control of the just-generated pending secret, not
    // that this is really the account holder.
    async activate(code: string, password: string): Promise<string[]> {
        const response = await apiClient.post('/api/v1/auth/mfa/activate', { code, password });
        return (response.data.data?.recovery_codes ?? []) as string[];
    },

    // Disable MFA after re-auth with a CURRENT authenticator code.
    //
    // #2738: the proof type is deliberately code-only. The endpoint also reads a
    // `password` field, but internal/core's requireReauth refuses the password alone
    // once a second factor is enrolled, and its password-accepting branch
    // additionally requires a live MFAStepUpPurposeReauth grant that no web login
    // flow mints — so a password submitted from this UI is always refused. Typing it
    // isn't representable here, which is what the old "code or password" label
    // invited and what made the dialog look broken.
    async disable(proof: MfaReauthProof): Promise<void> {
        await apiClient.post('/api/v1/auth/mfa/disable', proof);
    },

    // How many recovery codes remain unused (total 0 ⇒ MFA not enabled).
    async recoveryCodesStatus(): Promise<RecoveryCodesStatus> {
        const response = await apiClient.get('/api/v1/auth/mfa/recovery-codes');
        return response.data.data as RecoveryCodesStatus;
    },

    // Replace all recovery codes after re-auth with a current authenticator code;
    // returns the new one-time codes. Same code-only proof as disable() — see there.
    async regenerateRecoveryCodes(proof: MfaReauthProof): Promise<string[]> {
        const response = await apiClient.post('/api/v1/auth/mfa/recovery-codes/regenerate', proof);
        return (response.data.data?.recovery_codes ?? []) as string[];
    },
};
