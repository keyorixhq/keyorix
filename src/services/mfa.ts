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

export const mfaApi = {
    // Begin enrolment: returns the otpauth:// URI (for a QR) and the base32 secret.
    async enroll(): Promise<MfaEnrollment> {
        const response = await apiClient.post('/api/v1/auth/mfa/enroll', {});
        return response.data.data as MfaEnrollment;
    },

    // Confirm enrolment with a TOTP code; returns the one-time recovery codes.
    async activate(code: string): Promise<string[]> {
        const response = await apiClient.post('/api/v1/auth/mfa/activate', { code });
        return (response.data.data?.recovery_codes ?? []) as string[];
    },

    // Disable MFA after re-auth with a current code or the account password.
    async disable(proof: { code?: string; password?: string }): Promise<void> {
        await apiClient.post('/api/v1/auth/mfa/disable', proof);
    },

    // How many recovery codes remain unused (total 0 ⇒ MFA not enabled).
    async recoveryCodesStatus(): Promise<RecoveryCodesStatus> {
        const response = await apiClient.get('/api/v1/auth/mfa/recovery-codes');
        return response.data.data as RecoveryCodesStatus;
    },

    // Replace all recovery codes after re-auth; returns the new one-time codes.
    async regenerateRecoveryCodes(proof: { code?: string; password?: string }): Promise<string[]> {
        const response = await apiClient.post('/api/v1/auth/mfa/recovery-codes/regenerate', proof);
        return (response.data.data?.recovery_codes ?? []) as string[];
    },
};
