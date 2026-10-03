import axios, { AxiosResponse } from 'axios';
import {
    LoginFormData,
    LoginResponse,
    MfaRequiredResponse,
    RefreshTokenResponse,
    PasswordResetRequest,
    PasswordResetConfirm,
    User,
    ApiResponse,
    ProfileImpersonation,
} from '../types';
import { API_ENDPOINTS } from '../constants';
import { generateId } from '../utils';
import { getEnvConfig } from '../utils';
import { getCsrfToken, CSRF_HEADER_NAME, CSRF_PROTECTED_METHODS } from '../utils/auth';

const config = getEnvConfig();

// Separate instance for auth endpoints to avoid the circular import that would
// arise from auth.ts → client.ts → authStore.ts → auth.ts. The auth surface
// needs no proactive-refresh interceptor (it IS the refresh); it does need CSRF
// and a consistent X-Request-ID for log correlation, both wired below.
const authApi = axios.create({
    baseURL: '',
    timeout: config.API_TIMEOUT,
    withCredentials: true, // sends/receives the httpOnly session cookie
    headers: { 'Content-Type': 'application/json' },
});

authApi.interceptors.request.use((requestConfig) => {
    // CSRF double-submit on state-changing requests.
    const method = requestConfig.method?.toLowerCase();
    if (method && CSRF_PROTECTED_METHODS.has(method)) {
        const csrfToken = getCsrfToken();
        if (csrfToken) {
            requestConfig.headers[CSRF_HEADER_NAME] = csrfToken;
        }
    }
    // Consistent request ID for log correlation (matches apiClient).
    requestConfig.headers['X-Request-ID'] = `req_${Date.now()}_${generateId().slice(0, 8)}`;
    return requestConfig;
});

// Auth service functions
export const authService = {
    // #2442: the response is LoginResponse on a completed login, OR
    // MfaRequiredResponse (same HTTP 200) when the account has MFA enabled --
    // the caller (authStore.login) must check `mfa_required` before treating
    // this as an authenticated session.
    async login(credentials: LoginFormData): Promise<LoginResponse | MfaRequiredResponse> {
        try {
            const response: AxiosResponse<ApiResponse<LoginResponse | MfaRequiredResponse>> = await authApi.post(
                API_ENDPOINTS.AUTH.LOGIN,
                {
                    username: credentials.username,
                    password: credentials.password,
                    rememberMe: credentials.rememberMe,
                }
            );

            if (!response.data.data) {
                throw new Error(response.data.message || 'Login failed');
            }

            return response.data.data;
        } catch (error) {
            if (axios.isAxiosError(error)) {
                const message = error.response?.data?.error || error.response?.data?.message || 'Login failed';
                throw new Error(message, { cause: error });
            }
            throw error;
        }
    },

    // #2442: completes a two-step MFA login -- consumes the challenge from a
    // prior login() call's MfaRequiredResponse, along with a TOTP or recovery
    // code (server/http/handlers/mfa.go's VerifyMFA accepts either). Returns
    // a real LoginResponse and sets the session cookie, exactly like login()
    // on a non-MFA account.
    async verifyMfa(challenge: string, code: string): Promise<LoginResponse> {
        try {
            const response: AxiosResponse<ApiResponse<LoginResponse>> = await authApi.post(
                API_ENDPOINTS.AUTH.MFA_VERIFY,
                { mfa_challenge: challenge, code }
            );

            if (!response.data.data) {
                throw new Error(response.data.message || 'Invalid or expired code');
            }

            return response.data.data;
        } catch (error) {
            if (axios.isAxiosError(error)) {
                // message-first (not .error-first like this file's other
                // catch blocks): VerifyMFA's error response is always
                // {error: "Unauthorized", message: "Invalid or expired
                // code"} regardless of cause (wrong code, expired challenge,
                // locked account) -- showing the generic "Unauthorized" type
                // instead of the actual message would be less informative
                // than what the API provides, not "no more specific."
                const message =
                    error.response?.data?.message || error.response?.data?.error || 'Invalid or expired code';
                throw new Error(message, { cause: error });
            }
            throw error;
        }
    },

    async logout(): Promise<void> {
        // Deliberately does NOT swallow a failed server-side session
        // invalidation (G65) — the caller (authStore.logout()) still clears
        // all local client-side state as a fail-safe regardless of the
        // outcome here, but it needs the rejection to know the server-side
        // session may still be valid and surface that to the user, instead
        // of silently reporting a clean logout. Mirrors the
        // catch-and-rethrow-with-message shape used by login()/refreshToken()
        // above.
        try {
            await authApi.post(API_ENDPOINTS.AUTH.LOGOUT);
        } catch (error) {
            if (axios.isAxiosError(error)) {
                const message = error.response?.data?.error || error.response?.data?.message || 'Logout failed';
                throw new Error(message, { cause: error });
            }
            throw error;
        }
    },

    async endImpersonation(): Promise<void> {
        await authApi.post('/api/v1/auth/end-impersonation');
    },

    async refreshToken(): Promise<RefreshTokenResponse> {
        try {
            const response: AxiosResponse<ApiResponse<RefreshTokenResponse>> = await authApi.post(
                API_ENDPOINTS.AUTH.REFRESH
            );

            if (!response.data.data) {
                throw new Error(response.data.message || 'Token refresh failed');
            }

            return response.data.data;
        } catch (error) {
            if (axios.isAxiosError(error)) {
                const message = error.response?.data?.error || error.response?.data?.message || 'Token refresh failed';
                throw new Error(message, { cause: error });
            }
            throw error;
        }
    },

    /**
     * Get current user profile. `impersonation` is present only while the
     * current session is impersonating another user — server-validated from
     * the session cookie, not a client-supplied claim.
     */
    async getProfile(): Promise<User & { impersonation?: ProfileImpersonation }> {
        try {
            const response: AxiosResponse<ApiResponse<User & { impersonation?: ProfileImpersonation }>> =
                await authApi.get(API_ENDPOINTS.AUTH.PROFILE);

            if (!response.data.data) {
                throw new Error(response.data.message || 'Failed to get profile');
            }

            return response.data.data;
        } catch (error) {
            if (axios.isAxiosError(error)) {
                const message = error.response?.data?.error || error.response?.data?.message || 'Failed to get profile';
                throw new Error(message, { cause: error });
            }
            throw error;
        }
    },

    async getSSOProviders(): Promise<string[]> {
        try {
            const response = await authApi.get('/auth/sso/providers');
            return response.data?.data?.providers ?? [];
        } catch {
            return []; // SSO not configured / endpoint absent
        }
    },

    async requestPasswordReset(data: PasswordResetRequest): Promise<void> {
        try {
            const response: AxiosResponse<ApiResponse<void>> = await authApi.post('/api/auth/password-reset', data);

            if (!response.data.message) {
                throw new Error('Password reset request failed');
            }
        } catch (error) {
            if (axios.isAxiosError(error)) {
                const message =
                    error.response?.data?.error || error.response?.data?.message || 'Password reset request failed';
                throw new Error(message, { cause: error });
            }
            throw error;
        }
    },

    async confirmPasswordReset(data: PasswordResetConfirm): Promise<void> {
        try {
            const response: AxiosResponse<ApiResponse<void>> = await authApi.post(
                '/api/auth/password-reset/confirm',
                data
            );

            if (!response.data.message) {
                throw new Error('Password reset failed');
            }
        } catch (error) {
            if (axios.isAxiosError(error)) {
                const message = error.response?.data?.error || error.response?.data?.message || 'Password reset failed';
                throw new Error(message, { cause: error });
            }
            throw error;
        }
    },

    async checkAuth(): Promise<User | null> {
        try {
            return await this.getProfile();
        } catch {
            return null;
        }
    },
};
