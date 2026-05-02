import axios, { AxiosResponse } from 'axios';
import {
    LoginFormData,
    LoginResponse,
    RefreshTokenResponse,
    PasswordResetRequest,
    PasswordResetConfirm,
    User,
    ApiResponse
} from '../types';
import { API_ENDPOINTS } from '../constants';
import { getEnvConfig } from '../utils';

const config = getEnvConfig();

// Create axios instance for auth requests (separate from main API client to avoid circular dependencies)
const authApi = axios.create({
    baseURL: config.API_BASE_URL,
    timeout: config.API_TIMEOUT,
    withCredentials: true, // Important for HTTP-only cookies
});

// Add Bearer token from persisted auth state for endpoints that require it (e.g. /auth/refresh)
authApi.interceptors.request.use((requestConfig) => {
    try {
        const raw = localStorage.getItem('auth-storage');
        if (raw) {
            const parsed = JSON.parse(raw);
            const token: string | null = parsed?.state?.token ?? null;
            if (token) {
                requestConfig.headers.Authorization = `Bearer ${token}`;
            }
        }
    } catch {
        // Silently ignore — request proceeds without the header
    }
    return requestConfig;
});

// Auth service functions
export const authService = {
    /**
     * Login user with email and password
     */
    async login(credentials: LoginFormData): Promise<LoginResponse> {
        try {
            const response: AxiosResponse<ApiResponse<LoginResponse>> = await authApi.post(
                API_ENDPOINTS.AUTH.LOGIN,
                {
                    username: credentials.username,
                    password: credentials.password,
                    rememberMe: credentials.rememberMe,
                }
            );

            if (!response.data.data?.token) {
                throw new Error(response.data.message || 'Login failed');
            }

            return response.data.data;
        } catch (error) {
            if (axios.isAxiosError(error)) {
                const message = error.response?.data?.error || error.response?.data?.message || 'Login failed';
                throw new Error(message);
            }
            throw error;
        }
    },

    /**
     * Logout user and invalidate session
     */
    async logout(): Promise<void> {
        try {
            await authApi.post(API_ENDPOINTS.AUTH.LOGOUT);
        } catch (error) {
            // Even if logout fails on server, we should clear local state
            console.warn('Logout request failed:', error);
        }
    },

    /**
     * Refresh authentication token
     */
    async refreshToken(): Promise<RefreshTokenResponse> {
        try {
            const response: AxiosResponse<ApiResponse<RefreshTokenResponse>> = await authApi.post(
                API_ENDPOINTS.AUTH.REFRESH
            );

            if (!response.data.data?.token) {
                throw new Error(response.data.message || 'Token refresh failed');
            }

            return response.data.data;
        } catch (error) {
            if (axios.isAxiosError(error)) {
                const message = error.response?.data?.error || error.response?.data?.message || 'Token refresh failed';
                throw new Error(message);
            }
            throw error;
        }
    },

    /**
     * Get current user profile
     */
    async getProfile(): Promise<User> {
        try {
            const response: AxiosResponse<ApiResponse<User>> = await authApi.get(
                API_ENDPOINTS.AUTH.PROFILE
            );

            if (!response.data.data) {
                throw new Error(response.data.message || 'Failed to get profile');
            }

            return response.data.data;
        } catch (error) {
            if (axios.isAxiosError(error)) {
                const message = error.response?.data?.error || error.response?.data?.message || 'Failed to get profile';
                throw new Error(message);
            }
            throw error;
        }
    },

    /**
     * Request password reset
     */
    async requestPasswordReset(data: PasswordResetRequest): Promise<void> {
        try {
            const response: AxiosResponse<ApiResponse<void>> = await authApi.post(
                '/api/auth/password-reset',
                data
            );

            if (!response.data.message) {
                throw new Error('Password reset request failed');
            }
        } catch (error) {
            if (axios.isAxiosError(error)) {
                const message = error.response?.data?.error || error.response?.data?.message || 'Password reset request failed';
                throw new Error(message);
            }
            throw error;
        }
    },

    /**
     * Confirm password reset with token
     */
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
                throw new Error(message);
            }
            throw error;
        }
    },

    /**
     * Check if user is authenticated by validating current session
     */
    async checkAuth(): Promise<User | null> {
        try {
            return await this.getProfile();
        } catch (error) {
            return null;
        }
    },
};

// Export the axios instance for use in other services
export { authApi };