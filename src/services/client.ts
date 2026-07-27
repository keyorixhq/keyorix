import axios, { AxiosInstance, AxiosRequestConfig, AxiosResponse, AxiosError } from 'axios';
import { useAuthStore, shouldRefreshToken, isTokenExpired } from '../store/authStore';
import { getEnvConfig } from '../utils';
import { getCsrfToken, CSRF_HEADER_NAME, CSRF_PROTECTED_METHODS } from '../utils/auth';

const config = getEnvConfig();

const logError = (error: AxiosError) => {
    if (getEnvConfig().ENABLE_DEBUG) {
        console.error(`[API Error] ${error.config?.method?.toUpperCase()} ${error.config?.url}`, {
            status: error.response?.status,
            data: error.response?.data,
            message: error.message,
        });
    }
};

export const apiClient: AxiosInstance = axios.create({
    baseURL: '',
    timeout: config.API_TIMEOUT,
    withCredentials: true,
    headers: {
        'Content-Type': 'application/json',
    },
});

apiClient.interceptors.request.use(
    async (interceptorConfig) => {
        const authStore = useAuthStore.getState();

        const isAuthEndpoint =
            interceptorConfig.url?.includes('/auth/login') || interceptorConfig.url?.includes('/auth/refresh');

        // The session itself now rides an httpOnly cookie the browser attaches
        // automatically (withCredentials: true, below) — this interceptor no
        // longer reads or attaches a token. It still owns proactive refresh
        // scheduling: expiry bookkeeping lives in separate localStorage keys
        // (utils/auth.ts), not the token itself, so this needs no other change.
        if (!isAuthEndpoint && authStore.isAuthenticated) {
            if (isTokenExpired()) {
                await authStore.logout();
                throw new Error('Session expired');
            }

            if (shouldRefreshToken()) {
                await authStore.refreshToken();
            }
        }

        const method = interceptorConfig.method?.toLowerCase();
        if (method && CSRF_PROTECTED_METHODS.has(method)) {
            const csrfToken = getCsrfToken();
            if (csrfToken) {
                interceptorConfig.headers[CSRF_HEADER_NAME] = csrfToken;
            }
        }

        interceptorConfig.headers['X-Request-ID'] = `req_${Date.now()}_${crypto.randomUUID().slice(0, 8)}`;

        return interceptorConfig;
    },
    (error) => {
        logError(error);
        throw error;
    }
);

const handle401 = async (error: AxiosError, authStore: ReturnType<typeof useAuthStore.getState>): Promise<AxiosResponse | void> => {
    if (!authStore.isAuthenticated) {
        return;
    }
    if (error.config?.url?.includes('/auth/refresh')) {
        await authStore.logout();
        authStore.setError('Your session has expired. Please log in again.');
        return;
    }
    try {
        await authStore.refreshToken();
        // The retry rides the rotated session cookie automatically —
        // no header to reattach, unlike the old Bearer-token flow.
        if (error.config) {
            return apiClient.request(error.config);
        }
    } catch {
        await authStore.logout();
        authStore.setError('Your session has expired. Please log in again.');
    }
};

const handle403 = (error: AxiosError, authStore: ReturnType<typeof useAuthStore.getState>): void => {
    // ADR-025: a restricted account is blocked from everything but the
    // password change. Route it to the profile page rather than just
    // showing a permission error (robust across reloads / a lost flag).
    const code = (error.response?.data as { error?: string } | undefined)?.error;
    if (code === 'PasswordChangeRequired') {
        if (!window.location.pathname.startsWith('/profile')) {
            window.location.href = '/profile';
        }
    } else {
        authStore.setError('You do not have permission to perform this action.');
    }
};

const handleErrorByStatus = async (error: AxiosError, authStore: ReturnType<typeof useAuthStore.getState>): Promise<AxiosResponse | void> => {
    const status = error.response?.status;
    if (status === 401) {
        return handle401(error, authStore);
    }
    if (status === 403) {
        handle403(error, authStore);
    } else if (status === 429) {
        authStore.setError('Too many requests. Please wait a moment and try again.');
    } else if (status && status >= 500) {
        authStore.setError('Server error. Please try again later.');
    } else if (error.code === 'ECONNABORTED') {
        authStore.setError('Request timeout. Please check your connection and try again.');
    } else if (!error.response) {
        authStore.setError('Network error. Please check your connection.');
    }
};

apiClient.interceptors.response.use(
    (response: AxiosResponse) => {
        return response;
    },
    async (error: AxiosError) => {
        logError(error);

        const authStore = useAuthStore.getState();
        const result = await handleErrorByStatus(error, authStore);
        if (result !== undefined) {
            return result;
        }

        throw error;
    }
);

export const makeAuthenticatedRequest = async <T>(reqConfig: AxiosRequestConfig): Promise<T> => {
    const response = await apiClient.request<T>(reqConfig);
    return response.data;
};

// apiErrorMessage extracts the human-readable reason from an API error, preferring
// the server's `message` (e.g. a validation reason like "secret value is a known weak
// or placeholder value") over the `error` type code. Use this where the message is
// shown to the user; handleApiError keeps its legacy code-first ordering.
export const apiErrorMessage = (error: unknown): string => {
    if (axios.isAxiosError(error)) {
        const data = error.response?.data as { message?: string; error?: string } | undefined;
        if (data?.message) return data.message;
        if (data?.error) return data.error;
        if (error.message) return error.message;
    }
    if (error instanceof Error) return error.message;
    return 'An unexpected error occurred';
};

export const handleApiError = (error: unknown): string => {
    if (axios.isAxiosError(error)) {
        if (error.response?.data?.error) {
            return error.response.data.error;
        }
        if (error.response?.data?.message) {
            return error.response.data.message;
        }
        if (error.message) {
            return error.message;
        }
    }

    if (error instanceof Error) {
        return error.message;
    }

    return 'An unexpected error occurred';
};
