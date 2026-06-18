import axios, { AxiosInstance, AxiosRequestConfig, AxiosResponse, AxiosError } from 'axios';
import { useAuthStore, shouldRefreshToken, isTokenExpired } from '../store/authStore';
import { getEnvConfig } from '../utils';

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

        const isAuthEndpoint = interceptorConfig.url?.includes('/auth/login') ||
            interceptorConfig.url?.includes('/auth/refresh');

        if (!isAuthEndpoint && authStore.isAuthenticated) {
            if (isTokenExpired()) {
                await authStore.logout();
                throw new Error('Session expired');
            }

            if (shouldRefreshToken()) {
                await authStore.refreshToken();
            }

            if (authStore.token) {
                interceptorConfig.headers.Authorization = `Bearer ${authStore.token}`;
            }
        }

        interceptorConfig.headers['X-Request-ID'] = `req_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;

        return interceptorConfig;
    },
    (error) => {
        logError(error);
        return Promise.reject(error);
    }
);

apiClient.interceptors.response.use(
    (response: AxiosResponse) => {
        return response;
    },
    async (error: AxiosError) => {
        logError(error);

        const authStore = useAuthStore.getState();

        if (error.response?.status === 401) {
            if (authStore.isAuthenticated) {
                if (!error.config?.url?.includes('/auth/refresh')) {
                    try {
                        await authStore.refreshToken();

                        if (error.config) {
                            const newToken = useAuthStore.getState().token;
                            if (newToken) {
                                error.config.headers.Authorization = `Bearer ${newToken}`;
                                return apiClient.request(error.config);
                            }
                        }
                    } catch {
                        await authStore.logout();
                        authStore.setError('Your session has expired. Please log in again.');
                    }
                } else {
                    await authStore.logout();
                    authStore.setError('Your session has expired. Please log in again.');
                }
            }
        } else if (error.response?.status === 403) {
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
        } else if (error.response?.status === 429) {
            authStore.setError('Too many requests. Please wait a moment and try again.');
        } else if (error.response?.status && error.response.status >= 500) {
            authStore.setError('Server error. Please try again later.');
        } else if (error.code === 'ECONNABORTED') {
            authStore.setError('Request timeout. Please check your connection and try again.');
        } else if (!error.response) {
            authStore.setError('Network error. Please check your connection.');
        }

        return Promise.reject(error);
    }
);

export const makeAuthenticatedRequest = async <T>(
    reqConfig: AxiosRequestConfig
): Promise<T> => {
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
