import axios, { AxiosInstance, AxiosRequestConfig, AxiosResponse, AxiosError } from 'axios';
import { useAuthStore, shouldRefreshToken, isTokenExpired } from '../store/authStore';
import { getEnvConfig } from '../utils';
import {
    ApiResponse,
    PaginatedResponse,
    Secret,
    SecretFormData,
    ShareRecord,
    ShareFormData,
    User,
    Recipient,
    DashboardStats,
    ActivityItem
} from '../types';
import { API_ENDPOINTS } from '../constants';

const config = getEnvConfig();

// Request/Response logging utility
const logRequest = (config: AxiosRequestConfig) => {
    if (getEnvConfig().ENABLE_DEBUG) {
        console.log(`[API Request] ${config.method?.toUpperCase()} ${config.url}`, {
            headers: config.headers,
            data: config.data,
        });
    }
};

const logResponse = (response: AxiosResponse) => {
    if (getEnvConfig().ENABLE_DEBUG) {
        console.log(`[API Response] ${response.status} ${response.config.url}`, {
            data: response.data,
            headers: response.headers,
        });
    }
};

const logError = (error: AxiosError) => {
    console.error(`[API Error] ${error.config?.method?.toUpperCase()} ${error.config?.url}`, {
        status: error.response?.status,
        statusText: error.response?.statusText,
        data: error.response?.data,
        message: error.message,
    });
};

// Create main API client
export const apiClient: AxiosInstance = axios.create({
    baseURL: '',
    timeout: config.API_TIMEOUT,
    withCredentials: true, // Important for HTTP-only cookies
    headers: {
        'Content-Type': 'application/json',
    },
});

// Request interceptor for authentication and logging
apiClient.interceptors.request.use(
    async (config) => {
        // Log request in debug mode
        logRequest(config);

        const authStore = useAuthStore.getState();

        // Skip auth for login/refresh endpoints
        const isAuthEndpoint = config.url?.includes('/auth/login') ||
            config.url?.includes('/auth/refresh');

        if (!isAuthEndpoint && authStore.isAuthenticated) {
            // Check if token is expired
            if (isTokenExpired()) {
                // Token is expired, logout user
                await authStore.logout();
                throw new Error('Session expired');
            }

            // Check if token needs refresh
            if (shouldRefreshToken()) {
                try {
                    await authStore.refreshToken();
                } catch (error) {
                    // Refresh failed, logout will be handled by the store
                    throw error;
                }
            }

            // Add authorization header if we have a token
            if (authStore.token) {
                config.headers.Authorization = `Bearer ${authStore.token}`;
            }
        }

        // Add request ID for tracking
        config.headers['X-Request-ID'] = `req_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;

        return config;
    },
    (error) => {
        logError(error);
        return Promise.reject(error);
    }
);

// Response interceptor for logging and error handling
apiClient.interceptors.response.use(
    (response: AxiosResponse) => {
        // Log response in debug mode
        logResponse(response);
        return response;
    },
    async (error: AxiosError) => {
        // Log error
        logError(error);

        const authStore = useAuthStore.getState();

        if (error.response?.status === 401) {
            // Unauthorized - token might be invalid or expired
            if (authStore.isAuthenticated) {
                // Try to refresh token once
                if (!error.config?.url?.includes('/auth/refresh')) {
                    try {
                        await authStore.refreshToken();

                        // Retry the original request with new token
                        if (error.config) {
                            const newToken = useAuthStore.getState().token;
                            if (newToken) {
                                error.config.headers.Authorization = `Bearer ${newToken}`;
                                return apiClient.request(error.config);
                            }
                        }
                    } catch (refreshError) {
                        // Refresh failed, logout user
                        await authStore.logout();
                        authStore.setError('Your session has expired. Please log in again.');
                    }
                } else {
                    // Refresh endpoint failed, logout user
                    await authStore.logout();
                    authStore.setError('Your session has expired. Please log in again.');
                }
            }
        } else if (error.response?.status === 403) {
            // Forbidden - user doesn't have permission
            authStore.setError('You do not have permission to perform this action.');
        } else if (error.response?.status === 429) {
            // Rate limiting
            authStore.setError('Too many requests. Please wait a moment and try again.');
        } else if (error.response?.status && error.response.status >= 500) {
            // Server error
            authStore.setError('Server error. Please try again later.');
        } else if (error.code === 'ECONNABORTED') {
            // Request timeout
            authStore.setError('Request timeout. Please check your connection and try again.');
        } else if (!error.response) {
            // Network error
            authStore.setError('Network error. Please check your connection.');
        }

        return Promise.reject(error);
    }
);

// Helper function to make authenticated requests
export const makeAuthenticatedRequest = async <T>(
    config: AxiosRequestConfig
): Promise<T> => {
    try {
        const response = await apiClient.request<T>(config);
        return response.data;
    } catch (error) {
        throw error;
    }
};

// Helper function to handle API errors consistently
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

// Typed API service methods
export const apiService = {
    // Secret management
    secrets: {
        async list(params?: {
            page?: number;
            pageSize?: number;
            search?: string;
            type?: string;
            namespace?: string;
            zone?: string;
            environment?: string;
            environment_id?: number;
            tags?: string[];
        }): Promise<PaginatedResponse<Secret>> {
            const response = await apiClient.get(
                API_ENDPOINTS.SECRETS.LIST,
                { params }
            );
            const { secrets, total, page, page_size, total_pages } = response.data.data;
            const mappedSecrets: Secret[] = (secrets ?? []).map((s: any) => ({
                id: s.ID,
                name: s.Name,
                type: s.Type,
                isShared: s.IsShared ?? false,
                shareCount: s.share_count ?? 0,
                lastModified: s.UpdatedAt ?? s.CreatedAt ?? '',
                owner: s.CreatedBy ?? '',
                namespace: s.namespace_name ?? s.namespace ?? 'default',
                zone: s.zone_name ?? s.zone ?? '',
                environment: s.environment_name ?? s.environment ?? 'production',
                tags: [],
                permissions: [],
                metadata: {},
            }));
            return {
                data: mappedSecrets,
                total: total ?? 0,
                page: page ?? 1,
                pageSize: page_size ?? (params?.pageSize ?? 20),
                totalPages: total_pages ?? 1,
            };
        },

        async get(id: number): Promise<Secret> {
            const response = await apiClient.get<ApiResponse<Secret>>(
                API_ENDPOINTS.SECRETS.GET(id)
            );
            return response.data.data;
        },

        async create(data: any): Promise<Secret> {
            const response = await apiClient.post<ApiResponse<Secret>>(
                API_ENDPOINTS.SECRETS.CREATE,
                data
            );
            return response.data.data;
        },

        async update(id: number, data: Partial<SecretFormData>): Promise<Secret> {
            const response = await apiClient.put<ApiResponse<Secret>>(
                API_ENDPOINTS.SECRETS.UPDATE(id),
                data
            );
            return response.data.data;
        },

        async delete(id: number): Promise<void> {
            await apiClient.delete(API_ENDPOINTS.SECRETS.DELETE(id));
        },

        async getVersions(id: number): Promise<{ EncryptedValue: string; VersionNumber: number; CreatedAt: string }[]> {
            const response = await apiClient.get(
                API_ENDPOINTS.SECRETS.VERSIONS(id)
            );
            return response.data.data.versions ?? [];
        },
    },

    // Sharing management
    sharing: {
        async list(params?: {
            page?: number;
            pageSize?: number;
            secretId?: number;
            recipientType?: 'user' | 'group';
        }): Promise<PaginatedResponse<ShareRecord>> {
            const response = await apiClient.get<ApiResponse<PaginatedResponse<ShareRecord>>>(
                API_ENDPOINTS.SHARING.LIST,
                { params }
            );
            return response.data.data;
        },

        async get(id: number): Promise<ShareRecord> {
            const response = await apiClient.get<ApiResponse<ShareRecord>>(
                API_ENDPOINTS.SHARING.GET(id)
            );
            return response.data.data;
        },

        async create(data: ShareFormData & { secretId: number }): Promise<ShareRecord> {
            const response = await apiClient.post<ApiResponse<ShareRecord>>(
                API_ENDPOINTS.SHARING.CREATE(data.secretId),
                {
                    recipient_id: data.recipientId,
                    is_group: data.recipientType === 'group',
                    permission: data.permission,
                }
            );
            return response.data.data;
        },

        async update(id: number, data: Partial<ShareFormData>): Promise<ShareRecord> {
            const response = await apiClient.put<ApiResponse<ShareRecord>>(
                API_ENDPOINTS.SHARING.UPDATE(id),
                data
            );
            return response.data.data;
        },

        async delete(id: number): Promise<void> {
            await apiClient.delete(API_ENDPOINTS.SHARING.DELETE(id));
        },

        async selfRemove(id: number): Promise<void> {
            await apiClient.post(API_ENDPOINTS.SHARING.SELF_REMOVE(id));
        },
    },

    // Environments
    environments: {
        async list(): Promise<{ id: number; name: string }[]> {
            const response = await apiClient.get(API_ENDPOINTS.ENVIRONMENTS.LIST);
            const envs = response.data.data?.environments ?? [];
            return envs.map((e: any) => ({ id: e.ID, name: e.Name }));
        },
    },
    // User management
    users: {
        async list(params?: {
            page?: number;
            pageSize?: number;
            search?: string;
        }): Promise<PaginatedResponse<User>> {
            const response = await apiClient.get<ApiResponse<PaginatedResponse<User>>>(
                API_ENDPOINTS.USERS.LIST,
                { params }
            );
            return response.data.data;
        },

        async get(id: number): Promise<User> {
            const response = await apiClient.get<ApiResponse<User>>(
                API_ENDPOINTS.USERS.GET(id)
            );
            return response.data.data;
        },

        async search(query: string): Promise<Recipient[]> {
            const response = await apiClient.get(
                API_ENDPOINTS.USERS.SEARCH,
                { params: { q: query } }
            );
            const users = response.data.data?.users ?? [];
            return users.map((u: any) => ({
                id: u.id,
                name: u.username,
                type: 'user' as const,
                email: u.email,
            }));
        },
    },

    // Group management
    groups: {
        async list(params?: {
            page?: number;
            pageSize?: number;
            search?: string;
        }): Promise<PaginatedResponse<any>> {
            const response = await apiClient.get<ApiResponse<PaginatedResponse<any>>>(
                API_ENDPOINTS.GROUPS.LIST,
                { params }
            );
            return response.data.data;
        },

        async get(id: number): Promise<any> {
            const response = await apiClient.get<ApiResponse<any>>(
                API_ENDPOINTS.GROUPS.GET(id)
            );
            return response.data.data;
        },

        async search(query: string): Promise<Recipient[]> {
            const response = await apiClient.get<ApiResponse<Recipient[]>>(
                API_ENDPOINTS.GROUPS.SEARCH,
                { params: { q: query } }
            );
            return response.data.data;
        },
    },

    // Dashboard and analytics
    dashboard: {
        async getStats(): Promise<DashboardStats> {
            const response = await apiClient.get<ApiResponse<DashboardStats>>(
                '/api/v1/dashboard/stats'
            );
            return response.data.data;
        },

        async getActivity(params?: {
            page?: number;
            pageSize?: number;
            type?: string;
        }): Promise<PaginatedResponse<ActivityItem>> {
            const response = await apiClient.get<ApiResponse<PaginatedResponse<ActivityItem>>>(
                '/api/v1/dashboard/activity',
                { params }
            );
            return response.data.data;
        },
    },

    getAnomalyAlerts: async (unacknowledgedOnly = true) => {
        const response = await apiClient.get(`/api/v1/audit/anomalies${unacknowledgedOnly ? '?unacknowledged=true' : ''}`);
        return response.data;
    },

    acknowledgeAnomalyAlert: async (id: number) => {
        const response = await apiClient.post(`/api/v1/audit/anomalies/${id}/acknowledge`);
        return response.data;
    },

    rotateSecret: async (id: number, newValue: string) => {
        const response = await apiClient.post(`/api/v1/secrets/${id}/rotate`, { new_value: newValue });
        return response.data;
    },

    // Admin endpoints
    admin: {
        async getStats(): Promise<any> {
            const response = await apiClient.get<ApiResponse<any>>(
                API_ENDPOINTS.ADMIN.STATS
            );
            return response.data.data;
        },

        async getUsers(params?: {
            page?: number;
            pageSize?: number;
            search?: string;
        }): Promise<PaginatedResponse<User>> {
            const response = await apiClient.get<ApiResponse<PaginatedResponse<User>>>(
                API_ENDPOINTS.ADMIN.USERS,
                { params }
            );
            return response.data.data;
        },

        async getRoles(): Promise<any[]> {
            const response = await apiClient.get<ApiResponse<any[]>>(
                API_ENDPOINTS.ADMIN.ROLES
            );
            return response.data.data;
        },

        async getAuditLogs(params?: {
            page?: number;
            pageSize?: number;
            userId?: number;
            action?: string;
            startDate?: string;
            endDate?: string;
        }): Promise<PaginatedResponse<any>> {
            const response = await apiClient.get<ApiResponse<PaginatedResponse<any>>>(
                API_ENDPOINTS.ADMIN.AUDIT,
                { params }
            );
            return response.data.data;
        },
    },
};

// Export configured axios instance
export default apiClient;