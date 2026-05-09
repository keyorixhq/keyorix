import { apiClient } from './client';
import { ServiceAccount, APIToken } from '../types/serviceAccounts';

interface CreateServiceAccountBody {
    name: string;
    description: string;
    scopes: string;
}

interface UpdateServiceAccountBody {
    name?: string;
    description?: string;
    scopes?: string;
}

interface CreateTokenBody {
    description?: string;
    expires_at?: string;
}

// Normalize response — backend returns plain array or { service_accounts: [] }
function toArray<T>(data: any): T[] {
    if (!data) return [];
    if (Array.isArray(data)) return data as T[];
    if (Array.isArray(data.service_accounts)) return data.service_accounts as T[];
    if (Array.isArray(data.tokens)) return data.tokens as T[];
    return [];
}

export const serviceAccountsApi = {
    async listServiceAccounts(): Promise<ServiceAccount[]> {
        const response = await apiClient.get('/api/v1/service-accounts');
        return toArray<ServiceAccount>(response.data.data);
    },

    async createServiceAccount(
        body: CreateServiceAccountBody
    ): Promise<{ service_account: ServiceAccount; client_secret: string }> {
        const response = await apiClient.post('/api/v1/service-accounts', body);
        const data = response.data.data;
        // Backend returns the created account directly or wrapped
        const sa = data.service_account ?? data;
        const secret = data.client_secret ?? '';
        return { service_account: sa, client_secret: secret };
    },

    async updateServiceAccount(id: number, body: UpdateServiceAccountBody): Promise<ServiceAccount> {
        const response = await apiClient.put(`/api/v1/service-accounts/${id}`, body);
        const data = response.data.data;
        return data.service_account ?? data;
    },

    async deactivateServiceAccount(id: number): Promise<void> {
        await apiClient.delete(`/api/v1/service-accounts/${id}`);
    },

    async listTokens(serviceAccountId: number): Promise<APIToken[]> {
        const response = await apiClient.get(
            `/api/v1/service-accounts/${serviceAccountId}/tokens`
        );
        return toArray<APIToken>(response.data.data);
    },

    async createToken(
        serviceAccountId: number,
        body: CreateTokenBody
    ): Promise<{ token: APIToken; access_token: string }> {
        const response = await apiClient.post(
            `/api/v1/service-accounts/${serviceAccountId}/tokens`,
            body
        );
        const data = response.data.data;
        const token = data.token ?? data;
        const accessToken = data.token_value ?? data.access_token ?? data.plain_token ?? '';
        return { token, access_token: accessToken };
    },

    async revokeToken(tokenId: number): Promise<void> {
        await apiClient.delete(`/api/v1/tokens/${tokenId}`);
    },
};
