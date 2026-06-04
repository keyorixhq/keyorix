import { apiClient } from './client';

// Personal Access Tokens (ADR-027) — user-owned bearer credentials managed from
// the My Account page. The raw token is returned by createToken exactly once.

export interface PersonalAccessToken {
    id: number;
    name: string;
    token_prefix: string;
    revoked: boolean;
    created_at: string;
    expires_at: string | null;
    last_used_at: string | null;
}

function toArray<T>(data: unknown): T[] {
    return Array.isArray(data) ? (data as T[]) : [];
}

export const personalTokensApi = {
    async listTokens(): Promise<PersonalAccessToken[]> {
        const response = await apiClient.get('/api/v1/auth/tokens');
        return toArray<PersonalAccessToken>(response.data.data);
    },

    // Returns the freshly created token's metadata plus its one-time plaintext.
    async createToken(body: {
        name: string;
        expires_at?: string;
    }): Promise<{ token: string; pat: PersonalAccessToken }> {
        const response = await apiClient.post('/api/v1/auth/tokens', body);
        const data = response.data.data;
        return { token: data.token, pat: data.pat as PersonalAccessToken };
    },

    async revokeToken(id: number): Promise<void> {
        await apiClient.delete(`/api/v1/auth/tokens/${id}`);
    },
};
