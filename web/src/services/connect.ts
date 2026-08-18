import { apiClient } from './client';

// Keyorix Connect (ADR-043) read-through federation API. Read-only: list the
// configured connectors and proxy a read of a secret's current value from an
// external store. Gated server-side by secrets.read and audited.

export interface FederatedSecret {
    connector: string;
    ref: string;
    value: string;
}

// Per-reference RBAC grant (ADR-045): role `role_id` may read refs matching
// `ref_prefix` (a prefix, or a shell-style glob if it contains * ? [) on `connector`.
export interface ConnectRefGrant {
    id: number;
    role_id: number;
    connector: string;
    ref_prefix: string;
}

export const connectApi = {
    async listConnectors(): Promise<string[]> {
        const response = await apiClient.get('/api/v1/connect/connectors');
        return (response.data.data?.connectors ?? []) as string[];
    },

    // ref is sent in the POST body, not a query-string parameter: a GET query is
    // routinely captured by infrastructure access-log pipelines (reverse proxies,
    // TLS-terminating middleboxes, CDNs) in a way a POST body normally is not, and
    // ref names the secret's exact path/identifier inside the external store.
    async readSecret(connector: string, ref: string): Promise<FederatedSecret> {
        const response = await apiClient.post(`/api/v1/connect/${encodeURIComponent(connector)}/secret:read`, {
            ref,
        });
        return response.data.data as FederatedSecret;
    },

    async listRefGrants(): Promise<ConnectRefGrant[]> {
        const response = await apiClient.get('/api/v1/connect/ref-grants');
        return (response.data.data?.grants ?? []) as ConnectRefGrant[];
    },

    async createRefGrant(roleId: number, connector: string, refPrefix: string): Promise<ConnectRefGrant> {
        const response = await apiClient.post('/api/v1/connect/ref-grants', {
            role_id: roleId,
            connector,
            ref_prefix: refPrefix,
        });
        return response.data.data as ConnectRefGrant;
    },

    async deleteRefGrant(id: number): Promise<void> {
        await apiClient.delete(`/api/v1/connect/ref-grants/${id}`);
    },
};
