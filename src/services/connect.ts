import { apiClient } from './client';

// Keyorix Connect (ADR-043) read-through federation API. Read-only: list the
// configured connectors and proxy a read of a secret's current value from an
// external store. Gated server-side by secrets.read and audited.

export interface FederatedSecret {
    connector: string;
    ref: string;
    value: string;
}

export const connectApi = {
    async listConnectors(): Promise<string[]> {
        const response = await apiClient.get('/api/v1/connect/connectors');
        return (response.data.data?.connectors ?? []) as string[];
    },

    async readSecret(connector: string, ref: string): Promise<FederatedSecret> {
        const response = await apiClient.get(
            `/api/v1/connect/${encodeURIComponent(connector)}/secret`,
            { params: { ref } },
        );
        return response.data.data as FederatedSecret;
    },
};
