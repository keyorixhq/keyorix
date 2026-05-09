export interface ServiceAccount {
    id: number;
    name: string;
    description: string;
    client_id: string;
    scopes: string;
    is_active: boolean;
    created_at: string;
}

export interface APIToken {
    id: number;
    client_id: number;
    scope: string;
    expires_at: string | null;
    created_at: string;
    revoked: boolean;
}
