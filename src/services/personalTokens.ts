import { apiClient } from './client';

// Personal Access Tokens (ADR-027) — user-owned bearer credentials managed from
// the My Account page. The raw token is returned by createToken exactly once.
//
// A token may optionally be scoped below its owner (ADR-042): a permission
// allowlist (scopes) and/or a single-project confinement (project_scope). Empty
// scopes + project_scope 0 = inherit the owner's full permissions (the default).

export interface PersonalAccessToken {
    id: number;
    name: string;
    token_prefix: string;
    revoked: boolean;
    created_at: string;
    expires_at: string | null;
    last_used_at: string | null;
    scopes: string[]; // empty = inherits the owner's full permissions
    project_scope: number; // 0 = any project the owner can reach
}

export interface CreatePersonalTokenBody {
    name: string;
    expires_at?: string;
    scopes?: string[];
    project_scope?: number;
}

function toArray<T>(data: unknown): T[] {
    return Array.isArray(data) ? (data as T[]) : [];
}

// buildCreateTokenBody assembles the create payload from the form state, applying
// the ADR-042 least-privilege rules. When `limited` is false (or no scope is
// chosen) the token inherits the owner's full permissions: scopes/project are
// omitted. Permission entries are trimmed, de-duplicated, and blanks dropped; the
// advanced free-text field is comma/whitespace/newline separated.
export function buildCreateTokenBody(input: {
    name: string;
    expiresAt?: string;
    limited: boolean;
    permissions: string[];
    extraPermissions?: string;
    projectScope?: number;
}): CreatePersonalTokenBody {
    const body: CreatePersonalTokenBody = { name: input.name.trim() };
    if (input.expiresAt) {
        body.expires_at = new Date(input.expiresAt).toISOString();
    }
    if (!input.limited) {
        return body;
    }
    const seen = new Set<string>();
    const scopes: string[] = [];
    const add = (raw: string) => {
        const p = raw.trim();
        if (p && !seen.has(p)) {
            seen.add(p);
            scopes.push(p);
        }
    };
    input.permissions.forEach(add);
    (input.extraPermissions ?? '').split(/[\s,]+/).forEach(add);
    if (scopes.length > 0) {
        body.scopes = scopes;
    }
    if (input.projectScope && input.projectScope > 0) {
        body.project_scope = input.projectScope;
    }
    return body;
}

export const personalTokensApi = {
    async listTokens(): Promise<PersonalAccessToken[]> {
        const response = await apiClient.get('/api/v1/auth/tokens');
        return toArray<PersonalAccessToken>(response.data.data);
    },

    // Returns the freshly created token's metadata plus its one-time plaintext.
    async createToken(
        body: CreatePersonalTokenBody
    ): Promise<{ token: string; pat: PersonalAccessToken }> {
        const response = await apiClient.post('/api/v1/auth/tokens', body);
        const data = response.data.data;
        return { token: data.token, pat: data.pat as PersonalAccessToken };
    },

    async revokeToken(id: number): Promise<void> {
        await apiClient.delete(`/api/v1/auth/tokens/${id}`);
    },
};
