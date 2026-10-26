import { apiClient } from './client';
import { ApiResponse } from '../types';
import {
    Permission,
    Role,
    RoleAssignableScope,
    RoleWithPermissions,
    GroupRoles,
    GroupSharedSecret,
    Group,
} from '../types/rbac';

/** Where a role grant applies: no project = global (every project). */
export interface RoleGrantScope {
    projectId?: number;
    environmentId?: number;
}

const ASSIGNABLE_SCOPES: readonly RoleAssignableScope[] = ['global', 'project', 'any'];

/** An unknown or missing value is read as 'project', the most restrictive for a global grant. */
export function normalizeAssignableScope(s: unknown): RoleAssignableScope {
    return ASSIGNABLE_SCOPES.includes(s as RoleAssignableScope) ? (s as RoleAssignableScope) : 'project';
}

/**
 * The reason the server would refuse granting role with (projectId) or without a project, or null.
 * Mirrors the server's check (#3546) so the form can say what to change before sending.
 */
export function roleScopeRefusal(role: Pick<Role, 'name' | 'assignable_scope'>, projectId?: number): string | null {
    if (role.assignable_scope === 'project' && !projectId) {
        return `${role.name} is a project role: choose a project above, then check it again.`;
    }
    if (role.assignable_scope === 'global' && projectId) {
        return `${role.name} is install-wide: choose "All projects (global)" above, then check it again.`;
    }
    return null;
}

// Normalize a role object. The server always sends snake_case now (fixed via
// rbac_wire.go's roleWire/roleWithPermissionsWire as part of the API-hygiene
// casing campaign); this only handles the permissions array sometimes
// arriving as bare permission-name strings rather than full objects.
function normalizeRole(r: any): RoleWithPermissions {
    return {
        id: r.id ?? 0,
        name: r.name ?? '',
        description: r.description ?? '',
        bypasses_permission_checks: r.bypasses_permission_checks ?? false,
        assignable_scope: normalizeAssignableScope(r.assignable_scope),
        permissions: (r.permissions ?? []).map((p: any) =>
            typeof p === 'string'
                ? { id: 0, name: p, description: '', resource: p.split('.')[0] ?? '', action: p.split('.')[1] ?? '' }
                : {
                      id: p.id ?? 0,
                      name: p.name ?? '',
                      description: p.description ?? '',
                      resource: p.resource ?? '',
                      action: p.action ?? '',
                  }
        ),
    };
}

export const rbacApi = {
    async getRoles(): Promise<RoleWithPermissions[]> {
        const res = await apiClient.get('/api/v1/roles');
        const data = res.data.data;
        const roles = Array.isArray(data) ? data : (data?.roles ?? []);
        return roles.map(normalizeRole);
    },

    async getRole(id: number): Promise<RoleWithPermissions> {
        const res = await apiClient.get(`/api/v1/roles/${id}`);
        return normalizeRole(res.data.data);
    },

    // The server requires a non-empty description and at least one permission (by name) on
    // create, so the caller supplies them; nothing is defaulted here.
    async createRole(body: {
        name: string;
        description: string;
        permissions: string[];
        assignable_scope?: RoleAssignableScope;
    }): Promise<Role> {
        const res = await apiClient.post<ApiResponse<Role>>('/api/v1/roles', body);
        return res.data.data;
    },

    async updateRole(
        id: number,
        body: { name: string; description: string; permissions?: string[]; assignable_scope?: RoleAssignableScope }
    ): Promise<Role> {
        // `permissions` is sent only when given: a present key must hold at least one entry.
        const res = await apiClient.put<ApiResponse<Role>>(`/api/v1/roles/${id}`, body);
        return res.data.data;
    },

    async deleteRole(id: number): Promise<void> {
        await apiClient.delete(`/api/v1/roles/${id}`);
    },

    async getPermissions(resource?: string): Promise<Permission[]> {
        const res = await apiClient.get('/api/v1/permissions', {
            params: resource ? { resource } : undefined,
        });
        const data = res.data.data;
        return Array.isArray(data) ? data : (data?.permissions ?? []);
    },

    async getRolePermissions(
        roleId: number
    ): Promise<{ role_id: number; role_name: string; permissions: Permission[] }> {
        const res = await apiClient.get<ApiResponse<{ role_id: number; role_name: string; permissions: Permission[] }>>(
            `/api/v1/roles/${roleId}/permissions`
        );
        return res.data.data;
    },

    async assignPermissionToRole(roleId: number, permissionId: number): Promise<void> {
        await apiClient.post(`/api/v1/roles/${roleId}/permissions`, { permission_id: permissionId });
    },

    async removePermissionFromRole(roleId: number, permissionId: number): Promise<void> {
        await apiClient.delete(`/api/v1/roles/${roleId}/permissions/${permissionId}`);
    },

    async getGroupRoles(groupId: number): Promise<GroupRoles> {
        const res = await apiClient.get<ApiResponse<GroupRoles>>(`/api/v1/groups/${groupId}/roles`);
        return res.data.data;
    },

    // Live secrets a group can reach via shares. The server returns SecretNode rows,
    // which serialize with Go field names (PascalCase) — normalize to id/name/type.
    async getGroupSharedSecrets(groupId: number): Promise<GroupSharedSecret[]> {
        const res = await apiClient.get(`/api/v1/groups/${groupId}/shared-secrets`);
        const list = res.data?.data?.secrets ?? [];
        return (Array.isArray(list) ? list : []).map((s: any) => ({
            id: s.id ?? 0,
            name: s.name ?? '',
            type: s.type ?? '',
        }));
    },

    async assignRoleToGroup(
        groupId: number,
        roleId: number,
        expiresAt?: string,
        scope?: RoleGrantScope
    ): Promise<void> {
        // expiresAt (ISO) makes the grant time-bound; omit it for a permanent grant.
        // No scope (or project 0) is the GLOBAL scope: every project. The server
        // refuses a project role there (#3546).
        await apiClient.post(`/api/v1/groups/${groupId}/roles`, {
            role_id: roleId,
            ...(expiresAt ? { expires_at: expiresAt } : {}),
            ...(scope?.projectId ? { project_id: scope.projectId } : {}),
            ...(scope?.projectId && scope.environmentId ? { environment_id: scope.environmentId } : {}),
        });
    },

    async removeRoleFromGroup(groupId: number, roleId: number, scope?: RoleGrantScope): Promise<void> {
        const params: Record<string, number> = {};
        if (scope?.projectId) params.project_id = scope.projectId;
        if (scope?.projectId && scope.environmentId) params.environment_id = scope.environmentId;
        await apiClient.delete(`/api/v1/groups/${groupId}/roles/${roleId}`, { params });
    },

    async createGroup(body: { name: string; description: string }): Promise<Group> {
        const res = await apiClient.post<ApiResponse<Group>>('/api/v1/groups', body);
        return res.data.data;
    },

    async updateGroup(id: number, body: { name: string; description: string }): Promise<Group> {
        const res = await apiClient.put<ApiResponse<Group>>(`/api/v1/groups/${id}`, body);
        return res.data.data;
    },

    async deleteGroup(id: number): Promise<void> {
        await apiClient.delete(`/api/v1/groups/${id}`);
    },
};
