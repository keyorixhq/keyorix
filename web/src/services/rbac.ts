import { apiClient } from './client';
import { ApiResponse } from '../types';
import { Permission, Role, RoleWithPermissions, GroupRoles, GroupSharedSecret, Group } from '../types/rbac';

// Normalize a role object. The backend (server/http/handlers/rbac_wire.go) always
// serializes snake_case; the only remaining variability handled here is that a
// role's permissions may arrive as bare permission-name strings (e.g. from a
// mock) rather than full Permission objects.
function normalizeRole(r: any): RoleWithPermissions {
    return {
        id: r.id ?? 0,
        name: r.name ?? '',
        description: r.description ?? '',
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
        created_at: r.created_at ?? '',
        updated_at: r.updated_at ?? '',
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

    async createRole(body: { name: string; description: string; permissions?: string[] }): Promise<Role> {
        const res = await apiClient.post<ApiResponse<Role>>('/api/v1/roles', {
            ...body,
            permissions: body.permissions ?? [],
        });
        return res.data.data;
    },

    async updateRole(id: number, body: { name: string; description: string; permissions?: string[] }): Promise<Role> {
        const res = await apiClient.put<ApiResponse<Role>>(`/api/v1/roles/${id}`, {
            ...body,
            permissions: body.permissions ?? [],
        });
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
            id: s.id ?? s.ID ?? 0,
            name: s.name ?? s.Name ?? '',
            type: s.type ?? s.Type ?? '',
        }));
    },

    async assignRoleToGroup(groupId: number, roleId: number, expiresAt?: string): Promise<void> {
        // expiresAt (ISO) makes the grant time-bound; omit it for a permanent grant.
        await apiClient.post(`/api/v1/groups/${groupId}/roles`, {
            role_id: roleId,
            ...(expiresAt ? { expires_at: expiresAt } : {}),
        });
    },

    async removeRoleFromGroup(groupId: number, roleId: number): Promise<void> {
        await apiClient.delete(`/api/v1/groups/${groupId}/roles/${roleId}`);
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
