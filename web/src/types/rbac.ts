export interface Permission {
    id: number;
    name: string;
    description: string;
    resource: string;
    action: string;
}

export interface Role {
    id: number;
    name: string;
    description: string;
    // Always sent by the server (roleWire); true for the built-in roles that skip
    // per-permission checks.
    bypasses_permission_checks: boolean;
}

export interface RoleWithPermissions extends Role {
    permissions: Permission[];
}

// A role granted to a group, with the grant's optional time-bound expiry
// (absent = permanent).
export interface GroupRoleGrant {
    id: number;
    name: string;
    description: string;
    expires_at?: string;
}

export interface GroupRoles {
    group_id: number;
    // null (not []) when the group holds no role grants.
    roles: GroupRoleGrant[] | null;
}

// A secret a group can reach via shares (normalized from the server's SecretNode).
export interface GroupSharedSecret {
    id: number;
    name: string;
    type: string;
}

export interface UserRoleAssignment {
    user_id: number;
    username: string;
    email: string;
    roles: Role[];
}

export interface Group {
    id: number;
    name: string;
    description: string;
    member_count?: number;
}

export type BuiltInRole = 'super_admin' | 'admin' | 'editor' | 'viewer' | 'auditor';

export const BUILT_IN_ROLES: BuiltInRole[] = ['super_admin', 'admin', 'editor', 'viewer', 'auditor'];
