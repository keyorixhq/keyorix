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
    created_at: string;
    updated_at: string;
}

export interface RoleWithPermissions extends Role {
    permissions: Permission[];
}

// A role granted to a group, with the grant's optional time-bound expiry
// (absent = permanent).
export interface GroupRoleGrant extends Role {
    expires_at?: string;
}

export interface GroupRoles {
    group_id: number;
    roles: GroupRoleGrant[];
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
    created_at: string;
    updated_at: string;
}

export type BuiltInRole = 'super_admin' | 'admin' | 'editor' | 'viewer' | 'auditor';

export const BUILT_IN_ROLES: BuiltInRole[] = ['super_admin', 'admin', 'editor', 'viewer', 'auditor'];
