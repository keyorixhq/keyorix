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

export interface GroupRoles {
    group_id: number;
    roles: Role[];
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

export type BuiltInRole =
    'super_admin' | 'admin' | 'editor' | 'viewer' | 'auditor';

export const BUILT_IN_ROLES: BuiltInRole[] = [
    'super_admin', 'admin', 'editor', 'viewer', 'auditor',
];
