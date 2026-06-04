import type { User } from '../../types';

// Install-administrator role names (ADR-021). `admin` is the legacy alias of
// `system_admin`; `super_admin` is the bootstrap super-user.
export const ADMIN_ROLES = ['admin', 'system_admin', 'super_admin'];

// userIsAdmin reports whether a user holds any install-admin role. It checks
// both the single primary `role` and the full `roles` list, so it works
// regardless of which the backend populated. Pure (no React/hooks) so it can be
// used by route guards whose tests mock the auth module.
export const userIsAdmin = (user?: Pick<User, 'role' | 'roles'> | null): boolean => {
    if (!user) return false;
    if (user.role && ADMIN_ROLES.includes(user.role)) return true;
    return (user.roles ?? []).some(r => ADMIN_ROLES.includes(r));
};
