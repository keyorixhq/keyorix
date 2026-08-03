import { describe, it, expect } from 'vitest';
import { userIsAdmin, ADMIN_ROLES } from '../roles';

describe('userIsAdmin', () => {
    it('is false for null/undefined', () => {
        expect(userIsAdmin(null)).toBe(false);
        expect(userIsAdmin(undefined)).toBe(false);
    });

    it('admits the legacy "admin" primary role', () => {
        expect(userIsAdmin({ role: 'admin', roles: [] })).toBe(true);
    });

    it('admits "system_admin" (the ADR-021 admin role) — the case the old exact === "admin" check missed', () => {
        expect(userIsAdmin({ role: 'system_admin', roles: [] })).toBe(true);
        expect(userIsAdmin({ role: 'super_admin', roles: [] })).toBe(true);
    });

    it('admits when an admin role is only present in the roles list', () => {
        expect(userIsAdmin({ role: '', roles: ['project_viewer', 'system_admin'] })).toBe(true);
    });

    it('denies non-admin roles', () => {
        expect(userIsAdmin({ role: 'system_viewer', roles: ['system_viewer'] })).toBe(false);
        expect(userIsAdmin({ role: 'project_admin', roles: ['project_admin'] })).toBe(false);
        expect(userIsAdmin({ role: 'user', roles: [] })).toBe(false);
    });

    it('tolerates a missing roles array', () => {
        expect(userIsAdmin({ role: 'viewer' } as never)).toBe(false);
        expect(userIsAdmin({ role: 'admin' } as never)).toBe(true);
    });

    it('exposes the admin role set', () => {
        expect(ADMIN_ROLES).toEqual(['admin', 'system_admin', 'super_admin']);
    });
});
