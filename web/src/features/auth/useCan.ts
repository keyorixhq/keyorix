import { useAuth } from './api';

// What the signed-in user can do, as far as the API tells us. GET /auth/me and the
// login response return `permissions`: the distinct permission names across every
// role the user holds. That union is NOT scope-aware (a project_developer on A who is
// project_viewer on B holds secrets.write in the union), so this is a coarse
// show/hide for controls, never an authorisation decision: the server still checks the
// real scope on every request and a refused action shows the server's reason.
// Follow-up (API): per-project/per-secret effective permissions in the project and
// secret responses, so the UI can be exact instead of a superset.
//
// The names are the server's (internal/core/auth_bootstrap.go).
export const PERM = {
    secretsWrite: 'secrets.write',
    secretsDelete: 'secrets.delete',
    auditRead: 'audit.read',
    rolesAssign: 'roles.assign',
} as const;

export interface Can {
    /** Install administrator (user directory, system settings). */
    admin: boolean;
    /** Create / edit / rotate / share / suspend / copy a secret. */
    writeSecrets: boolean;
    /** Delete a secret or hand over its ownership. */
    deleteSecrets: boolean;
    /** Read the audit log. */
    readAudit: boolean;
    /** Add, re-role or remove project members. */
    manageMembers: boolean;
}

export function useCan(): Can {
    const { isAdmin, hasPermission } = useAuth();
    const has = (p: string) => isAdmin || hasPermission(p);
    return {
        admin: isAdmin,
        writeSecrets: has(PERM.secretsWrite),
        deleteSecrets: has(PERM.secretsDelete),
        readAudit: has(PERM.auditRead),
        manageMembers: has(PERM.rolesAssign),
    };
}
