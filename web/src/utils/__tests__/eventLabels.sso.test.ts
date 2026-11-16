import { describe, it, expect } from 'vitest';
import { eventLabel } from '../eventLabels';

// Every SSO audit event the server writes (internal/core/sso.go) has a curated
// label, so the Audit page never shows the humanized fallback ("Auth SSO login
// session failed") for a refused or half-finished SSO login.
describe('SSO audit event labels', () => {
    it.each([
        ['auth.sso_login', 'SSO login'],
        ['auth.sso_jit_provisioned', 'SSO user provisioned'],
        ['auth.sso_groups_synced', 'SSO groups synced'],
        ['auth.sso_roles_synced', 'SSO roles synced'],
        ['auth.sso_login_session_failed', 'SSO login failed to start a session'],
        ['auth.sso_reconcile_refused', 'SSO login refused: group or role sync incomplete'],
        ['auth.sso_reconcile_last_admin_removal_refused', 'SSO login refused: last administrator would be removed'],
    ])('%s -> %s', (raw, want) => {
        expect(eventLabel(raw)).toBe(want);
    });
});
