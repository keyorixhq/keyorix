// web/e2e/real/access-control.spec.ts — SESSION-WEB-E2E item 3: creates a
// user with a limited (project_viewer) role through the real admin UI, then
// verifies that user's own UI hides what the API denies, and that a
// forbidden deep link never renders admin data.
//
// Note on "a forbidden deep link shows a proper error rather than data": the
// actual behavior of every <AdminRoute> in this app
// (web/src/components/layout/ProtectedRoute.tsx) is a SILENT redirect to
// /dashboard, not a distinct error page — `redirectOnFailure` defaults to
// `true` and no route in web/src/App.tsx overrides it, so the component's
// own `AccessDenied` fallback is unreachable dead code today. This is safe
// (no data is ever rendered) but is not the same as "a proper error" the
// brief describes. Documented here and in the report rather than asserting
// a UI state that doesn't exist.
import { test, expect, Page } from '@playwright/test';

const ADMIN_USERNAME = process.env.KEYORIX_E2E_ADMIN_USERNAME;
const ADMIN_PASSWORD = process.env.KEYORIX_E2E_ADMIN_PASSWORD;

if (!ADMIN_USERNAME || !ADMIN_PASSWORD) {
    throw new Error(
        'KEYORIX_E2E_ADMIN_USERNAME/KEYORIX_E2E_ADMIN_PASSWORD are not set -- run ' +
            'scripts/e2e/web-real-smoke.sh, which bootstraps a real admin and sets them, ' +
            'rather than invoking this spec file directly.'
    );
}

async function submitLogin(page: Page, username: string, password: string) {
    await page.getByTestId('username-input').fill(username);
    await page.getByTestId('password-input').fill(password);
    await page.getByTestId('login-button').click();
}

async function logout(page: Page) {
    await page.getByTestId('user-menu-button').click();
    await page.getByText('Sign out').click();
    await page.waitForURL('**/login', { timeout: 15_000 });
}

test('a limited (project_viewer) user cannot see or reach what their role denies', async ({ page }) => {
    // The "New User" modal (web/src/pages/admin/AdminPage.tsx) has no internal
    // scroll container -- its content (username/display-name/email, 3 create
    // modes with descriptions, password field + policy hints, project
    // assignment picker) overflows a standard 1280x720 viewport with no way
    // to reach the submit button (confirmed live: Playwright's own
    // scroll-into-view retried for the full 30s timeout and never found it
    // visible). Real product gap, folded into SESSION-WEB-E2E's J36 UI-polish
    // report rather than filed standalone; worked around here with a taller
    // viewport so this test can still exercise the create flow.
    await page.setViewportSize({ width: 1280, height: 2200 });

    // Unique per run so repeat runs against a persistent dev DB don't collide.
    const stamp = Math.floor(Math.random() * 1_000_000);
    const projectName = `access-ctrl-${stamp}`;
    const limitedUsername = `limiteduser${stamp}`;
    // Deliberately NOT derived from `stamp` (or any other username/email/
    // display-name substring) -- internal/core/rules.DefaultPasswordPolicy
    // rejects a password containing the account's own username/email/display
    // name (see scripts/smoke.sh's own header comment on this exact trap, and
    // CLAUDE.md's "local-only test failures" notes). A shared stamp here
    // silently 400s the create-user call with a generic "ValidationError".
    const limitedPassword = 'Quartz-Falcon-77-Ridge!-' + Math.random().toString(36).slice(2, 10);

    // ── Setup as admin: a project, and a user scoped to only that project ──
    await page.goto('/login');
    await submitLogin(page, ADMIN_USERNAME as string, ADMIN_PASSWORD as string);
    await page.waitForURL('/dashboard', { timeout: 15_000 });

    await page.goto('/projects?new=1');
    await page.getByLabel('Project name').fill(projectName);
    await page.getByRole('button', { name: 'Create Project' }).click();
    await page.waitForURL(/\/projects\/\d+$/, { timeout: 15_000 });

    await page.goto('/admin/users');
    await page.getByRole('button', { name: 'New User' }).click();
    await page.getByLabel('Username').fill(limitedUsername);
    await page.getByLabel('Display Name').fill(`Limited User ${stamp}`);
    await page.getByLabel('Email').fill(`${limitedUsername}@example.invalid`);
    await page.locator('#create-password').fill(limitedPassword);
    // Default-role project assignment: the typeahead attaches project_viewer
    // (web/src/features/admin/ProjectAssignmentsPicker.tsx's DEFAULT_ROLE) --
    // deliberately left unchanged so this user's role really is read-only,
    // not elevated by the test itself.
    await page.getByPlaceholder('Search projects to add…').fill(projectName);
    await page.getByRole('button', { name: projectName, exact: true }).click();
    await page.getByRole('button', { name: 'Create User', exact: true }).click();
    // The classic (password) create path closes the modal directly on
    // success (no out-of-band artifact to relay) -- its disappearance, plus
    // the new row landing in the table, is the completion signal.
    await expect(page.getByRole('dialog')).toBeHidden({ timeout: 10_000 });
    // Scoped to the "@username" caption specifically -- a bare getByText(username)
    // also matches the email cell (which contains the username as a prefix).
    await expect(page.getByText(`@${limitedUsername}`)).toBeVisible({ timeout: 10_000 });

    await logout(page);

    // ── As the limited user ─────────────────────────────────────────────────
    await page.goto('/login');
    await submitLogin(page, limitedUsername, limitedPassword);
    await page.waitForURL('/dashboard', { timeout: 15_000 });

    // UI hides it: no admin-only nav group rendered at all (web/src/components/
    // layout/Sidebar.tsx filters out adminOnly groups client-side for a non-admin).
    await expect(page.getByText('Access Control')).toHaveCount(0);

    // API denies it too -- the UI hiding it isn't just cosmetic. Goes through
    // the same-origin Vite dev proxy (relative path + the context's
    // configured baseURL), so the real session cookie is attached exactly
    // like a real page navigation would send it.
    // NOT /api/v1/admin/users -- that path is unregistered (server/http/router.go
    // only ever mounts the global users collection at /api/v1/users, gated by
    // RequirePermission(permUsersRead)); web/src/constants.ts's ADMIN.USERS
    // constant pointing at /api/v1/admin/users is dead code that is never
    // actually called by any service in web/src. Hitting the wrong path would
    // "pass" via a router 404 that proves nothing about authorization.
    const adminUsersRes = await page.context().request.get('/api/v1/users');
    expect(adminUsersRes.status(), 'a project-scoped viewer must not be able to list all users').toBe(403);

    // A forbidden deep link never renders admin data. See the top-of-file
    // note: the actual behavior is a silent redirect to /dashboard, not a
    // distinct error page -- asserted as such, not as a hypothetical one.
    await page.goto('/admin/users');
    await page.waitForURL('/dashboard', { timeout: 15_000 });
    await expect(page.getByText(ADMIN_USERNAME as string)).toHaveCount(0);
    await expect(page.locator('table')).toHaveCount(0);
});
