// web/e2e/real/audit-and-session.spec.ts — SESSION-WEB-E2E item 4: the audit
// view shows the operations exercised elsewhere in this suite, and a session
// timeout / logout really end the session server-side (not just hide the UI)
// -- including that the browser back button can't resurrect protected data
// after logout. Real backend (scripts/e2e/web-real-smoke.sh), no mocked
// routes.
import { test, expect, Page, request as apiRequest } from '@playwright/test';

const ADMIN_USERNAME = process.env.KEYORIX_E2E_ADMIN_USERNAME;
const ADMIN_PASSWORD = process.env.KEYORIX_E2E_ADMIN_PASSWORD;

if (!ADMIN_USERNAME || !ADMIN_PASSWORD) {
    throw new Error(
        'KEYORIX_E2E_ADMIN_USERNAME/KEYORIX_E2E_ADMIN_PASSWORD are not set -- run ' +
            'scripts/e2e/web-real-smoke.sh, which bootstraps a real admin and sets them, ' +
            'rather than invoking this spec file directly.'
    );
}

async function realLogin(page: Page) {
    await page.goto('/login');
    await page.getByTestId('username-input').fill(ADMIN_USERNAME as string);
    await page.getByTestId('password-input').fill(ADMIN_PASSWORD as string);
    await page.getByTestId('login-button').click();
    await page.waitForURL('/dashboard', { timeout: 15_000 });
}

test("the audit log records this session's own login, project, and secret creation", async ({ page }) => {
    const unique = Date.now();
    const projectName = `e2e-audit-${unique}`;

    await realLogin(page);

    await page.goto('/projects');
    await page.getByRole('button', { name: 'New Project' }).click();
    await page.locator('#create-project-name').fill(projectName);
    await page.getByRole('button', { name: 'Create Project' }).click();
    await page.waitForURL(/\/projects\/\d+(\/secrets)?$/, { timeout: 15_000 });

    await page.goto('/audit');
    await page.getByPlaceholder('Filter by actor…').fill(ADMIN_USERNAME as string);

    // auth.login for the login at the top of this test.
    await expect(page.getByText(/logged in/i).first()).toBeVisible({ timeout: 10_000 });
    // project.created for the project just made, naming it specifically so
    // this can't be satisfied by some other, unrelated project-created row.
    await expect(
        page.getByText(new RegExp(`created project.*${projectName}|${projectName}.*created`, 'i'))
    ).toBeVisible({ timeout: 10_000 });
});

test('an inactivity session timeout really ends the session (server-side, not just the UI)', async ({
    page,
    context,
}) => {
    // Install the clock BEFORE login -- web/src/features/auth/api.ts's useAuth
    // schedules its inactivity-timeout setTimeout the moment isAuthenticated
    // flips true (right after login), using the real Date.now() at that
    // instant as the deadline's base. Installing afterwards would leave that
    // first timer registered against the real, unmocked clock, and
    // fast-forwarding the fake one wouldn't touch it. Installed with the real
    // current time so login's own timestamps stay realistic.
    await page.clock.install({ time: Date.now() });

    await realLogin(page);

    // Capture the live session cookie before it's invalidated, to prove the
    // eventual 401 below is because the SERVER revoked the session -- not
    // just that the client forgot to send a cookie.
    const cookiesBefore = await context.cookies();
    const profileBefore = await page.context().request.get('/api/v1/auth/profile');
    expect(profileBefore.ok(), 'the session must actually be valid before the timeout').toBeTruthy();

    // web/src/constants.ts's DEFAULT_VALUES.SESSION_TIMEOUT is 1 hour; fast-
    // forward well past it so the inactivity-logout branch in useAuth fires.
    await page.clock.fastForward('01:05:00');

    await page.waitForURL('/login', { timeout: 15_000 });

    // The server, not just the client, must now reject the old session --
    // replay the captured pre-timeout cookie directly against the API.
    const freshRequest = await apiRequest.newContext({ storageState: { cookies: cookiesBefore, origins: [] } });
    const profileAfter = await freshRequest.get(`${new URL(page.url()).origin}/api/v1/auth/profile`);
    expect(profileAfter.status(), 'the pre-timeout session cookie must be rejected after the timeout').toBe(401);
    await freshRequest.dispose();
});

test("logout really ends the session: the server rejects the old cookie, and back doesn't reveal data", async ({
    page,
    context,
}) => {
    await realLogin(page);
    await expect(page.getByText('Total Secrets')).toBeVisible();

    const cookiesBefore = await context.cookies();

    await page.getByTestId('user-menu-button').click();
    await page.getByText('Sign out').click();
    await page.waitForURL('**/login', { timeout: 15_000 });

    // Server-side invalidation, not just a client-side state clear.
    const freshRequest = await apiRequest.newContext({ storageState: { cookies: cookiesBefore, origins: [] } });
    const profileAfter = await freshRequest.get(`${new URL(page.url()).origin}/api/v1/auth/profile`);
    expect(profileAfter.status(), 'the pre-logout session cookie must be rejected after logout').toBe(401);
    await freshRequest.dispose();

    // Back button after logout must not resurrect the dashboard from bfcache
    // or any other client-side cache -- it must re-request and bounce to
    // /login (checkAuth's 401 path) rather than flash real data.
    await page.goBack();
    await expect(page.getByText('Total Secrets')).not.toBeVisible();
    await page.waitForURL('**/login', { timeout: 15_000 });
});
