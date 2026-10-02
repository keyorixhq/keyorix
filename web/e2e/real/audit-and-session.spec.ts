// web/e2e/real/audit-and-session.spec.ts — SESSION-WEB-E2E item 4: the real
// Audit Log page reflects secret operations performed above, and a session
// timeout / explicit logout really end the session (server-side, not just
// client-side state) -- including that the browser back button never
// re-reveals protected data afterward.
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

async function realLogin(page: Page) {
    await page.goto('/login');
    await page.getByTestId('username-input').fill(ADMIN_USERNAME as string);
    await page.getByTestId('password-input').fill(ADMIN_PASSWORD as string);
    await page.getByTestId('login-button').click();
    await page.waitForURL('/dashboard', { timeout: 15_000 });
}

test('the audit log shows create/rotate/delete operations on a real secret', async ({ page }) => {
    const unique = Date.now();
    const projectName = `e2e-audit-${unique}`;
    const envName = `e2eenv${unique}`;
    const secretName = `e2e-secret-${unique}`;

    await realLogin(page);

    // ── Produce the operations this test asserts on ────────────────────────
    await page.goto('/projects');
    await page.getByRole('button', { name: 'New Project' }).click();
    await page.locator('#create-project-name').fill(projectName);
    await page.getByRole('button', { name: 'Create Project' }).click();
    await page.waitForURL(/\/projects\/\d+(\/secrets)?$/, { timeout: 15_000 });
    const projectUrl = page.url().replace(/\/secrets$/, '');

    await page.goto(`${projectUrl}/settings`);
    await page.getByPlaceholder('New environment name…').fill(envName);
    await page.getByRole('button', { name: 'Add' }).click();
    await expect(page.getByText(envName, { exact: false })).toBeVisible({ timeout: 10_000 });

    await page.goto(`${projectUrl}/secrets`);
    await page.getByRole('button', { name: new RegExp(`^${envName}$`, 'i') }).click();
    await expect(page).toHaveURL(new RegExp(`env=${envName}`), { timeout: 10_000 });
    await page.getByRole('button', { name: 'New Secret' }).first().click();
    await page.locator('#create-secret-name').fill(secretName);
    await page.locator('#create-secret-value').fill(`value-${unique}`);
    await page.getByRole('button', { name: 'Create Secret' }).click();
    await expect(page.getByRole('dialog')).toBeHidden({ timeout: 10_000 });

    const row = page.getByRole('row', { name: new RegExp(secretName) });
    await row.getByTitle('View').click();
    await page.setViewportSize({ width: 1280, height: 2600 }); // see secrets-crud.spec.ts's note on this modal's scroll gap
    await page.getByRole('button', { name: 'Rotate', exact: true }).click();
    await page.getByLabel('New value').fill(`rotated-${unique}`);
    await page.getByRole('button', { name: 'Rotate secret' }).click();
    await expect(page.getByText(`Rotate ${secretName}`)).not.toBeVisible({ timeout: 10_000 });

    page.on('dialog', (d) => d.accept());
    await page.getByRole('button', { name: 'Delete', exact: true }).click();
    await expect(page.getByText('Delete Secret')).toBeVisible();
    await page.getByRole('button', { name: 'Delete', exact: true }).click();
    await expect(page.getByText('Delete Secret')).not.toBeVisible({ timeout: 10_000 });

    // ── The audit log reflects all three operations on this exact secret ───
    await page.goto('/audit');
    await page.getByPlaceholder('Filter by actor…').fill(ADMIN_USERNAME as string);

    const secretRows = page.getByRole('row', { name: new RegExp(secretName) });
    await expect(secretRows).toHaveCount(3, { timeout: 10_000 });
    const rowsText = (await secretRows.allTextContents()).join(' | ');
    expect(rowsText, 'audit log must show the secret was created').toContain('Created');
    expect(rowsText, 'audit log must show the secret was rotated').toContain('Rotated');
    expect(rowsText, 'audit log must show the secret was deleted').toContain('Deleted');

    // A login this same session performed is in the log too.
    await page.getByPlaceholder('Filter by actor…').fill('');
    await expect(page.getByRole('row').filter({ hasText: 'Login' }).first()).toBeVisible({ timeout: 10_000 });
});

test('logout and an inactivity timeout both really end the session', async ({ page, context }) => {
    await realLogin(page);
    // Dashboard's "Total Secrets" stat is the same stable, data-independent
    // authenticated-page signal pages.spec.ts already relies on -- unlike a
    // secrets table (which renders nothing with this testid when the list is
    // empty), this always renders once logged in.
    await expect(page.getByText('Total Secrets')).toBeVisible();

    // ── Explicit logout really invalidates the session server-side ─────────
    await page.getByTestId('user-menu-button').click();
    await page.getByText('Sign out').click();
    await page.waitForURL('**/login', { timeout: 15_000 });

    // Not just client-side state cleared -- the server has actually revoked
    // the session, so the old cookie (still held by this browser context)
    // gets a real 401 on a protected endpoint, not a stale-but-accepted one.
    const profileAfterLogout = await context.request.get('/api/v1/auth/profile');
    expect(profileAfterLogout.status(), 'the server session must be revoked, not just forgotten client-side').toBe(401);

    // Back button after logout must never reveal the previously-authenticated
    // page's data -- checkAuth() re-validates against the server (which just
    // 401'd above) regardless of what a bfcache snapshot might otherwise show.
    await page.goBack();
    await expect(page.getByText('Total Secrets')).not.toBeVisible();
    await expect(page.locator('body')).not.toContainText(ADMIN_USERNAME as string);

    // ── A real inactivity timeout also really ends the session ─────────────
    // page.clock mocks this page's own Date/setTimeout so the real
    // DEFAULT_VALUES.SESSION_TIMEOUT (1 hour, web/src/constants.ts) can be
    // exercised deterministically without waiting an hour of real time or
    // overriding VITE_SESSION_TIMEOUT for the whole suite (which would make
    // pages.spec.ts's ~10s page walk flaky). Installed on a fresh page/login
    // so the mocked clock never affects the logout flow just exercised above.
    const page2 = await context.newPage();
    await page2.clock.install();
    await page2.goto('/login');
    await page2.getByTestId('username-input').fill(ADMIN_USERNAME as string);
    await page2.getByTestId('password-input').fill(ADMIN_PASSWORD as string);
    await page2.getByTestId('login-button').click();
    await page2.waitForURL('/dashboard', { timeout: 15_000 });

    // Past SESSION_TIMEOUT with no activity -- useAuth's own inactivity timer
    // (web/src/features/auth/api.ts) fires logout() once the mocked clock
    // crosses the deadline it set at login.
    await page2.clock.fastForward('01:00:01');
    await page2.waitForURL('**/login', { timeout: 15_000 });

    const profileAfterTimeout = await page2.context().request.get('/api/v1/auth/profile');
    expect(profileAfterTimeout.status(), 'an inactivity timeout must also revoke the server session').toBe(401);
    // (Back-button-after-session-end is already covered above for the
    // explicit-logout path; skipped here too -- a real browser navigation on
    // a page.clock-mocked page leaves Playwright's own CDP session in a state
    // where goBack() can't reliably attach afterward, independent of
    // anything the app itself does.)
});
