// web/e2e/real/secrets-crud.spec.ts — SESSION-WEB-E2E item 2: the secrets
// lifecycle through the real Profile → Projects → Secrets UI (no mocked
// routes, real backend via scripts/e2e/web-real-smoke.sh): create a project
// and environment, create a secret, confirm its value is never visible
// before an explicit reveal (and never appears in the page URL), update it
// (rotate), delete it, and restore it from the project's recycle bin.
//
// "Version history and rollback" (also in scope for this item) turned out to
// be unreachable through the UI at all -- see the second test below and the
// linked issue #2450: clicking "Reveal" crashes the whole page for every
// secret, unconditionally, and Version History's own data fetch is gated
// behind that same reveal action, so it never has a chance to render real
// data either. That is not a gap in this test; it is the actual, confirmed
// product behavior today. The first test below deliberately never clicks
// Reveal so the rest of the lifecycle (create, update, delete, restore) can
// still be exercised and verified.
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

// createProjectEnvAndSecret drives the UI through project creation, an
// explicit custom environment, and a secret in it -- shared setup for both
// tests below. Returns the project's base URL and the created secret's name.
async function createProjectEnvAndSecret(
    page: Page,
    opts: { projectName: string; envName: string; secretName: string; value: string }
): Promise<string> {
    await page.goto('/projects');
    await page.getByRole('button', { name: 'New Project' }).click();
    await page.locator('#create-project-name').fill(opts.projectName);
    await page.getByRole('button', { name: 'Create Project' }).click();
    await page.waitForURL(/\/projects\/\d+(\/secrets)?$/, { timeout: 15_000 });
    const projectUrl = page.url().replace(/\/secrets$/, '');

    await page.goto(`${projectUrl}/settings`);
    await page.getByPlaceholder('New environment name…').fill(opts.envName);
    await page.getByRole('button', { name: 'Add' }).click();
    await expect(page.getByText(opts.envName, { exact: false })).toBeVisible({ timeout: 10_000 });

    await page.goto(`${projectUrl}/secrets`);
    await page.getByRole('button', { name: new RegExp(`^${opts.envName}$`, 'i') }).click();
    await expect(page).toHaveURL(new RegExp(`env=${opts.envName}`), { timeout: 10_000 });

    // Two "New Secret" buttons render at once for a freshly-created, empty
    // environment: one in the toolbar, one in the empty-state panel
    // (web/src/pages/projects/ProjectSecretsTab.tsx) -- .first() is the
    // toolbar one, deliberately, so this still works once the environment is
    // no longer empty (the empty-state button disappears, the toolbar one
    // doesn't).
    await page.getByRole('button', { name: 'New Secret' }).first().click();
    // The create-secret modal's own context badge confirms it really is
    // scoped to the environment just switched to, not whatever was active
    // before. Scoped to the dialog as a whole, not the "Environment:" label
    // span itself -- that label and the env name are two separate sibling
    // spans, not one text node.
    await expect(page.getByRole('dialog')).toContainText(opts.envName, { ignoreCase: true });
    await page.locator('#create-secret-name').fill(opts.secretName);
    await page.locator('#create-secret-value').fill(opts.value);
    await page.getByRole('button', { name: 'Create Secret' }).click();
    await expect(page.getByRole('dialog')).toBeHidden({ timeout: 10_000 });

    return projectUrl;
}

test('secrets lifecycle: project/env creation, reveal gating, update, delete, restore', async ({ page }) => {
    // Auto-accept every window.confirm() this flow triggers (suspend) --
    // this is Playwright's own browser context under full test automation,
    // not an interactive session, so there is no "blocks all further
    // events" hazard the way there is for the claude-in-chrome extension;
    // page.on('dialog', ...) is the standard way Playwright tests handle
    // confirm()/alert().
    page.on('dialog', (d) => d.accept());

    // The secret detail modal (web/src/features/secrets/SecretDetailView.tsx)
    // has no internal scroll container -- same real, no-scroll-on-tall-content
    // gap as the "New User" modal (see access-control.spec.ts's own comment
    // on this), and this view has many panels (header, value, accessors,
    // recent access, description, tags, audit trail, risk score,
    // dependencies, metadata, sharing, permissions) so it overflows a
    // standard viewport even more readily. Folded into SESSION-WEB-E2E's J36
    // UI-polish report; worked around here with a taller viewport.
    await page.setViewportSize({ width: 1280, height: 2600 });

    const unique = Date.now();
    const projectName = `e2e-secrets-${unique}`;
    const envName = `e2eenv${unique}`;
    const secretName = `e2e-secret-${unique}`;
    const originalValue = `original-value-${unique}-${Math.random().toString(36).slice(2)}`;
    const rotatedValue = `rotated-value-${unique}-${Math.random().toString(36).slice(2)}`;

    await realLogin(page);
    const projectUrl = await createProjectEnvAndSecret(page, {
        projectName,
        envName,
        secretName,
        value: originalValue,
    });

    // The value must never appear in the plain row/list view.
    const row = page.getByRole('row', { name: new RegExp(secretName) });
    await expect(row).toBeVisible();
    await expect(page.locator('body')).not.toContainText(originalValue);

    // ── Open the detail view: value must be hidden, no reveal clicked here ──
    await row.getByTitle('View').click();
    await expect(page.getByRole('heading', { name: 'Secret Value' })).toBeVisible();
    await expect(page.getByText('Secret value is hidden for security')).toBeVisible();
    await expect(page.locator('body')).not.toContainText(originalValue);
    expect(page.url(), 'the secret value must never appear in the page URL').not.toContain(originalValue);

    // No request for the version data (which is what Reveal would normally
    // fetch) has been made -- confirms the value was never even requested,
    // not just hidden client-side.
    let versionsRequests = 0;
    page.on('request', (req) => {
        if (/\/secrets\/\d+\/versions/.test(req.url())) versionsRequests++;
    });

    // ── Update (rotate), without ever revealing ─────────────────────────────
    // Deliberately NOT clicking Reveal first (see this file's header comment
    // and issue #2450) -- Rotate is reachable directly from the detail
    // header regardless of reveal state.
    await page.getByRole('button', { name: 'Rotate', exact: true }).click();
    await page.getByLabel('New value').fill(rotatedValue);
    await page.getByRole('button', { name: 'Rotate secret' }).click();
    await expect(page.getByText(`Rotate ${secretName}`)).not.toBeVisible({ timeout: 10_000 });
    expect(versionsRequests, 'rotating a secret never requires fetching its value').toBe(0);

    // ── Delete, then restore from the project's recycle bin ─────────────────
    await page.getByRole('button', { name: 'Delete', exact: true }).click();
    await expect(page.getByText('Delete Secret')).toBeVisible();
    await page.getByRole('button', { name: 'Delete', exact: true }).click();
    await expect(page.getByText('Delete Secret')).not.toBeVisible({ timeout: 10_000 });
    await expect(page.getByRole('row', { name: new RegExp(secretName) })).toHaveCount(0);

    await page.goto(`${projectUrl}/settings`);
    await expect(page.getByText('Recycle bin')).toBeVisible();
    const recycleRow = page.locator('li', { hasText: secretName });
    await expect(recycleRow).toBeVisible({ timeout: 10_000 });
    await recycleRow.getByRole('button', { name: 'Restore' }).click();
    await expect(recycleRow).toHaveCount(0, { timeout: 10_000 });

    await page.goto(`${projectUrl}/secrets?env=${envName}`);
    await expect(page.getByRole('row', { name: new RegExp(secretName) })).toBeVisible({ timeout: 10_000 });
});

test('revealing a secret value crashes the page (known bug #2450)', async ({ page }) => {
    // https://github.com/keyorixhq/keyorix/issues/2450 -- the versions
    // endpoint Reveal reads from (GET /secrets/{id}/versions) can never
    // return a value field at all (internal/storage/models.SecretVersion's
    // EncryptedValue is tagged `json:"-"`), but
    // web/src/features/secrets/SecretDetailView.tsx's Reveal handler calls
    // atob() on that always-undefined field unconditionally. atob(undefined)
    // coerces to the literal string "undefined", which is not valid base64,
    // so it throws and the nearest route error boundary replaces the whole
    // page with "Page failed to load." Confirmed live through this exact UI
    // flow and independently via the API (GET .../versions never has a value
    // field; GET .../secrets/{id}?include_value=true -- the endpoint that
    // DOES work -- returns the correct plaintext).
    test.fail(true, 'issue #2450 -- Reveal always atob()s a field the API structurally never returns');

    await page.setViewportSize({ width: 1280, height: 2600 });

    const unique = Date.now();
    const projectName = `e2e-reveal-crash-${unique}`;
    const envName = `e2eenv${unique}`;
    const secretName = `e2e-secret-${unique}`;
    const value = `value-${unique}`;

    await realLogin(page);
    await createProjectEnvAndSecret(page, { projectName, envName, secretName, value });

    const row = page.getByRole('row', { name: new RegExp(secretName) });
    await row.getByTitle('View').click();

    // What SHOULD happen: the plaintext value renders in place of the
    // "hidden" placeholder. What ACTUALLY happens: this click throws inside
    // SecretDetailView's render and the whole page is replaced by the
    // RouteErrorBoundary's fallback -- there is no plaintext to find.
    await page.getByRole('button', { name: 'Reveal' }).click();
    await expect(page.locator('body')).toContainText(value, { timeout: 10_000 });
});
