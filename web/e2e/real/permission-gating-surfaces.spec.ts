// web/e2e/real/permission-gating-surfaces.spec.ts -- WEB-GATING-TAILS-3 (4095 L3): the project
// Settings tab, the project Access Review tab and the Rotation Policies page offer a least-privilege
// user no write control, and offer the admin all of them, against a REAL keyorix-server.
//
// The persona is the one scripts/e2e/web-real-smoke.sh seeds (same as demo-permission-aware.spec.ts):
// system_viewer globally plus project_viewer on web-e2e-project. She holds secrets.read only, so none
// of secrets.write (project edit, freeze, environments, rotation policies) or roles.assign / roles.read
// (access-review decisions). The admin runs the same pages as the positive control: without it
// "the button is absent" would also pass on a page that rendered nothing.
//
// Run via scripts/e2e/web-real-smoke.sh (it boots the backend, seeds, and exports the env vars read
// below), never directly.
import { test, expect, Page } from '@playwright/test';

const ADMIN_USERNAME = process.env.KEYORIX_E2E_ADMIN_USERNAME;
const ADMIN_PASSWORD = process.env.KEYORIX_E2E_ADMIN_PASSWORD;
const LOWPRIV_USERNAME = process.env.KEYORIX_E2E_LOWPRIV_USERNAME;
const LOWPRIV_PASSWORD = process.env.KEYORIX_E2E_LOWPRIV_PASSWORD;
const PROJECT_NAME = process.env.KEYORIX_E2E_PROJECT_NAME;

if (!ADMIN_USERNAME || !ADMIN_PASSWORD || !LOWPRIV_USERNAME || !LOWPRIV_PASSWORD || !PROJECT_NAME) {
    throw new Error(
        'KEYORIX_E2E_{ADMIN,LOWPRIV}_{USERNAME,PASSWORD} and KEYORIX_E2E_PROJECT_NAME are not all ' +
            'set -- run scripts/e2e/web-real-smoke.sh, which bootstraps the accounts, seeds the ' +
            'project and exports them.'
    );
}

async function login(page: Page, username: string, password: string) {
    await page.goto('/login');
    await page.getByTestId('username-input').fill(username);
    await page.getByTestId('password-input').fill(password);
    await page.getByTestId('login-button').click();
    await page.waitForURL(/\/dashboard/, { timeout: 20_000 });
}

async function settle(page: Page) {
    await page.waitForLoadState('networkidle', { timeout: 20_000 }).catch(() => undefined);
    await page.waitForTimeout(500);
}

// The seeded project's id, from the API as the signed-in session.
async function projectId(page: Page): Promise<number> {
    const id = await page.evaluate(async (name) => {
        const res = await fetch('/api/v1/projects', { credentials: 'include' });
        if (!res.ok) return null;
        const body = await res.json();
        const hit = (body.data?.projects ?? []).find((p: { name?: string }) => p.name === name);
        return hit?.id ?? null;
    }, PROJECT_NAME as string);
    expect(id, `the signed-in user must see project ${PROJECT_NAME}`).not.toBeNull();
    return id as number;
}

const RAW_AXIOS = /Request failed with status code \d+/;

test.describe('least-privilege user (alice): Settings, Access Review, Rotation Policies', () => {
    test.beforeEach(async ({ page }) => {
        await login(page, LOWPRIV_USERNAME as string, LOWPRIV_PASSWORD as string);
    });

    test('the project Settings tab renders without a Save, Freeze, Add environment or Delete Project', async ({
        page,
    }) => {
        const pid = await projectId(page);
        await page.goto(`/projects/${pid}/settings`);
        await settle(page);
        const main = page.locator('main');
        // The tab itself is up (the form is shown read-only), so the absences below are not an empty page.
        await expect(main.getByLabel(/Project name/)).toBeVisible();
        await expect(main.getByLabel(/Project name/)).toBeDisabled();
        await expect(main.getByLabel(/Require MFA for this project/)).toBeDisabled();
        await expect(main.getByRole('button', { name: 'Save' })).toHaveCount(0);
        await expect(main.getByPlaceholder('New environment name…')).toHaveCount(0);
        await expect(main.getByRole('button', { name: 'Freeze all secrets' })).toHaveCount(0);
        await expect(main.getByRole('button', { name: 'Resume all' })).toHaveCount(0);
        await expect(main.getByRole('button', { name: 'Delete Project' })).toHaveCount(0);
        await expect(main.getByTitle(/Promote/)).toHaveCount(0);
        await expect(main.getByTitle('Delete environment')).toHaveCount(0);
        expect(await main.innerText()).not.toMatch(RAW_AXIOS);
    });

    test('the project Access Review tab offers no Attest, Revoke or campaign decision', async ({ page }) => {
        const pid = await projectId(page);
        await page.goto(`/projects/${pid}/access-review`);
        await settle(page);
        const main = page.locator('main');
        await expect(main.getByRole('heading', { name: 'Access Review', exact: true })).toBeVisible();
        await expect(main.getByRole('button', { name: 'Attest', exact: true })).toHaveCount(0);
        await expect(main.getByTitle('Remove this access')).toHaveCount(0);
        expect(await main.innerText()).not.toMatch(RAW_AXIOS);
    });

    test('the Rotation Policies page offers no New Policy, Edit or Delete', async ({ page }) => {
        await page.goto('/secrets/rotation');
        await settle(page);
        const main = page.locator('main');
        // GET /rotation-policies needs a deployment-wide secrets.read (no ?project_id= scope is sent), which
        // this persona only holds per project, so the page shows its refusal card instead of the list and
        // heading (ui-route-walk.spec.ts asserts the same). Assert that state, so the absences below are
        // not an empty page; the admin test below proves the controls render when the page loads.
        await expect(main.getByText('Failed to load rotation policies')).toBeVisible();
        await expect(main.getByRole('button', { name: /new policy/i })).toHaveCount(0);
        await expect(main.getByTitle('Edit', { exact: true })).toHaveCount(0);
        await expect(main.getByTitle('Delete', { exact: true })).toHaveCount(0);
        expect(await main.innerText()).not.toMatch(RAW_AXIOS);
    });
});

test.describe('admin keeps every control on those surfaces (positive control)', () => {
    test.beforeEach(async ({ page }) => {
        await login(page, ADMIN_USERNAME as string, ADMIN_PASSWORD as string);
    });

    test('the project Settings tab offers Save, Add environment, Freeze and Delete Project', async ({ page }) => {
        const pid = await projectId(page);
        await page.goto(`/projects/${pid}/settings`);
        await settle(page);
        const main = page.locator('main');
        await expect(main.getByLabel(/Project name/)).toBeEnabled();
        await expect(main.getByLabel(/Require MFA for this project/)).toBeEnabled();
        // General and Security each carry a Save.
        await expect(main.getByRole('button', { name: 'Save' })).toHaveCount(2);
        await expect(main.getByPlaceholder('New environment name…')).toBeVisible();
        await expect(main.getByRole('button', { name: 'Freeze all secrets' })).toBeVisible();
        await expect(main.getByRole('button', { name: 'Delete Project' })).toBeVisible();
    });

    test('the project Access Review tab offers Attest on a grant', async ({ page }) => {
        const pid = await projectId(page);
        await page.goto(`/projects/${pid}/access-review`);
        await settle(page);
        const main = page.locator('main');
        await expect(main.getByRole('heading', { name: 'Access Review', exact: true })).toBeVisible();
        await expect(main.getByRole('button', { name: 'Attest', exact: true }).first()).toBeVisible();
    });

    test('the Rotation Policies page offers New Policy', async ({ page }) => {
        await page.goto('/secrets/rotation');
        await settle(page);
        const main = page.locator('main');
        await expect(main.getByRole('heading', { name: 'Rotation Policies', exact: true })).toBeVisible();
        await expect(main.getByRole('button', { name: /new policy/i }).first()).toBeVisible();
    });
});
