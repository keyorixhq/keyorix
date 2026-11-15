// web/e2e/real/secret-reveal-copy.spec.ts -- Reveal and Copy value against a REAL keyorix-server (#2450).
//
// #2450: Reveal and the list's Copy value read the plaintext from a field the versions API never
// returns (GET .../versions is metadata only; EncryptedValue is `json:"-"`), atob() threw and the
// route error boundary replaced the whole page. Both now read GET /secrets/{id}?include_value=true.
// secrets-crud.spec.ts covers Reveal inside the full lifecycle and secret-read-refusal.spec.ts
// covers the REFUSED reads; this spec is the success path of both controls, end to end:
//
//   1. Reveal shows the plaintext from the include_value read (200) and the page keeps working
//      (no pageerror, no "Page failed to load", Hide re-masks, a second Reveal works).
//   2. The versions list the page fetches alongside carries no value: neither the plaintext nor
//      an EncryptedValue key appears in it (the shape the old code decoded).
//   3. The list's Copy value puts exactly the plaintext on the clipboard, and the list stays up.
//   4. Reveal, then the detail view's own Copy, puts exactly the plaintext on the clipboard.
//
// Login budget (see web-real-smoke.sh): 1 API login + 1 UI login = 2 of 10.
//
// Run via scripts/e2e/web-real-smoke.sh, never directly.
import { test, expect, Page, request as apiRequestFactory } from '@playwright/test';
import { ADMIN_USERNAME, ADMIN_PASSWORD, BACKEND_URL, apiLogin, realLogin } from './helpers';

const WEB_PORT = process.env.KEYORIX_E2E_WEB_PORT || '18190';
const WEB_URL = `http://localhost:${WEB_PORT}`;

const stamp = Date.now();
const secretName = `reveal-copy-${stamp}`;
const secretValue = `plaintext-${stamp}`;

let projectId: number;
let envName: string;
let secretId: number;
let page: Page;
let pageErrors: string[];
let versionsBodies: string[];

async function mustBearer(token: string, method: 'GET' | 'POST', path: string, data?: unknown) {
    const ctx = await apiRequestFactory.newContext({ baseURL: BACKEND_URL });
    try {
        const res = await ctx.fetch(path, {
            method,
            headers: { Authorization: `Bearer ${token}` },
            ...(data === undefined ? {} : { data }),
        });
        if (res.status() >= 300) throw new Error(`setup ${method} ${path} failed: ${res.status()} ${await res.text()}`);
        return await res.json();
    } finally {
        await ctx.dispose();
    }
}

const isValueRead = (url: string) =>
    new URL(url).pathname === `/api/v1/secrets/${secretId}` &&
    new URL(url).searchParams.get('include_value') === 'true';

async function openList() {
    await page.goto(`/projects/${projectId}/secrets?env=${envName}`);
    const row = page.getByRole('row', { name: secretName });
    await expect(row).toBeVisible({ timeout: 15_000 });
    return row;
}

async function clipboardText(): Promise<string> {
    return page.evaluate(() => navigator.clipboard.readText());
}

// The page must still be the real screen, not the route error boundary's fallback.
async function expectPageAlive() {
    await expect(page.getByText('Page failed to load')).toHaveCount(0);
    expect(pageErrors, 'a Reveal / Copy must not throw out of the page (atob of a missing field)').toEqual([]);
}

test.describe.configure({ mode: 'serial' });

test.beforeAll(async ({ browser }) => {
    const adminToken = await apiLogin(ADMIN_USERNAME as string, ADMIN_PASSWORD as string);
    projectId = (
        await mustBearer(adminToken, 'POST', '/api/v1/projects', {
            name: `e2e-reveal-copy-${stamp}`,
            description: 'secret-reveal-copy e2e fixture',
        })
    ).data.id;
    const envs = await mustBearer(adminToken, 'GET', `/api/v1/projects/${projectId}/environments`);
    const envId = envs.data.environments[0].id as number;
    envName = envs.data.environments[0].name as string;
    secretId = (
        await mustBearer(adminToken, 'POST', '/api/v1/secrets', {
            name: secretName,
            value: secretValue,
            type: 'text',
            project_id: projectId,
            environment_id: envId,
        })
    ).data.id as number;

    const ctx = await browser.newContext({ baseURL: WEB_URL, viewport: { width: 1280, height: 2600 } });
    await ctx.grantPermissions(['clipboard-read', 'clipboard-write'], { origin: WEB_URL });
    page = await ctx.newPage();
    await realLogin(page, ADMIN_USERNAME as string, ADMIN_PASSWORD as string);
});

test.beforeEach(() => {
    pageErrors = [];
    versionsBodies = [];
    page.removeAllListeners('pageerror');
    page.removeAllListeners('response');
    page.on('pageerror', (e) => pageErrors.push(e.message));
    page.on('response', (r) => {
        if (new URL(r.url()).pathname === `/api/v1/secrets/${secretId}/versions`) {
            void r.text().then((t) => versionsBodies.push(t));
        }
    });
});

test.afterEach(async () => {
    const testInfo = test.info();
    if (testInfo.status === testInfo.expectedStatus) return;
    await page?.screenshot({ path: testInfo.outputPath('page.png'), fullPage: true }).catch(() => undefined);
});

test.afterAll(async () => {
    await page
        ?.context()
        .close()
        .catch(() => undefined);
});

test('Reveal shows the plaintext from the value read and the page keeps working', async () => {
    const row = await openList();
    await row.getByTitle('View').click();

    const valueRead = page.waitForResponse((r) => isValueRead(r.url()));
    await page.getByRole('button', { name: 'Reveal', exact: true }).click();
    expect((await valueRead).status()).toBe(200);
    await expect(page.locator('body')).toContainText(secretValue, { timeout: 10_000 });
    await expect(page.getByRole('heading', { name: 'Secret Value' })).toBeVisible();
    await expectPageAlive();

    // Hide re-masks, and a second Reveal works (the page is not stuck after the first).
    await page.getByRole('button', { name: 'Hide', exact: true }).click();
    await expect(page.locator('body')).not.toContainText(secretValue);
    await page.getByRole('button', { name: 'Reveal', exact: true }).click();
    await expect(page.locator('body')).toContainText(secretValue, { timeout: 10_000 });
    await expectPageAlive();
});

test('the versions list the page fetches carries no value for Reveal to decode', async () => {
    const row = await openList();
    await row.getByTitle('View').click();
    await page.getByRole('button', { name: 'Reveal', exact: true }).click();
    await expect(page.locator('body')).toContainText(secretValue, { timeout: 10_000 });

    // Reveal asks for the versions too (Version History); whatever it got must be metadata only.
    await expect.poll(() => versionsBodies.length, { timeout: 10_000 }).toBeGreaterThan(0);
    for (const body of versionsBodies) {
        expect(body).not.toContain(secretValue);
        expect(body).not.toContain('EncryptedValue');
        expect(JSON.parse(body).data.versions[0]).toHaveProperty('VersionNumber');
    }
});

test("the list's Copy value copies exactly the plaintext and the list stays up", async () => {
    const row = await openList();
    const valueRead = page.waitForResponse((r) => isValueRead(r.url()));
    await row.getByTitle('Copy value').click();
    expect((await valueRead).status()).toBe(200);

    await expect.poll(clipboardText, { timeout: 5_000 }).toBe(secretValue);
    await expect(row).toBeVisible();
    await expect(row.getByTitle('Copy value')).toBeEnabled();
    await expectPageAlive();
});

test("Reveal then the detail view's Copy copies exactly the plaintext", async () => {
    await page.evaluate(() => navigator.clipboard.writeText('stale'));
    const row = await openList();
    await row.getByTitle('View').click();
    await page.getByRole('button', { name: 'Reveal', exact: true }).click();
    await expect(page.locator('body')).toContainText(secretValue, { timeout: 10_000 });

    // Two buttons are named "Copy": the header's copy-to-another-environment action and the value
    // panel's copy-the-revealed-value action, which comes last in the DOM.
    await page.getByRole('button', { name: 'Copy', exact: true }).last().click();
    await expect(page.getByText('Copied!')).toBeVisible({ timeout: 5_000 });
    expect(await clipboardText()).toBe(secretValue);
    await expectPageAlive();
});
