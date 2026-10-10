// web/e2e/real/share-elevation.spec.ts — E2E-SHARE-1: share → elevated access → revoke, driven
// through the real UI against a REAL keyorix-server (#3001, decision #2941).
//
// The rule under test: a share may ELEVATE a project member's access on that one secret
// (effective = max(role, active share)); revoking the share removes exactly the elevation;
// the owner must be a live project member to share (a global admin with no project role is
// refused), and the refusal says what to do rather than a bare 403.
//
//   1. owner (project_admin, member) shares secret A with a project_viewer at `write`
//      → the Share dialog reports success and the share shows up in Sharing Management.
//   2. the viewer edits A in the UI (the value really changes) while B, which was NOT
//      shared, stays read-only: the UI refuses the edit and the API answers 403.
//   3. owner revokes the share in Sharing Management → the row disappears (UI and API) and
//      the viewer's edit of A is refused again, the value unchanged.
//   4. a global admin who OWNS a secret but holds no role in its project tries to share →
//      the dialog shows the explanatory message and the API answers 403 with the same text.
//
// Login budget: server/http/handlers/auth.go allows 10 login attempts per IP per 15 min and
// web-real-smoke.sh gives every spec file its own fresh server. This file uses 3 API logins
// (admin, owner-setup, viewer-checks) + 3 UI logins (owner, viewer, admin) + 1 seeding
// login = 7. Each persona logs in ONCE and keeps its browser context for the whole serial
// run, so adding a test here does not add logins.
//
// require_mfa is switched off for this harness by web-real-smoke.sh (see its comment on
// the sed), so there is no MFA step; MFA login is covered by mfa-login.spec.ts.
//
// Run via scripts/e2e/web-real-smoke.sh, never directly.
import { test, expect, Browser, BrowserContext, Page, request as apiRequestFactory } from '@playwright/test';
import { ADMIN_USERNAME, ADMIN_PASSWORD, BACKEND_URL, apiLogin, realLogin } from './helpers';
import { compliantPassword, personalInfoCandidates } from './support/password';

const WEB_PORT = process.env.KEYORIX_E2E_WEB_PORT || '18190';
const WEB_URL = `http://localhost:${WEB_PORT}`;

// The fixed server-side wording (internal/core/share_authz.go ShareRefusalMessage). Asserted on
// a stable fragment of each sentence rather than the whole string, so a copy tweak that keeps
// the advice does not break the spec, but dropping the advice does.
const OWNER_NOT_MEMBER_MESSAGE = /not a member of this secret's project/i;
const OWNER_NOT_MEMBER_ADVICE = /Ask a project admin to give you a role in the project/i;

interface Persona {
    username: string;
    password: string;
    id: number;
}

const stamp = Date.now();
const projectName = `e2e-share-${stamp}`;
const secretAName = `share-a-${stamp}`;
const secretBName = `share-b-${stamp}`;
const secretCName = `share-c-${stamp}`;
const valueA0 = `value-a-original-${stamp}`;
const valueA1 = `value-a-by-viewer-${stamp}`;
const valueA2 = `value-a-after-revoke-${stamp}`;
const valueB0 = `value-b-original-${stamp}`;
const valueB1 = `value-b-by-viewer-${stamp}`;

let projectId: number;
let envName: string;
let owner: Persona;
let viewer: Persona;
let secretA: number;
let secretB: number;
let secretC: number;
let adminToken: string;
let viewerToken: string;
let ownerPage: Page;
let viewerPage: Page;
let adminPage: Page;
const contexts: BrowserContext[] = [];

// bearer runs one API call with a fresh cookie-free context (see helpers.ts apiLogin for why a
// context must not be reused across a login and a mutation).
async function bearer(
    token: string,
    method: 'GET' | 'POST' | 'PUT' | 'DELETE',
    path: string,
    data?: unknown
): Promise<{ status: number; body: any }> {
    const ctx = await apiRequestFactory.newContext({ baseURL: BACKEND_URL });
    try {
        const res = await ctx.fetch(path, {
            method,
            headers: { Authorization: `Bearer ${token}` },
            ...(data === undefined ? {} : { data }),
        });
        let body: any = null;
        try {
            body = await res.json();
        } catch {
            body = null;
        }
        return { status: res.status(), body };
    } finally {
        await ctx.dispose();
    }
}

async function mustBearer(token: string, method: 'GET' | 'POST' | 'PUT' | 'DELETE', path: string, data?: unknown) {
    const res = await bearer(token, method, path, data);
    if (res.status >= 300) throw new Error(`setup ${method} ${path} failed: ${res.status} ${JSON.stringify(res.body)}`);
    return res.body;
}

// createUser mirrors helpers.ts createDedicatedUser but lets the caller pick a global role,
// which that helper does not take. `role` is the same field web-real-smoke.sh's seeding uses.
async function createUser(prefix: string, label: string, role?: string): Promise<Persona> {
    const username = `${prefix}${stamp}`;
    const email = `${username}@example.invalid`;
    const displayName = `${label} ${stamp}`;
    const password = compliantPassword(personalInfoCandidates({ username, email, displayName }));
    const body = await mustBearer(adminToken, 'POST', '/api/v1/users', {
        username,
        email,
        display_name: displayName,
        password,
        ...(role ? { role } : {}),
    });
    return { username, password, id: body.data.id as number };
}

async function newPersonaPage(browser: Browser, who: { username: string; password: string }): Promise<Page> {
    const ctx = await browser.newContext({ baseURL: WEB_URL, viewport: { width: 1280, height: 1600 } });
    contexts.push(ctx);
    const page = await ctx.newPage();
    await realLogin(page, who.username, who.password);
    return page;
}

async function settle(page: Page) {
    await page.waitForLoadState('networkidle', { timeout: 20_000 }).catch(() => undefined);
}

async function openProjectSecrets(page: Page) {
    // The tab opens on "Production" by default; the fixture secrets live in the first environment.
    await page.goto(`/projects/${projectId}/secrets?env=${envName}`);
    await settle(page);
}

function secretRow(page: Page, name: string) {
    return page.getByRole('row', { name: new RegExp(name) });
}

// openShareDialog + fillShare drive the Share dialog for `recipient` at `permission`.
async function openShareDialog(page: Page, secretName: string) {
    await openProjectSecrets(page);
    await expect(secretRow(page, secretName)).toBeVisible({ timeout: 15_000 });
    await secretRow(page, secretName).getByTitle('Share').click();
    await expect(page.getByRole('dialog')).toContainText(`Share "${secretName}"`);
}

async function fillShare(page: Page, recipient: Persona, permission: 'read' | 'write') {
    const dialog = page.getByRole('dialog');
    await dialog.locator('#recipient-input').fill(recipient.username);
    await dialog.getByRole('button', { name: new RegExp(`@${recipient.username}`) }).click();
    await dialog.locator('#permission-select').selectOption(permission);
    const answered = page.waitForResponse(
        (r) => /\/api\/v1\/secrets\/\d+\/share$/.test(new URL(r.url()).pathname) && r.request().method() === 'POST'
    );
    await dialog.getByRole('button', { name: 'Share', exact: true }).click();
    return (await answered).status();
}

// editSecretValue drives the Edit dialog and returns once the request has been answered.
async function editSecretValue(page: Page, secretName: string, newValue: string) {
    await openProjectSecrets(page);
    await expect(secretRow(page, secretName)).toBeVisible({ timeout: 15_000 });
    await secretRow(page, secretName).getByTitle('Edit').click();
    const dialog = page.getByRole('dialog');
    await expect(dialog).toContainText(`Edit Secret: ${secretName}`);
    await dialog.locator('#edit-secret-value').fill(newValue);
    const answered = page.waitForResponse(
        (r) => /\/api\/v1\/secrets\/\d+$/.test(new URL(r.url()).pathname) && r.request().method() === 'PUT'
    );
    await dialog.getByRole('button', { name: 'Save Changes' }).click();
    return (await answered).status();
}

// readValue asks the API, as the page's own session, for a secret's plaintext.
async function readValue(page: Page, id: number): Promise<string | null> {
    return page.evaluate(async (secretId) => {
        const res = await fetch(`/api/v1/secrets/${secretId}?include_value=true`, { credentials: 'include' });
        if (!res.ok) return null;
        const body = await res.json();
        return (body.data?.value ?? body.data?.secret?.value ?? null) as string | null;
    }, id);
}

test.describe.configure({ mode: 'serial' });

test.beforeAll(async ({ browser }) => {
    adminToken = await apiLogin(ADMIN_USERNAME as string, ADMIN_PASSWORD as string);

    // The bootstrap admin creates the project but is NOT a member of it: creating a project
    // grants the creator no role in it (web-real-smoke.sh adds the self-membership explicitly
    // for its own fixture project). That is exactly the "global admin, no project role" persona.
    const project = await mustBearer(adminToken, 'POST', '/api/v1/projects', {
        name: projectName,
        description: 'share-elevation e2e fixture',
    });
    projectId = project.data.id;
    const envs = await mustBearer(adminToken, 'GET', `/api/v1/projects/${projectId}/environments`);
    const envId = envs.data.environments[0].id as number;
    envName = envs.data.environments[0].name as string;

    // owner: project_admin in the project, plus the global read-only system_auditor role. The
    // global role is only here because the Share dialog's recipient search (GET /api/v1/users,
    // users.read) and the Sharing Management page (GET /api/v1/shares, global secrets.read) are
    // GLOBAL-permission gates: a project-only member can open the dialog but finds nobody to
    // pick. That is a product gap, recorded in the PR; it is not what this spec is about.
    // viewer: project_viewer only, no global role.
    owner = await createUser('shareowner', 'Share Owner', 'system_auditor');
    viewer = await createUser('shareviewer', 'Share Viewer');
    await mustBearer(adminToken, 'POST', `/api/v1/projects/${projectId}/members`, {
        user_id: owner.id,
        role: 'project_admin',
    });
    await mustBearer(adminToken, 'POST', `/api/v1/projects/${projectId}/members`, {
        user_id: viewer.id,
        role: 'project_viewer',
    });

    const ownerToken = await apiLogin(owner.username, owner.password);
    const mk = async (token: string, name: string, value: string) =>
        (
            await mustBearer(token, 'POST', '/api/v1/secrets', {
                name,
                value,
                type: 'text',
                project_id: projectId,
                environment_id: envId,
            })
        ).data.id as number;
    secretA = await mk(ownerToken, secretAName, valueA0);
    secretB = await mk(ownerToken, secretBName, valueB0);
    // C is owned by the admin, who holds no role in the project.
    secretC = await mk(adminToken, secretCName, `value-c-${stamp}`);

    viewerToken = await apiLogin(viewer.username, viewer.password);

    ownerPage = await newPersonaPage(browser, owner);
    viewerPage = await newPersonaPage(browser, viewer);
    adminPage = await newPersonaPage(browser, {
        username: ADMIN_USERNAME as string,
        password: ADMIN_PASSWORD as string,
    });
});

test.afterEach(async () => {
    const testInfo = test.info();
    if (testInfo.status === testInfo.expectedStatus) return;
    for (const [name, page] of [
        ['owner', ownerPage],
        ['viewer', viewerPage],
        ['admin', adminPage],
    ] as const) {
        await page?.screenshot({ path: testInfo.outputPath(`${name}.png`), fullPage: true }).catch(() => undefined);
    }
});

test.afterAll(async () => {
    for (const ctx of contexts) await ctx.close().catch(() => undefined);
});

test('fixture sanity: the viewer starts read-only on both secrets', async () => {
    // Before any share, the viewer's project_viewer role must not allow a write. Without this a
    // later "viewer can edit A" would be vacuous if the role were already permissive.
    for (const id of [secretA, secretB]) {
        const res = await bearer(viewerToken, 'PUT', `/api/v1/secrets/${id}`, { value: `probe-${stamp}` });
        expect(res.status, `a plain project_viewer must not be able to update secret ${id}`).toBe(403);
    }
    // And can read, so the Edit dialog's absence of a value is not a read failure.
    const read = await bearer(viewerToken, 'GET', `/api/v1/secrets/${secretA}`);
    expect(read.status).toBe(200);
});

test('owner shares secret A with the project_viewer at write', async () => {
    await openShareDialog(ownerPage, secretAName);
    const shareStatus = await fillShare(ownerPage, viewer, 'write');
    expect(shareStatus, 'POST /secrets/A/share at write').toBeLessThan(300);
    // ProjectSecretsTab closes the dialog the moment the share succeeds (its onSuccess), so the
    // dialog's own "Shared!" banner never gets to render here: the visible outcome is the dialog
    // closing and the row's Sharing column counting the new share.
    await expect(ownerPage.getByRole('dialog')).toBeHidden({ timeout: 10_000 });
    await expect(secretRow(ownerPage, secretAName)).toContainText('1 shares', { timeout: 10_000 });
    await expect(secretRow(ownerPage, secretBName)).not.toContainText('shares');

    // The Sharing Management page lists it: Secret #A, viewer, "Read & Write".
    await ownerPage.goto('/sharing');
    await settle(ownerPage);
    const row = ownerPage.getByRole('row').filter({ hasText: `Secret #${secretA}` });
    await expect(row).toHaveCount(1, { timeout: 15_000 });
    await expect(row).toContainText('Read & Write');
    await expect(row, 'the recipient is the viewer (shown by display name or username)').toContainText(
        new RegExp(`Share Viewer ${stamp}|${viewer.username}`)
    );
    // Secret B was not shared.
    await expect(ownerPage.getByRole('row').filter({ hasText: `Secret #${secretB}` })).toHaveCount(0);
});

test('the viewer can update the shared secret A in the UI, and B stays read-only', async () => {
    // ── A: the share elevates project_viewer to write on this one secret ──
    const statusA = await editSecretValue(viewerPage, secretAName, valueA1);
    expect(statusA, 'PUT /secrets/A as the elevated viewer').toBe(200);
    await expect(viewerPage.getByRole('dialog')).toBeHidden({ timeout: 10_000 });
    await expect(viewerPage.getByText('Failed to update secret')).toHaveCount(0);
    expect(await readValue(viewerPage, secretA), 'the new value is really stored').toBe(valueA1);

    // ── B: nothing shared, so the viewer's role alone decides ──
    const statusB = await editSecretValue(viewerPage, secretBName, valueB1);
    expect(statusB, 'PUT /secrets/B as the un-elevated viewer').toBe(403);
    const dialog = viewerPage.getByRole('dialog');
    await expect(dialog, 'the refusal must be visible in the dialog, which stays open').toContainText(
        'Failed to update secret'
    );
    const viaApi = await bearer(viewerToken, 'PUT', `/api/v1/secrets/${secretB}`, { value: valueB1 });
    expect(viaApi.status).toBe(403);
    await dialog.getByRole('button', { name: 'Cancel' }).click();
    // The owner still sees B's original value.
    expect(await readValue(ownerPage, secretB)).toBe(valueB0);

    // The elevation is not a role: delete on A is still refused (a share satisfies only
    // secrets.read / secrets.write).
    const del = await bearer(viewerToken, 'DELETE', `/api/v1/secrets/${secretA}`);
    expect(del.status, 'a write share must not allow delete').toBe(403);
});

test('owner revokes the share: it leaves the list and the viewer is refused again', async () => {
    await ownerPage.goto('/sharing');
    await settle(ownerPage);
    const row = ownerPage.getByRole('row').filter({ hasText: `Secret #${secretA}` });
    await expect(row).toHaveCount(1, { timeout: 15_000 });
    await row.getByTitle('Revoke access').click();
    await expect(ownerPage.getByRole('dialog')).toContainText('revoke access for');
    const revoked = ownerPage.waitForResponse(
        (r) => /\/api\/v1\/shares\/\d+$/.test(new URL(r.url()).pathname) && r.request().method() === 'DELETE'
    );
    await ownerPage.getByRole('dialog').getByRole('button', { name: 'Revoke', exact: true }).click();
    expect((await revoked).status(), 'DELETE /shares/{id}').toBeLessThan(300);

    // Gone from the list in the UI (after a reload, so it is the server's answer, not a cache)…
    await ownerPage.reload();
    await settle(ownerPage);
    await expect(ownerPage.getByRole('row').filter({ hasText: `Secret #${secretA}` })).toHaveCount(0, {
        timeout: 15_000,
    });
    // …and from the API's.
    const shares = await ownerPage.evaluate(async (id) => {
        const res = await fetch(`/api/v1/secrets/${id}/shares`, { credentials: 'include' });
        return { status: res.status, text: await res.text() };
    }, secretA);
    expect(shares.status).toBe(200);
    expect(shares.text).not.toContain(viewer.username);

    // The viewer's next update of A is refused, in the UI and at the API, value unchanged.
    const status = await editSecretValue(viewerPage, secretAName, valueA2);
    expect(status, 'PUT /secrets/A after the share was revoked').toBe(403);
    await expect(viewerPage.getByRole('dialog')).toContainText('Failed to update secret');
    const viaApi = await bearer(viewerToken, 'PUT', `/api/v1/secrets/${secretA}`, { value: valueA2 });
    expect(viaApi.status).toBe(403);
    expect(typeof viaApi.body?.message === 'string' && viaApi.body.message.length > 0, 'a reason is given').toBe(true);
    await viewerPage.getByRole('dialog').getByRole('button', { name: 'Cancel' }).click();
    expect(
        await readValue(ownerPage, secretA),
        "the viewer's last accepted value survives; the refused one never landed"
    ).toBe(valueA1);

    // Revoke removed exactly the elevation: the viewer still READS A (project_viewer).
    const read = await bearer(viewerToken, 'GET', `/api/v1/secrets/${secretA}`);
    expect(read.status).toBe(200);
});

test('a global admin who owns a secret but is not a project member is told why the share is refused', async () => {
    await openShareDialog(adminPage, secretCName);
    await fillShare(adminPage, viewer, 'read');
    const dialog = adminPage.getByRole('dialog');
    // Not the axios fallback and not a bare 403: the dialog says what is wrong and what to do.
    await expect(dialog).toContainText(OWNER_NOT_MEMBER_MESSAGE, { timeout: 10_000 });
    await expect(dialog).toContainText(OWNER_NOT_MEMBER_ADVICE);
    await expect(dialog).not.toContainText('Request failed with status code');
    await expect(dialog).not.toContainText('Shared!');

    // The same answer at the API, and nothing was created.
    const res = await bearer(adminToken, 'POST', `/api/v1/secrets/${secretC}/share`, {
        recipient_id: viewer.id,
        is_group: false,
        permission: 'read',
    });
    expect(res.status).toBe(403);
    expect(JSON.stringify(res.body)).toMatch(OWNER_NOT_MEMBER_MESSAGE);
    const shares = await bearer(adminToken, 'GET', `/api/v1/secrets/${secretC}/shares`);
    expect(JSON.stringify(shares.body)).not.toContain(viewer.username);
});
