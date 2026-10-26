// web/e2e/real/suspend-clear-synced-copies-expired.spec.ts — the case FIX-3215 left out of
// suspend-clear-synced-copies.spec.ts: a secret that is suspended with "also clear synced
// copies" AND then expires, against a REAL keyorix-server.
//
// The server judges expiry before suspension (internal/core/secret_suspend_clear_copies_expired_test.go
// covers this at the core layer), so once the secret expires the read refusal changes from
// SecretSuspended to SecretExpired. The clear choice must survive that switch, or the operator
// and k8s-sync keep the copies the user was told would be cleared. Driven end to end:
//
//   1. The secret is created with a short expiry and suspended through the UI with the box checked.
//   2. After the expiry passes the reader gets a 409 SecretExpired refusal that still carries
//      details.clear_synced_copies:true and never the secret value (an expired credential is
//      not usable; the server answers 409 for an expired secret, not 401).
//   3. The audit log still shows the secret.suspended event for that secret.
//   4. Control: an expired secret that was never suspended carries no details.
//
// Login budget (see web-real-smoke.sh): 1 API login + 1 UI login = 2 of 10.
//
// Run via scripts/e2e/web-real-smoke.sh, never directly.
import { test, expect, Page, request as apiRequestFactory } from '@playwright/test';
import { ADMIN_USERNAME, ADMIN_PASSWORD, BACKEND_URL, apiLogin, realLogin } from './helpers';

const WEB_PORT = process.env.KEYORIX_E2E_WEB_PORT || '18190';
const WEB_URL = `http://localhost:${WEB_PORT}`;

// Seconds the fixtures stay valid, counted from after the UI login: long enough for the UI
// suspend on a slow VM, short enough to wait out.
const EXPIRY_SECONDS = 60;

const stamp = Date.now();
const suspendedName = `expired-suspended-${stamp}`;
const controlName = `expired-control-${stamp}`;

let adminToken: string;
let projectId: number;
let envName: string;
let page: Page;
const ids: Record<string, number> = {};

async function bearer(method: 'GET' | 'POST', path: string, data?: unknown) {
    const ctx = await apiRequestFactory.newContext({ baseURL: BACKEND_URL });
    try {
        const res = await ctx.fetch(path, {
            method,
            headers: { Authorization: `Bearer ${adminToken}` },
            ...(data === undefined ? {} : { data }),
        });
        return { status: res.status(), body: await res.json().catch(() => ({})) };
    } finally {
        await ctx.dispose();
    }
}

async function mustBearer(method: 'GET' | 'POST', path: string, data?: unknown) {
    const r = await bearer(method, path, data);
    if (r.status >= 300) throw new Error(`setup ${method} ${path} failed: ${r.status} ${JSON.stringify(r.body)}`);
    return r.body;
}

// stored is what the server says about the secret while it is still unexpired.
async function stored(name: string) {
    const body = await mustBearer('GET', `/api/v1/secrets/${ids[name]}`);
    return { status: body.data.status as string, clear: Boolean(body.data.clear_synced_copies) };
}

// refusal reads the value the way a workload would and returns the refusal envelope.
async function refusal(name: string) {
    const r = await bearer('GET', `/api/v1/secrets/${ids[name]}?include_value=true`);
    return { status: r.status, error: r.body.error as string, details: r.body.details, raw: JSON.stringify(r.body) };
}

async function openDetail(name: string) {
    await page.goto(`/projects/${projectId}/secrets?env=${envName}`);
    const row = page.getByRole('row', { name });
    await expect(row).toBeVisible({ timeout: 15_000 });
    await row.getByTitle('View').click();
    await expect(page.getByTestId('secret-header')).toBeVisible({ timeout: 10_000 });
}

const suspendDialog = () => page.getByRole('dialog', { name: /^Suspend / });

const suspendCall = (name: string) =>
    page.waitForRequest(
        (r) => r.method() === 'POST' && new URL(r.url()).pathname === `/api/v1/secrets/${ids[name]}/suspend`
    );

test.describe.configure({ mode: 'serial' });

test.beforeAll(async ({ browser }) => {
    adminToken = await apiLogin(ADMIN_USERNAME as string, ADMIN_PASSWORD as string);
    projectId = (
        await mustBearer('POST', '/api/v1/projects', {
            name: `e2e-purge-exp-${stamp}`,
            description: 'suspend-clear-synced-copies-expired e2e fixture',
        })
    ).data.id;
    const envs = await mustBearer('GET', `/api/v1/projects/${projectId}/environments`);
    const envId = envs.data.environments[0].id as number;
    envName = envs.data.environments[0].name as string;

    const ctx = await browser.newContext({ baseURL: WEB_URL, viewport: { width: 1280, height: 2600 } });
    page = await ctx.newPage();
    await realLogin(page, ADMIN_USERNAME as string, ADMIN_PASSWORD as string);

    // Created after the UI login so the login's time does not eat into the expiry window.
    const expiration = new Date(Date.now() + EXPIRY_SECONDS * 1000).toISOString();
    for (const name of [suspendedName, controlName]) {
        ids[name] = (
            await mustBearer('POST', '/api/v1/secrets', {
                name,
                value: `value-${name}`,
                type: 'text',
                project_id: projectId,
                environment_id: envId,
                expiration,
            })
        ).data.id as number;
    }
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

test('suspending with the clear box checked, before expiry, stores the choice', async () => {
    await openDetail(suspendedName);
    await page.getByRole('button', { name: 'Suspend', exact: true }).click();
    const dialog = suspendDialog();
    await dialog.getByLabel(/Also clear copies synced to Kubernetes clusters/i).check();

    const request = suspendCall(suspendedName);
    await dialog.getByRole('button', { name: 'Suspend secret', exact: true }).click();
    expect((await request).postDataJSON()).toMatchObject({ clear_synced_copies: true });
    await expect(page.getByTestId('suspended-badge')).toBeVisible({ timeout: 10_000 });

    expect(await stored(suspendedName)).toEqual({ status: 'suspended', clear: true });
    // Not expired yet: still the suspended refusal with the marker.
    const refused = await refusal(suspendedName);
    expect(refused.status).toBe(409);
    expect(refused.error).toBe('SecretSuspended');
    expect(refused.details).toEqual({ clear_synced_copies: true });
});

test('once expired, the refusal is SecretExpired, still carries the clear marker and never the value', async () => {
    test.setTimeout(EXPIRY_SECONDS * 1000 + 60_000);
    // Wait out the expiry; the refusal code flips from SecretSuspended to SecretExpired.
    await expect
        .poll(async () => (await refusal(suspendedName)).error, {
            timeout: EXPIRY_SECONDS * 1000 + 30_000,
            intervals: [1_000],
        })
        .toBe('SecretExpired');

    const refused = await refusal(suspendedName);
    expect(refused.status).toBe(409);
    expect(refused.details).toEqual({ clear_synced_copies: true });
    expect(refused.raw).not.toContain(`value-${suspendedName}`);
});

test('the audit log shows the suspend of the expired secret', async () => {
    await expect
        .poll(
            async () => {
                const r = await bearer('GET', `/api/v1/audit/logs?secret_id=${ids[suspendedName]}&page_size=100`);
                const logs = (r.body.data?.logs ?? []) as { event_type: string }[];
                return logs.map((l) => l.event_type);
            },
            { timeout: 15_000 }
        )
        .toContain('secret.suspended');
});

test('control: an expired secret that was never suspended carries no details', async () => {
    const refused = await refusal(controlName);
    expect(refused.status).toBe(409);
    expect(refused.error).toBe('SecretExpired');
    expect(refused.details).toBeUndefined();
    expect(refused.raw).not.toContain(`value-${controlName}`);
});
