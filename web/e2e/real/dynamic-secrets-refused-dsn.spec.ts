// web/e2e/real/dynamic-secrets-refused-dsn.spec.ts — DYNAMIC-WEB-TAILS-1 leftover, driven
// against a REAL keyorix-server: a dynamic-secret config whose stored admin DSN names an
// option the server refuses since #3952 shows the "refused admin DSN" banner on
// /secrets/dynamic; replacing the DSN from the banner clears it.
//
//   1. The banner lists the seeded config and the option it refused.
//   2. "Fix admin DSN for <config>" opens the replace form; submitting a clean DSN
//      shows the confirmation line.
//   3. The banner is gone, and the server's own report
//      (GET /api/v1/dynamic-secrets/configs/refused-admin-dsn) no longer lists the config.
//
// SEEDING CONTRACT (not provided by the harness yet). The server refuses such a DSN on
// create AND on replace (dsn.CheckLocalFileOptions), so no API call can produce this
// state: it only exists as pre-#3952 data, written straight to storage with the server's
// key (the Go-side equivalent is storeLegacyConfig in
// internal/core/dynamic_secrets_revoke_stripped_options_test.go). The harness has to seed
// one config with no live leases whose admin DSN carries e.g. sslrootcert=/x, and export
//   KEYORIX_E2E_REFUSED_DSN_PROJECT_ID   id of the project holding it
//   KEYORIX_E2E_REFUSED_DSN_CONFIG_NAME  the config's name
// Without them this spec skips and says why; it never seeds around the server's refusal.
//
// Login budget (see web-real-smoke.sh): 1 API login + 1 UI login = 2 of 10.
//
// Run via scripts/e2e/web-real-smoke.sh, never directly.
import { test, expect, request as apiRequestFactory } from '@playwright/test';
import { ADMIN_USERNAME, ADMIN_PASSWORD, BACKEND_URL, apiLogin, realLogin } from './helpers';

const seededProjectId = process.env.KEYORIX_E2E_REFUSED_DSN_PROJECT_ID;
const seededConfigName = process.env.KEYORIX_E2E_REFUSED_DSN_CONFIG_NAME;

// A clean replacement: no local-file option, and the config has no live leases, so the
// "same host(s)" rule for configs with leases does not apply.
const CLEAN_DSN = 'postgres://user:pass@e2e-refused-dsn-fixed.invalid:5432/db';

async function refusedConfigNames(token: string, projectId: string): Promise<string[]> {
    const ctx = await apiRequestFactory.newContext({ baseURL: BACKEND_URL });
    try {
        const res = await ctx.get(`/api/v1/dynamic-secrets/configs/refused-admin-dsn?project_id=${projectId}`, {
            headers: { Authorization: `Bearer ${token}` },
        });
        if (!res.ok()) throw new Error(`refused-admin-dsn report failed: ${res.status()} ${await res.text()}`);
        const body = await res.json();
        const configs: Array<{ name: string }> = (body.data ?? body).configs ?? [];
        return configs.map((c) => c.name);
    } finally {
        await ctx.dispose();
    }
}

test.describe('dynamic secrets: refused admin DSN banner', () => {
    test.skip(
        !seededProjectId || !seededConfigName,
        'harness does not seed a config with a refused admin DSN yet (KEYORIX_E2E_REFUSED_DSN_PROJECT_ID / _CONFIG_NAME unset); see the SEEDING CONTRACT in this file'
    );

    test('the banner lists the config and clears once its admin DSN is replaced', async ({ page }) => {
        const projectId = seededProjectId as string;
        const configName = seededConfigName as string;
        const token = await apiLogin(ADMIN_USERNAME as string, ADMIN_PASSWORD as string);

        // Precondition from the server itself, so a bad seed fails here and not as a UI mystery.
        expect(await refusedConfigNames(token, projectId)).toContain(configName);

        await realLogin(page, ADMIN_USERNAME as string, ADMIN_PASSWORD as string);
        await page.goto('/secrets/dynamic');
        await page.getByLabel('Project', { exact: true }).selectOption(projectId);

        const banner = page.getByTestId('refused-admin-dsn-banner');
        await expect(banner).toBeVisible();
        await expect(banner).toContainText('a refused admin DSN');
        await expect(banner).toContainText(configName);
        await expect(banner).toContainText('refused:');

        await banner.getByRole('button', { name: `Fix admin DSN for ${configName}` }).click();
        await expect(page.getByText(`Replace admin DSN for ${configName}`)).toBeVisible();
        await page.getByLabel('New admin connection string').fill(CLEAN_DSN);
        await page.getByRole('button', { name: 'Replace admin DSN', exact: true }).click();

        await expect(page.getByRole('status')).toContainText(`Admin DSN replaced for ${configName}.`);
        await expect(page.getByTestId('refused-admin-dsn-banner')).toHaveCount(0);

        expect(await refusedConfigNames(token, projectId)).not.toContain(configName);
    });
});
