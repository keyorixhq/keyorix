// web/e2e/real/demo-copy-guard.spec.ts -- DEMO-WALK-3: what a customer must never see on screen.
//
// The demo walks (DEMO-WALK-1..3) kept finding the same class of defect that no
// functional spec looks for, because the page "works": developer text in
// customer copy ("(ADR-035)", "NEEDS ANDREI"), unpluralised relative times
// ("1 minutes ago"), raw client errors ("Request failed with status code 403"),
// and template leaks ("undefined", "NaN", "[object Object]"). This spec walks the
// screens a presenter shows, as the bootstrapped admin, and asserts none of those
// strings is rendered in <main>. It also pins the audit CSV export's shape
// (UTC ISO-8601 timestamps, the documented header), which the demo script shows.
//
// Deliberately NOT asserted here (known open findings, tracked in
// DEMO-WALK-3's report): raw event names on the dashboard and audit page, and the
// share dialog's refusal text. Those belong to the PRs that fix them, which
// should extend FORBIDDEN when they land.
//
// Run via scripts/e2e/web-real-smoke.sh (it boots the backend and exports the
// env vars read below), never directly.
import { test, expect, Page } from '@playwright/test';
import fs from 'node:fs';

const ADMIN_USERNAME = process.env.KEYORIX_E2E_ADMIN_USERNAME;
const ADMIN_PASSWORD = process.env.KEYORIX_E2E_ADMIN_PASSWORD;

if (!ADMIN_USERNAME || !ADMIN_PASSWORD) {
    throw new Error(
        'KEYORIX_E2E_ADMIN_USERNAME/KEYORIX_E2E_ADMIN_PASSWORD are not set -- run ' +
            'scripts/e2e/web-real-smoke.sh, which bootstraps a real admin and sets them, ' +
            'rather than invoking this spec file directly.'
    );
}

// The screens the demo script (docs/demo/GOLDEN-PATH.md) and the sales walk-through show.
const DEMO_SCREENS = [
    '/dashboard',
    '/secrets',
    '/secrets/dynamic',
    '/secrets/rotation',
    '/secrets/expiry',
    '/secrets/health',
    '/secrets/usage',
    '/projects',
    '/projects/2/secrets',
    '/projects/2/members',
    '/projects/2/activity',
    '/projects/2/settings',
    '/audit',
    '/sharing',
    '/profile',
    '/admin/users',
    '/admin/groups',
    '/admin/roles',
    '/admin/machine-identities',
    '/compliance',
    '/settings/auth',
    '/settings/encryption',
    '/settings/license',
    '/settings/health',
];

// Each entry: a pattern that must not appear in rendered copy, and why.
const FORBIDDEN: { re: RegExp; why: string }[] = [
    { re: /NEEDS ANDREI/i, why: 'internal review note' },
    { re: /\bADR-\d+\b/, why: 'internal design-record number in customer copy' },
    { re: /\bTODO\b|\bFIXME\b/, why: 'unfinished-work marker' },
    { re: /\b1 (minutes|hours|days) ago\b/, why: 'unpluralised relative time' },
    { re: /\bundefined\b|\bNaN\b|\[object Object\]/, why: 'template/data leak' },
    { re: /Request failed with status code \d+/, why: 'raw axios error text' },
];

async function login(page: Page) {
    await page.goto('/login');
    await page.getByTestId('username-input').fill(ADMIN_USERNAME as string);
    await page.getByTestId('password-input').fill(ADMIN_PASSWORD as string);
    await page.getByTestId('login-button').click();
    await page.waitForURL(/\/dashboard/, { timeout: 20_000 });
}

test('no developer text or template leaks on any demo screen (admin)', async ({ page }) => {
    // ~24 routes at 1-2 s each against a real backend; a timeout detects a hang,
    // it does not enforce speed.
    test.setTimeout(180_000);
    await login(page);

    const hits: string[] = [];
    for (const route of DEMO_SCREENS) {
        await page.goto(route, { waitUntil: 'domcontentloaded' });
        await page.waitForLoadState('networkidle', { timeout: 20_000 }).catch(() => undefined);
        await page.waitForTimeout(500);
        const text = (
            (await page
                .locator('main')
                .innerText()
                .catch(() => '')) || ''
        ).replace(/\s+/g, ' ');
        expect(text.length, `${route}: <main> rendered nothing, so the scan below would be vacuous`).toBeGreaterThan(
            25
        );
        for (const { re, why } of FORBIDDEN) {
            const m = text.match(re);
            if (m) hits.push(`${route}: "${m[0]}" (${why})`);
        }
    }
    expect(hits, 'one entry per forbidden string rendered on a demo screen').toEqual([]);
});

test('audit CSV export: documented header, UTC ISO-8601 timestamps, at least the login event', async ({ page }) => {
    await login(page);
    await page.goto('/audit');
    await page.waitForLoadState('networkidle', { timeout: 20_000 }).catch(() => undefined);

    const [download] = await Promise.all([
        page.waitForEvent('download', { timeout: 15_000 }),
        page.getByRole('button', { name: /Export CSV/ }).click(),
    ]);
    expect(download.suggestedFilename()).toMatch(/^keyorix-audit-log-\d{4}-\d{2}-\d{2}\.csv$/);

    const path = await download.path();
    expect(path, 'the download was saved').toBeTruthy();
    const lines = fs
        .readFileSync(path as string, 'utf8')
        .trim()
        .split('\n');
    expect(lines[0]).toBe('Timestamp,Event,Actor,Actor Type,Description');
    expect(lines.length, 'header plus at least the bootstrap/login events').toBeGreaterThan(1);
    for (const line of lines.slice(1, 6)) {
        // UTC, with an explicit Z: the audit page itself shows browser-local time with no zone label,
        // so the export is the one place an auditor can read an unambiguous time.
        expect(line, 'every exported row starts with a UTC ISO-8601 timestamp').toMatch(
            /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?Z,/
        );
    }
});
