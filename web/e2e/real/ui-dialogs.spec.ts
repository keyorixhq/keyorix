// web/e2e/real/ui-dialogs.spec.ts -- WEB-SWEEP-1: opens every create/invite
// dialog in the app against a REAL keyorix-server and checks the three things
// that go wrong in a demo, in order of how badly:
//
//   1. it opens at all (the control exists, is enabled, and produces a dialog);
//   2. Escape closes it (a dialog with no keyboard exit is a stuck dialog -- the
//      failure DEMO-1/2 hit by clicking);
//   3. reopening it starts clean (text typed into the first open must not still
//      be there on the second -- the state-leak failure a user sees as "it
//      remembered what I abandoned").
//
// DIALOGS is a hand-maintained list rather than "click every button that looks
// like an opener". A generic sweep was tried first and is the wrong tool here:
// it cannot tell a control that legitimately isn't a dialog (Export CSV, a tab)
// from one that is broken, so every such control lands in the result set as an
// indistinguishable maybe. Naming each dialog makes the list itself the thing a
// reviewer can check against the pages, and makes a dialog that disappears from
// a page fail loudly instead of silently dropping out of coverage.
//
// Each entry names the page, the accessible name of the control that opens the
// dialog, and the accessible name of the dialog's own heading.
//
// Run via scripts/e2e/web-real-smoke.sh, never directly.
import { test, expect, Page } from '@playwright/test';

const ADMIN_USERNAME = process.env.KEYORIX_E2E_ADMIN_USERNAME;
const ADMIN_PASSWORD = process.env.KEYORIX_E2E_ADMIN_PASSWORD;

if (!ADMIN_USERNAME || !ADMIN_PASSWORD) {
    throw new Error(
        'KEYORIX_E2E_ADMIN_USERNAME/KEYORIX_E2E_ADMIN_PASSWORD are not set -- run ' +
            'scripts/e2e/web-real-smoke.sh, which bootstraps a real admin and exports them.'
    );
}

interface DialogCase {
    page: string;
    opener: string;
    /** Substring of the dialog's own visible title. */
    title: string;
}

const DIALOGS: DialogCase[] = [
    { page: '/secrets', opener: 'New Secret', title: 'Create New Secret' },
    { page: '/secrets/dynamic', opener: 'New config', title: 'New dynamic-secret config' },
    { page: '/secrets/rotation', opener: 'New Policy', title: 'New Rotation Policy' },
    { page: '/projects/2/secrets', opener: 'New Secret', title: 'New Secret' },
    { page: '/projects/2/members', opener: 'Invite by email', title: 'Invite to' },
    { page: '/admin/users', opener: 'New User', title: 'Create User' },
    { page: '/admin/users', opener: 'Invite User', title: 'Invite User' },
    { page: '/admin/roles', opener: 'New Role', title: 'New Role' },
    { page: '/admin/groups', opener: 'New Group', title: 'New Group' },
    { page: '/admin/notification-channels', opener: 'New Channel', title: 'New Channel' },
];

const DIRTY = 'websweep1-abandoned-value';

async function login(page: Page) {
    await page.goto('/login');
    await page.getByTestId('username-input').fill(ADMIN_USERNAME as string);
    await page.getByTestId('password-input').fill(ADMIN_PASSWORD as string);
    await page.getByTestId('login-button').click();
    await page.waitForURL(/\/dashboard/, { timeout: 20_000 });
}

// dialogValues reads back every text-ish control inside the open dialog.
// Radix generates element ids per mount, so the values are compared as a SET of
// values, never keyed by id -- a reopened dialog legitimately has different ids
// for the same fields, and keying on them would make this assert nothing.
async function dialogValues(page: Page): Promise<string[]> {
    const fields = page
        .locator('[role="dialog"]')
        .locator('input:not([type="checkbox"]):not([type="radio"]), textarea');
    const n = await fields.count();
    const out: string[] = [];
    for (let i = 0; i < n; i++)
        out.push(
            await fields
                .nth(i)
                .inputValue()
                .catch(() => '')
        );
    return out;
}

async function openDialog(page: Page, c: DialogCase) {
    await page.goto(c.page, { waitUntil: 'domcontentloaded' });
    await page.waitForLoadState('networkidle', { timeout: 20_000 }).catch(() => undefined);
    const opener = page.getByRole('button', { name: c.opener, exact: true }).first();
    await expect(opener, `${c.page}: the "${c.opener}" control must exist`).toBeVisible({ timeout: 10_000 });
    await opener.click();
    const dialog = page.locator('[role="dialog"]').first();
    await expect(dialog, `${c.page}: "${c.opener}" must open a dialog`).toBeVisible({ timeout: 10_000 });
    await expect(dialog, `${c.page}: the dialog opened by "${c.opener}" must be the expected one`).toContainText(
        c.title
    );
    return dialog;
}

// One test per dialog (so one broken dialog names itself instead of hiding the
// nine behind it in a single loop's first failure), but ONE login for the whole
// file, shared through a single long-lived page in beforeAll.
//
// The shared page is not a convenience: server/http/handlers/auth.go's
// reserveLoginAttempt spends a per-IP slot on every login attempt, 10 per 15
// minutes, so a login-per-test file at this size would 429 partway through and
// report an exhausted rate-limit budget as broken dialogs. Serial mode is
// therefore mandatory, not a preference -- the tests share one page object.
test.describe.configure({ mode: 'serial' });

let shared: Page;

test.beforeAll(async ({ browser }) => {
    shared = await browser.newPage();
    await login(shared);
});

test.afterAll(async () => {
    await shared?.close();
});

for (const c of DIALOGS) {
    test(`${c.page} -> "${c.opener}" opens, closes on Escape, and reopens clean`, async () => {
        const dialog = await openDialog(shared, c);

        // Dirty the first text field, then close with the keyboard only.
        const firstText = dialog.locator('input[type="text"], input:not([type]), textarea').first();
        if ((await firstText.count()) > 0) await firstText.fill(DIRTY);

        await shared.keyboard.press('Escape');
        await expect(dialog, `"${c.opener}" must close on Escape`).toBeHidden({ timeout: 5_000 });

        const reopened = await openDialog(shared, c);
        const values = await dialogValues(shared);
        expect(values, `"${c.opener}" must not carry the abandoned value into a reopen`).not.toContain(DIRTY);
        // And it must still be usable, not a husk: at least one field present.
        expect(await reopened.locator('input, textarea, select').count()).toBeGreaterThan(0);
    });
}
