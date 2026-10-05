// web/e2e/real/ui-project-dialogs.spec.ts -- WEB-SWEEP-1: the two dialogs on
// the Projects page, against a REAL keyorix-server.
//
// They are singled out from ui-dialogs.spec.ts's inventory because they were
// the only two modal overlays in the app's pages not built on the shared Modal
// (web/src/components/ui/Modal.tsx, a Radix Dialog.Root) -- they were bare
// `<div className="fixed inset-0">` panels, and so had none of what Radix
// supplies: no role="dialog", no accessible name, no focus trap, no
// Escape-to-close, no overlay dismiss. The only way out of New Project was to
// find and mouse-click Cancel (#2776). Separately, a rejected create was
// swallowed in silence: the server returns 409 "A project with that name
// already exists" and the dialog showed nothing at all, so clicking Create
// Project on a duplicate name looked like the product had hung (#2777).
//
// Four properties, each the thing a user actually hits:
//   1. it IS a dialog (role, accessible name) -- the basis for everything below
//      and for anyone driving the app by screen reader;
//   2. Escape and the backdrop both close it -- a dialog with no keyboard exit
//      is a stuck dialog;
//   3. focus goes into the panel and stays there -- otherwise Tab walks into
//      the page behind the overlay, which is live but obscured;
//   4. a server rejection is shown -- the difference between "that name is
//      taken" and "nothing happened".
//
// The happy path is deliberately NOT re-asserted here: access-control.spec.ts
// already creates a project through this exact dialog (/projects?new=1 -> fill
// -> Create Project -> waitForURL) as the setup for its own subject, so it is
// a standing green control for "creating a project still works" and
// duplicating it here would add a login for no new coverage.
//
// Run via scripts/e2e/web-real-smoke.sh, never directly.
import { test, expect, Page } from '@playwright/test';

const ADMIN_USERNAME = process.env.KEYORIX_E2E_ADMIN_USERNAME;
const ADMIN_PASSWORD = process.env.KEYORIX_E2E_ADMIN_PASSWORD;
// The project seed_demo_data creates; its name is what makes a duplicate.
const SEEDED_PROJECT = process.env.KEYORIX_E2E_PROJECT_NAME || 'web-e2e-project';

if (!ADMIN_USERNAME || !ADMIN_PASSWORD) {
    throw new Error(
        'KEYORIX_E2E_ADMIN_USERNAME/KEYORIX_E2E_ADMIN_PASSWORD are not set -- run ' +
            'scripts/e2e/web-real-smoke.sh, which bootstraps a real admin and exports them.'
    );
}

// One login for the file (serial, one shared page) -- the per-IP login budget
// is 10 attempts per 15 minutes and is spent on every attempt, successful or
// not. See scripts/e2e/web-real-smoke.sh's header.
test.describe.configure({ mode: 'serial' });

let shared: Page;

test.beforeAll(async ({ browser }) => {
    shared = await browser.newPage();
    await shared.goto('/login');
    await shared.getByTestId('username-input').fill(ADMIN_USERNAME as string);
    await shared.getByTestId('password-input').fill(ADMIN_PASSWORD as string);
    await shared.getByTestId('login-button').click();
    await shared.waitForURL(/\/dashboard/, { timeout: 20_000 });
});

test.afterAll(async () => {
    await shared?.close();
});

async function openNewProject(page: Page) {
    // ?new=1 is the page's own deep link into the dialog
    // (ProjectsListPage reads it into its initial showCreate state), so this
    // does not depend on the button's label staying the same.
    await page.goto('/projects?new=1', { waitUntil: 'domcontentloaded' });
    await page.waitForLoadState('networkidle', { timeout: 20_000 }).catch(() => undefined);
    await expect(page.getByLabel('Project name')).toBeVisible({ timeout: 10_000 });
}

async function openEditProject(page: Page) {
    await page.goto('/projects', { waitUntil: 'domcontentloaded' });
    await page.waitForLoadState('networkidle', { timeout: 20_000 }).catch(() => undefined);
    await page.getByRole('button', { name: 'Edit project' }).first().click();
    await expect(page.getByLabel('Project name')).toBeVisible({ timeout: 10_000 });
}

test('New Project is a real dialog: it has the role and an accessible name', async () => {
    await openNewProject(shared);

    const dialog = shared.getByRole('dialog');
    await expect(dialog, 'the New Project panel must be exposed as a dialog').toBeVisible();
    await expect(dialog).toHaveAccessibleName(/new project/i);
});

test('New Project closes on Escape', async () => {
    await openNewProject(shared);
    await shared.keyboard.press('Escape');
    await expect(
        shared.getByLabel('Project name'),
        'Escape must close New Project -- with no keyboard exit it is a stuck dialog'
    ).toBeHidden({ timeout: 5_000 });
});

test('New Project closes on a backdrop click', async () => {
    await openNewProject(shared);
    // Top-left corner: on the overlay, far from the centred panel.
    await shared.mouse.click(8, 8);
    await expect(shared.getByLabel('Project name'), 'clicking the backdrop must dismiss New Project').toBeHidden({
        timeout: 5_000,
    });
});

test('New Project takes focus into the panel and does not let Tab escape behind it', async () => {
    await openNewProject(shared);

    const focusedIsInside = () =>
        shared.evaluate(() => {
            const dialog = document.querySelector('[role="dialog"]');
            const active = document.activeElement;
            return !!dialog && !!active && dialog.contains(active);
        });

    expect(await focusedIsInside(), 'focus must land inside the dialog on open').toBe(true);

    // Enough tabs to walk past every focusable control in the panel (two text
    // inputs, Cancel, Create Project, the close button) and back around. An
    // untrapped overlay lets focus out into the obscured page behind it --
    // which is how this was found: activeElement ended up on the page's own
    // "Projects" nav link, outside the overlay entirely.
    for (let i = 0; i < 10; i++) {
        await shared.keyboard.press('Tab');
        expect(await focusedIsInside(), `focus escaped the dialog after ${i + 1} Tab(s)`).toBe(true);
    }
});

test("New Project shows the server's rejection rather than appearing to do nothing", async () => {
    await openNewProject(shared);

    // The seeded project's name is already taken, so the server answers 409
    // with a message meant to be read by a human.
    await shared.getByLabel('Project name').fill(SEEDED_PROJECT);

    const rejected = shared.waitForResponse(
        (r) => r.url().includes('/api/v1/projects') && r.request().method() === 'POST' && r.status() === 409,
        { timeout: 15_000 }
    );
    await shared.getByRole('button', { name: 'Create Project' }).click();
    await rejected;

    // The dialog must stay open (nothing was created, so there is nothing to
    // navigate to) AND say why.
    await expect(shared.getByLabel('Project name'), 'a rejected create must not close the dialog').toBeVisible();
    await expect(
        shared.getByRole('dialog'),
        "the dialog must surface the server's own reason, not swallow it"
    ).toContainText(/already exists/i);
});

test('Edit project is a real dialog and closes on Escape', async () => {
    await openEditProject(shared);

    const dialog = shared.getByRole('dialog');
    await expect(dialog, 'the Edit project panel must be exposed as a dialog').toBeVisible();
    await expect(dialog).toHaveAccessibleName(/edit project/i);

    await shared.keyboard.press('Escape');
    await expect(shared.getByLabel('Project name'), 'Escape must close Edit project too').toBeHidden({
        timeout: 5_000,
    });
});
