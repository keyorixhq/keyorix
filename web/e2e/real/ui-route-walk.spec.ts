// web/e2e/real/ui-route-walk.spec.ts -- WEB-SWEEP-1: walks EVERY route
// web/src/App.tsx declares against a REAL keyorix-server, twice: once as the
// bootstrapped admin and once as a least-privilege account (system_viewer
// globally + project_viewer on the seeded project, created by
// scripts/e2e/web-real-smoke.sh's seed_demo_data).
//
// Why a second persona, and not just the admin with a flag flipped: almost
// every page in this app issues at least one API call that a project-scoped
// account is not permitted to make (server/http/router.go gates
// GET /api/v1/projects on RequirePermission, i.e. global scope -- a
// project_viewer gets 403 on it from every single page, because the layout's
// project switcher asks for it). An admin-only walk cannot see any of that, so
// it cannot tell a page that renders a clear "you don't have access" state from
// one that renders a blank panel or spins forever. Those are the two failure
// shapes a demo audience actually hits, and they are what this file asserts.
//
// Deliberately NOT asserted: an empty browser console. A legitimate 403 on an
// API call the page is designed to tolerate produces a browser-level "Failed to
// load resource: 403" console line that no application code can suppress, so a
// zero-console-errors rule would be red for the least-privilege persona on
// literally every route while nothing is wrong. What IS asserted is zero
// uncaught JS exceptions (page.on('pageerror')) -- that is the signal a
// console-error count was standing in for, and unlike the count it is not
// satisfiable by a legitimate HTTP status.
//
// Run via scripts/e2e/web-real-smoke.sh (it boots the backend and exports the
// env vars read below), never directly.
import { test, expect, Page } from '@playwright/test';

const ADMIN_USERNAME = process.env.KEYORIX_E2E_ADMIN_USERNAME;
const ADMIN_PASSWORD = process.env.KEYORIX_E2E_ADMIN_PASSWORD;
const LOWPRIV_USERNAME = process.env.KEYORIX_E2E_LOWPRIV_USERNAME;
const LOWPRIV_PASSWORD = process.env.KEYORIX_E2E_LOWPRIV_PASSWORD;

if (!ADMIN_USERNAME || !ADMIN_PASSWORD || !LOWPRIV_USERNAME || !LOWPRIV_PASSWORD) {
    throw new Error(
        'KEYORIX_E2E_{ADMIN,LOWPRIV}_{USERNAME,PASSWORD} are not all set -- run ' +
            'scripts/e2e/web-real-smoke.sh, which bootstraps both accounts and exports them.'
    );
}

// Every path App.tsx declares, in declaration order, plus the two retired
// service-account URLs it redirects (docs/adr-113) and one unknown URL for the
// catch-all. Parameterised routes use the ids seed_demo_data creates: project 2
// (project 1 is the install's own default project) and user 2 (user 1 is the
// bootstrapped admin).
//
// ADMIN_ONLY lists the paths App.tsx wraps in <AdminRoute>; for those the
// least-privilege expectation is a redirect away, not a rendered page.
const ADMIN_ONLY = new Set([
    '/admin',
    '/admin/users',
    '/admin/users/2',
    '/admin/billing',
    '/admin/roles',
    '/admin/groups',
    '/admin/machine-identities',
    '/admin/notification-channels',
    '/admin/service-accounts',
    '/admin/api-tokens',
    '/settings/auth',
    '/settings/encryption',
    '/settings/license',
    '/settings/health',
]);

// REDIRECTS are the paths that are expected NOT to settle on themselves.
const REDIRECTS: Record<string, string> = {
    '/projects/2': '/projects/2/secrets',
    '/admin/service-accounts': '/admin/machine-identities',
    '/admin/api-tokens': '/admin/machine-identities',
};

const ROUTES: string[] = [
    '/dashboard',
    '/secrets',
    '/secrets/dynamic',
    '/secrets/rotation',
    '/secrets/expiry',
    '/secrets/health',
    '/secrets/usage',
    '/projects',
    '/projects/2',
    '/projects/2/secrets',
    '/projects/2/members',
    '/projects/2/activity',
    '/projects/2/settings',
    '/audit',
    '/sharing',
    '/profile',
    '/admin',
    '/admin/users',
    '/admin/users/2',
    '/admin/billing',
    '/admin/roles',
    '/admin/groups',
    '/admin/machine-identities',
    '/admin/notification-channels',
    '/admin/service-accounts',
    '/admin/api-tokens',
    '/settings/appearance',
    '/settings/auth',
    '/settings/encryption',
    '/settings/license',
    '/settings/health',
    '/compliance',
    '/integrations/connect',
    '/integrations/sdks',
    '/roadmap',
    '/no-such-route-web-sweep-1',
];

async function login(page: Page, username: string, password: string) {
    await page.goto('/login');
    await page.getByTestId('username-input').fill(username);
    await page.getByTestId('password-input').fill(password);
    await page.getByTestId('login-button').click();
    await page.waitForURL(/\/dashboard/, { timeout: 20_000 });
}

type RouteOutcome = {
    route: string;
    settledAt: string;
    mainText: string;
    jsErrors: string[];
    spinners: number;
};

// visitAll walks every route in ONE browser session, the way a user does.
// server/http/handlers/auth.go's reserveLoginAttempt spends a shared per-IP
// budget on EVERY login attempt (10 per 15 minutes), so a login-per-route walk
// would 429 partway through and report it as broken pages -- see
// web/e2e/real/pages.spec.ts's header for the run that proved it.
async function visitAll(page: Page): Promise<RouteOutcome[]> {
    const jsErrors: string[] = [];
    page.on('pageerror', (err) => jsErrors.push(err.message.slice(0, 300)));

    const outcomes: RouteOutcome[] = [];
    for (const route of ROUTES) {
        jsErrors.length = 0;
        await page.goto(route, { waitUntil: 'domcontentloaded' });
        await page.waitForLoadState('networkidle', { timeout: 20_000 }).catch(() => undefined);
        // A short settle after networkidle: React Query renders its result one
        // tick after the request resolves, and a spinner counted at the instant
        // the network goes idle is still legitimately on screen.
        await page.waitForTimeout(500);

        outcomes.push({
            route,
            settledAt: new URL(page.url()).pathname,
            mainText: (
                (await page
                    .locator('main')
                    .innerText()
                    .catch(() => '')) || ''
            )
                .replace(/\s+/g, ' ')
                .trim(),
            jsErrors: [...jsErrors],
            spinners: await page
                .locator('main [class*="animate-spin"], main [role="status"]')
                .count()
                .catch(() => 0),
        });
    }
    return outcomes;
}

// MIN_MAIN_TEXT: the shortest legitimate <main> in the app is the 404 page
// ("404 / Page not found / Go to Dashboard", ~35 characters). Anything under
// this is the blank-panel failure this file exists to catch.
const MIN_MAIN_TEXT = 25;

function check(outcomes: RouteOutcome[], persona: 'admin' | 'lowpriv'): string[] {
    const failures: string[] = [];
    for (const o of outcomes) {
        if (o.jsErrors.length > 0) {
            failures.push(`${persona} ${o.route}: uncaught JS error(s): ${JSON.stringify(o.jsErrors)}`);
        }
        if (o.settledAt === '/login') {
            failures.push(`${persona} ${o.route}: bounced to /login mid-session`);
            continue;
        }
        if (o.spinners > 0) {
            failures.push(`${persona} ${o.route}: ${o.spinners} spinner(s) still rendered after the page settled`);
        }
        if (o.mainText.length < MIN_MAIN_TEXT) {
            failures.push(
                `${persona} ${o.route}: <main> has only ${o.mainText.length} chars of text (${JSON.stringify(o.mainText)}) -- blank page`
            );
        }

        const expectedRedirect = REDIRECTS[o.route];
        if (persona === 'admin') {
            const expected = expectedRedirect ?? o.route;
            if (o.settledAt !== expected) {
                failures.push(`${persona} ${o.route}: settled on ${o.settledAt}, expected ${expected}`);
            }
        } else if (ADMIN_ONLY.has(o.route)) {
            // An admin-only route must take a non-admin somewhere else. Where
            // is App.tsx's business (AdminRoute redirects to /dashboard today);
            // what this asserts is that it does not render the admin page.
            if (o.settledAt === o.route) {
                failures.push(`${persona} ${o.route}: rendered an <AdminRoute> page for a non-admin`);
            }
        } else if (o.settledAt !== (expectedRedirect ?? o.route)) {
            failures.push(`${persona} ${o.route}: settled on ${o.settledAt}, expected ${expectedRedirect ?? o.route}`);
        }
    }
    return failures;
}

// Each walk visits ~36 routes at roughly 1.5-2s apiece against a real server,
// so ~60-75s -- well past playwright.config.real.ts's 30s default. Raised per
// test rather than in the shared config so no OTHER spec silently gets a looser
// timeout along with it: a timeout that only this file needs belongs to this
// file. Generous, not tight -- a timeout detects a hang, it does not enforce
// speed, and the per-route cost is what it is against a real backend.
const WALK_TIMEOUT_MS = 240_000;

test('every route renders for an admin: no JS error, no stuck spinner, no blank page', async ({ page }) => {
    test.setTimeout(WALK_TIMEOUT_MS);
    await login(page, ADMIN_USERNAME as string, ADMIN_PASSWORD as string);
    const outcomes = await visitAll(page);
    expect(outcomes, 'every declared route was visited').toHaveLength(ROUTES.length);
    expect(check(outcomes, 'admin'), 'one entry per route that failed its own check').toEqual([]);

    // The catch-all must say so, not render an empty shell: this app's layout
    // route owns the splat, so a regression here is a blank Layout rather than
    // a 404 (see App.tsx's own comment on why the catch-all lives where it does).
    const notFound = outcomes.find((o) => o.route === '/no-such-route-web-sweep-1');
    expect(notFound?.mainText).toContain('Page not found');
});

test('every route is survivable for a least-privilege user: a refusal, never a blank page', async ({ page }) => {
    test.setTimeout(WALK_TIMEOUT_MS);
    await login(page, LOWPRIV_USERNAME as string, LOWPRIV_PASSWORD as string);
    const outcomes = await visitAll(page);
    expect(outcomes, 'every declared route was visited').toHaveLength(ROUTES.length);
    expect(check(outcomes, 'lowpriv'), 'one entry per route that failed its own check').toEqual([]);

    // Spot-check the two pages whose data call this persona is refused outright:
    // each must name the failure rather than render an empty panel.
    const sharing = outcomes.find((o) => o.route === '/sharing');
    expect(sharing?.mainText, '/sharing must explain the refusal').toMatch(/failed to load|error|permission|access/i);
    const rotation = outcomes.find((o) => o.route === '/secrets/rotation');
    expect(rotation?.mainText, '/secrets/rotation must explain the refusal').toMatch(
        /failed to load|error|permission|access/i
    );

    // The nav must not offer this persona a destination it will be bounced off
    // (#2774: Billing was rendered for everyone and silently redirected to
    // /dashboard on click). Derived from what is actually RENDERED rather than
    // from a list of links to check, so a newly added admin-only nav entry is
    // covered the moment it appears -- and cross-referenced against the walk's
    // own settledAt for each href, so it costs no extra navigation.
    //
    // Every collapsed group is expanded first. Without that, a child leaf is
    // simply absent from the DOM and would pass by not being there, which is
    // the vacuous-guard shape: the check would be green precisely because it
    // found nothing to check.
    await page.goto('/dashboard');
    await page.waitForLoadState('networkidle', { timeout: 20_000 }).catch(() => undefined);
    const groupHeaders = page.locator('nav > div > button');
    for (let i = 0; i < (await groupHeaders.count()); i++) {
        const chevron = groupHeaders.nth(i).locator('svg.transition-transform');
        const expanded = ((await chevron.getAttribute('class')) || '').includes('rotate-180');
        if (!expanded) await groupHeaders.nth(i).click();
    }
    const navHrefs = await page.locator('nav a[href^="/"]').evaluateAll((els) =>
        Array.from(new Set(els.map((el) => (el as HTMLAnchorElement).getAttribute('href') || '')))
    );
    expect(navHrefs.length, 'the sidebar rendered some links to check').toBeGreaterThan(5);

    const unreachable: string[] = [];
    for (const href of navHrefs) {
        const outcome = outcomes.find((o) => o.route === href);
        // A nav href with no entry in ROUTES means this spec's ROUTES list has
        // drifted from NAV; say so rather than skipping it silently.
        if (!outcome) {
            unreachable.push(`${href}: in the sidebar but not in this spec's ROUTES list`);
        } else if (outcome.settledAt !== href) {
            unreachable.push(`${href}: the sidebar offers it, but it redirects to ${outcome.settledAt}`);
        }
    }
    expect(unreachable, 'every nav link the sidebar shows this persona must actually lead there').toEqual([]);
});
