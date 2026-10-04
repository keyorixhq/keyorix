// web/e2e/real/mfa-login.spec.ts — SESSION-WEB-E2E item 1: exercises TOTP MFA
// through the real Profile → Security UI (no mocked routes, same real-backend
// shape as pages.spec.ts) and a subsequent login.
//
// Both known product bugs this file originally tracked are now fixed:
// - #2441 (MFA enrollment always 400ing — EnrollModal never collected/sent the
//   account password ActivateMFA requires): EnrollModal now has a password
//   field, and mfaApi.activate sends it alongside the code.
// - #2442 (logging in with MFA enabled never prompted for a code — authStore
//   ignored mfa_required): login() now stores a pending mfaChallenge instead
//   of landing a bogus "authenticated" session, LoginPage renders a code-entry
//   step, and verifyMfa() completes it against the real VerifyMFA endpoint.
// Both tests below assert the real flow completes end to end, instead of
// test.fail()ing on either known bug.
//
// Note on "bootstrap admin via the UI" (SESSION-WEB-E2E item 1's own wording):
// there is no such UI flow in this app. POST /system/init (internal/core's
// bootstrap) has no corresponding page -- grepped web/src for any
// system-init/setup-wizard component and found none; web/src/pages/auth/
// SetupPage.tsx is a DIFFERENT flow (ADR-028 credential-delivery links for
// already-created users, not first-run bootstrap). The admin account below is
// bootstrapped the same way web-real-smoke.sh already does it (POST
// /system/init via curl). This is a real, documented product gap (no UI
// onboarding wizard), not a shortcut taken by this test -- flagged in
// SESSION-WEB-E2E's report, not silently worked around.
//
// TOTP codes below are computed with a minimal local RFC 6238 implementation
// (totpCode()) rather than pulling in a new npm dependency for one helper --
// internal/core/mfa.go's totpPeriod/Digits/Algorithm constants (30s, 6
// digits, SHA1) are mirrored exactly, not guessed, and cross-checked live
// against the real github.com/pquerna/otp output for the same secret/time
// before this file was written.
//
// Both tests create their own dedicated throwaway user (createDedicatedUser)
// for the actual MFA enroll/login attempt -- MFA is a one-way, session-
// breaking mutation, so enabling it on the shared ADMIN_USERNAME would make
// every other spec file's (and this suite's own repeat-run) admin login
// order-dependent on whether this file ran first. ADMIN_USERNAME is used
// only for its unrelated authority to create another account via
// POST /api/v1/users, exactly like web-real-smoke.sh already uses it to
// create a project -- the shared admin's own MFA/session/role/password state
// is never touched. Because each test operates on a throwaway user nobody
// else depends on, neither test needs a disable-MFA cleanup step.
import { test, expect, Page, request as apiRequestFactory } from '@playwright/test';
import { createHmac } from 'node:crypto';

const ADMIN_USERNAME = process.env.KEYORIX_E2E_ADMIN_USERNAME;
const ADMIN_PASSWORD = process.env.KEYORIX_E2E_ADMIN_PASSWORD;
const BACKEND_URL = process.env.KEYORIX_E2E_BACKEND_URL;

if (!ADMIN_USERNAME || !ADMIN_PASSWORD || !BACKEND_URL) {
    throw new Error(
        'KEYORIX_E2E_ADMIN_USERNAME/KEYORIX_E2E_ADMIN_PASSWORD/KEYORIX_E2E_BACKEND_URL are not set -- ' +
            'run scripts/e2e/web-real-smoke.sh, which bootstraps a real admin and sets them, rather than ' +
            'invoking this spec file directly.'
    );
}

// base32Decode implements RFC 4648 base32 (no padding tolerance needed --
// pquerna/otp's GenerateOpts never pads its generated secrets).
function base32Decode(input: string): Buffer {
    const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
    const clean = input.toUpperCase().replace(/=+$/, '');
    let bits = '';
    for (const char of clean) {
        const idx = alphabet.indexOf(char);
        if (idx === -1) throw new Error(`invalid base32 character: ${char}`);
        bits += idx.toString(2).padStart(5, '0');
    }
    const bytes: number[] = [];
    for (let i = 0; i + 8 <= bits.length; i += 8) {
        bytes.push(parseInt(bits.slice(i, i + 8), 2));
    }
    return Buffer.from(bytes);
}

// totpCode implements RFC 6238 (HMAC-SHA1, 30s step, 6 digits) -- matches
// internal/core/mfa.go's totpPeriod/otp.DigitsSix/otp.AlgorithmSHA1 exactly.
function totpCode(base32Secret: string, atSeconds = Date.now() / 1000): string {
    const counter = Math.floor(atSeconds / 30);
    const counterBuf = Buffer.alloc(8);
    counterBuf.writeBigUInt64BE(BigInt(counter));
    const key = base32Decode(base32Secret);
    const hmac = createHmac('sha1', key).update(counterBuf).digest();
    const offset = hmac[hmac.length - 1] & 0x0f;
    const binary =
        ((hmac[offset] & 0x7f) << 24) |
        ((hmac[offset + 1] & 0xff) << 16) |
        ((hmac[offset + 2] & 0xff) << 8) |
        (hmac[offset + 3] & 0xff);
    return (binary % 1_000_000).toString().padStart(6, '0');
}

// waitForFreshTotpCode polls (real time, not the test's local clock arithmetic)
// until the current 30s TOTP step is strictly past lastUsedStep, then returns
// the CURRENT step's code (delta 0 -- the one validateTOTPStep is guaranteed
// to accept no matter how fast or slow the check that follows runs). Needed
// because this app's anti-replay (MarkTOTPStepUsed, internal/core's doc
// comment: "a code already accepted at this or a later step is a replay") is
// ONE shared counter per account across every TOTP check site -- enroll's
// activate and login's verify both draw from it. This SPA's client-side
// routing makes two of those checks only a few hundred milliseconds apart in
// practice (confirmed live: two "next step" guesses a test run apart computed
// to the identical step and code), so predicting a future step ahead of time
// is not reliable; waiting for a real, fresh step to actually arrive is.
async function waitForFreshTotpCode(
    page: Page,
    secret: string,
    lastUsedStep: number
): Promise<{ code: string; step: number }> {
    const periodSeconds = 30;
    for (;;) {
        const now = Date.now() / 1000;
        const step = Math.floor(now / periodSeconds);
        if (step > lastUsedStep) {
            return { code: totpCode(secret, now), step };
        }
        await page.waitForTimeout(1000);
    }
}

async function submitLogin(page: Page, username: string, password: string) {
    await page.getByTestId('username-input').fill(username);
    await page.getByTestId('password-input').fill(password);
    await page.getByTestId('login-button').click();
}

async function realLogin(page: Page, username: string, password: string) {
    await page.goto('/login');
    await submitLogin(page, username, password);
    await page.waitForURL('/dashboard', { timeout: 15_000 });
}

// apiLogin returns a bearer token for `username`, via a context that is
// discarded immediately after -- POST /auth/login's response sets both a
// session cookie and a CSRF cookie (the normal double-submit pattern for a
// real browser session), and Playwright's request contexts retain and
// resend cookies set by earlier responses through that same context.
// Reusing the login context for a later call would carry that session
// cookie along, and server/middleware/csrf.go's RequireCSRF demands a
// matching X-CSRF-Token header the moment ANY session cookie is present on a
// state-changing request -- even one that also carries a perfectly valid
// Bearer token. Confirmed live: a reused context 403'd with "Missing CSRF
// token header" on the follow-up call. A pure-Bearer caller with no session
// cookie at all is exempt by the same code path (see that file's own
// comment) -- so the fix is a brand-new, cookie-free context per Bearer call,
// not adding CSRF-header plumbing this test setup has no reason to need.
async function apiLogin(username: string, password: string): Promise<string> {
    const loginCtx = await apiRequestFactory.newContext({ baseURL: BACKEND_URL });
    try {
        const loginRes = await loginCtx.post('/auth/login', { data: { username, password } });
        if (!loginRes.ok()) throw new Error(`setup login failed: ${loginRes.status()} ${await loginRes.text()}`);
        return (await loginRes.json()).data.token as string;
    } finally {
        await loginCtx.dispose();
    }
}

// createDedicatedUser provisions a brand-new, throwaway user via the admin
// API (POST /api/v1/users, admin-set-password path) rather than ever
// enabling MFA or attempting a second login on the shared bootstrap admin
// itself. Every test below enables/attempts MFA on ITS OWN dedicated user,
// never on ADMIN_USERNAME -- the admin is used here only to exercise its
// (unrelated) authority to create another account, exactly like
// web-real-smoke.sh already uses it to create a project. This keeps the
// shared admin's own MFA/session/role/password state untouched across the
// whole real-backend suite, so other spec files (and repeat runs within this
// one) never depend on run order. Password is deliberately NOT derived from
// the username/email/display name -- internal/core/rules.DefaultPasswordPolicy
// rejects a password containing any of those substrings.
async function createDedicatedUser(usernamePrefix: string): Promise<{ username: string; password: string }> {
    const token = await apiLogin(ADMIN_USERNAME as string, ADMIN_PASSWORD as string);
    // A separate, cookie-free context for the actual mutation -- see apiLogin's
    // comment for why this can't reuse the login context.
    const api = await apiRequestFactory.newContext({ baseURL: BACKEND_URL });
    try {
        const stamp = Date.now();
        const username = `${usernamePrefix}${stamp}`;
        // Deliberately NOT derived from `stamp` (or any other username/email/
        // display-name substring) -- internal/core/rules.password_policy.go's
        // containsPersonalInfo rejects a password containing any 3+-char word
        // of the display name, and "MFA Test User <stamp>" has `stamp` as one
        // of those words. A shared stamp here silently 400s the create-user
        // call with a generic "ValidationError". Confirmed live.
        const password = `Quartz-Falcon-${Math.random().toString(36).slice(2, 10)}-Garnet!`;
        const createRes = await api.post('/api/v1/users', {
            headers: { Authorization: `Bearer ${token}` },
            data: {
                username,
                email: `${username}@example.invalid`,
                display_name: `MFA Test User ${stamp}`,
                password,
            },
        });
        if (!createRes.ok())
            throw new Error(`setup create-user failed: ${createRes.status()} ${await createRes.text()}`);

        return { username, password };
    } finally {
        await api.dispose();
    }
}

test('MFA enrollment via Profile → Security completes (fixes known bug #2441)', async ({ page }) => {
    // https://github.com/keyorixhq/keyorix/issues/2441 -- server/http/handlers/mfa.go's
    // ActivateMFA requires BOTH the TOTP code and the account password
    // (internal/core/mfa.go's requireReauth falls through to the
    // password-compare branch, since MFAEnabled is still false during
    // enrollment). web/src/features/account/MfaSection.tsx's EnrollModal now
    // collects both -- mfaApi.activate(code, password) sends {code, password}
    // -- so the backend's real contract (confirmed live in the issue's own
    // repro: the exact same request shape with both fields succeeds) is now
    // reachable through the UI.

    const user = await createDedicatedUser('mfaenroll');
    await realLogin(page, user.username, user.password);

    await page.goto('/profile');
    await page.getByRole('button', { name: 'Security' }).click();
    await expect(page.getByText('Two-Factor Authentication')).toBeVisible();

    await page.getByRole('button', { name: 'Enable' }).click();
    const secretLocator = page.locator('code').first();
    await expect(secretLocator).toBeVisible({ timeout: 10_000 });
    const secret = (await secretLocator.textContent())?.trim();
    expect(secret, 'enrollment must render a non-empty setup key').toBeTruthy();

    // A genuinely correct code, straight from the real secret.
    await page.getByPlaceholder('123456').fill(totpCode(secret as string));
    await page.getByPlaceholder('Your current password').fill(user.password);
    await page.getByRole('button', { name: 'Verify & enable' }).click();

    // What SHOULD happen: recovery codes render, confirming activation.
    await expect(page.getByText('Save your recovery codes')).toBeVisible({ timeout: 10_000 });
});

// enableMfaViaApi is test SETUP ONLY, not a UI shortcut taken out of laziness:
// this test exercises LOGIN's code-entry step, not enrollment's UI (that's
// the test above), so it reaches its precondition (an MFA-enabled account)
// via the same direct API path web-real-smoke.sh already uses for setup, not
// through the UI. Operates on the dedicated user created below, NEVER on the
// shared admin -- enabling MFA is a one-way, session-breaking mutation on
// whichever account it's applied to, so doing this to ADMIN_USERNAME would
// make every later spec's admin login order-dependent on this one running
// (or not) first. Returns activatedStep alongside the secret so the caller
// can wait for a TOTP step strictly after it before the login verify below --
// see waitForFreshTotpCode's own comment for why.
async function enableMfaViaApi(username: string, password: string): Promise<{ secret: string; activatedStep: number }> {
    const token = await apiLogin(username, password);
    const auth = { Authorization: `Bearer ${token}` };
    // A separate, cookie-free context for the actual mutations -- see
    // apiLogin's comment for why this can't reuse the login context.
    const api = await apiRequestFactory.newContext({ baseURL: BACKEND_URL });
    try {
        const enrollRes = await api.post('/api/v1/auth/mfa/enroll', { headers: auth, data: {} });
        if (!enrollRes.ok()) throw new Error(`setup enroll failed: ${enrollRes.status()} ${await enrollRes.text()}`);
        const secret = (await enrollRes.json()).data.secret as string;

        const activateAtSeconds = Date.now() / 1000;
        const activateRes = await api.post('/api/v1/auth/mfa/activate', {
            headers: auth,
            data: { code: totpCode(secret, activateAtSeconds), password },
        });
        if (!activateRes.ok())
            throw new Error(`setup activate failed: ${activateRes.status()} ${await activateRes.text()}`);

        return { secret, activatedStep: Math.floor(activateAtSeconds / 30) };
    } finally {
        await api.dispose();
    }
}

test('logging in with MFA enabled completes via the code-entry step (fixes known bug #2442)', async ({ page }) => {
    // https://github.com/keyorixhq/keyorix/issues/2442 -- server/http/handlers/auth.go's
    // Login returns HTTP 200 with {mfa_required: true, mfa_challenge, ...} on
    // a correct password for an MFA account (no session cookie set).
    // authStore.login() now stores this as a pending mfaChallenge instead of
    // treating it as a completed session, LoginPage renders MfaChallengeForm
    // once mfaChallenge is set, and verifyMfa() calls the real VerifyMFA
    // endpoint with the challenge + code.

    const user = await createDedicatedUser('mfalogin');
    const { secret: totpSecret, activatedStep } = await enableMfaViaApi(user.username, user.password);

    // See waitForFreshTotpCode's own comment: the activate call above and this
    // verify both draw from the same per-account anti-replay counter, and this
    // SPA's routing can make them only moments apart in wall-clock time.
    const verifyCode = await waitForFreshTotpCode(page, totpSecret, activatedStep);

    await page.goto('/login');
    await submitLogin(page, user.username, user.password);

    // The code-entry step for the pending MFA challenge.
    await expect(page.getByPlaceholder('123456')).toBeVisible({ timeout: 10_000 });
    await page.getByPlaceholder('123456').fill(verifyCode.code);
    await page.getByRole('button', { name: /verify/i }).click();
    await page.waitForURL('/dashboard', { timeout: 15_000 });
});
