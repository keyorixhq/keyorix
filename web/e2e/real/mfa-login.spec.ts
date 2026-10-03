// web/e2e/real/mfa-login.spec.ts — SESSION-WEB-E2E item 1: exercises TOTP MFA
// through the real Profile → Security UI (no mocked routes, same real-backend
// shape as pages.spec.ts) and a subsequent login.
//
// WEB-FIX1: both tests below are now real passing tests. The first
// (#2441, enrollment) -- EnrollModal was fixed to collect and send the
// account password ActivateMFA requires. The second (#2442, login) --
// authStore.login() was fixed to detect an mfa_required response and park
// it instead of treating it as a completed session, and LoginPage now
// renders a code-entry step (MfaChallengeForm) off that state, calling the
// real VerifyMFA endpoint to complete the login.
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
// is never touched.
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

// waitForNextTotpStep blocks until the TOTP period rolls over to a new
// 30-second step, plus a small buffer past the boundary. #2442's test below
// needs this: internal/core/mfa.go's anti-replay guard (MarkTOTPStepUsed)
// marks whichever time-step a code was accepted at as used, and rejects ANY
// code for that same (or an earlier) step afterward, even a different,
// independently-correct one -- a real security property (closes the ~90s
// replay window on a leaked code), not a bug. enableMfaViaApi's own
// activation call consumes a step; without this wait, the login attempt
// moments later would very likely compute a code for that same step and get
// "invalid code or expired" rejected as a false replay. Confirmed live.
async function waitForNextTotpStep(): Promise<void> {
    const periodMs = 30_000;
    const msIntoCurrentStep = Date.now() % periodMs;
    const msUntilNextStep = periodMs - msIntoCurrentStep;
    await new Promise((resolve) => setTimeout(resolve, msUntilNextStep + 1000));
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
        //
        // The trailing "-7" guarantees at least one digit: base36
        // (Math.random().toString(36)) can land on an all-letters slice often
        // enough to flake in practice -- confirmed live, a real run 400'd with
        // "password must contain a digit" with no digit anywhere in the
        // random segment.
        const password = `Quartz-Falcon-${Math.random().toString(36).slice(2, 10)}-7-Garnet!`;
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

test('MFA enrollment via Profile → Security', async ({ page }) => {
    // https://github.com/keyorixhq/keyorix/issues/2441 -- FIXED by WEB-FIX1.
    // server/http/handlers/mfa.go's ActivateMFA requires BOTH the TOTP code
    // and the account password (internal/core/mfa.go's requireReauth falls
    // through to the password-compare branch, since MFAEnabled is still
    // false during enrollment). web/src/features/account/MfaSection.tsx's
    // EnrollModal used to only ever collect the 6-digit code -- fixed to
    // also collect the account password and send both.
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
    await page.getByLabel('Account password').fill(user.password);
    await page.getByRole('button', { name: 'Verify & enable' }).click();

    // Recovery codes render, confirming activation. This specifically was the
    // part #2441's fix had to get right beyond just "the request succeeds":
    // internal/core/mfa.go's ActivateMFA invalidates the CURRENT session the
    // instant it succeeds (an intentional security upgrade -- a pre-MFA
    // session must not outlive it), and the query client's global
    // refetchOnWindowFocus default refetches every ACTIVE query on a focus
    // event, not just ones explicitly invalidated. Before useMfaRecoveryStatus
    // was gated inactive for the enrollment modal's lifetime
    // (web/src/features/account/index.ts), that combination raced this exact
    // assertion: a focus-triggered background refetch of the recovery-code
    // status hit the now-invalid session, which the apiClient interceptor
    // turned into an automatic hard-redirect to /login -- tearing down the
    // one-time codes screen before this could even observe it. Confirmed live
    // (this assertion genuinely failed, deterministically, before that fix).
    await expect(page.getByText('Save your recovery codes')).toBeVisible({ timeout: 10_000 });
    await page.getByRole('button', { name: 'Done' }).click();

    // Clicking Done re-activates the recovery-status query, which now (by
    // design, not a bug) finds the current session invalidated and the app
    // redirects to /login -- the user must re-authenticate under the new
    // MFA-enforced policy. Confirming that landing, not a stuck/broken page.
    // The redirect lands on /login?logout_error=1 (G65's "server-side logout
    // couldn't be confirmed" path, since the session was already gone by the
    // time the explicit logout call fired) -- '**/login' alone wouldn't match
    // that query string, confirmed live.
    await page.waitForURL(/\/login(\?|$)/, { timeout: 15_000 });
});

// enableMfaViaApi is test SETUP ONLY, not a UI shortcut: the login test below
// (#2442) is specifically testing what happens once an account already HAS
// MFA enabled, so enrollment itself (covered by the test above) isn't what's
// under test here -- going straight to the API keeps this test focused and
// avoids depending on the enrollment test's own UI flow having run first.
// Operates on the dedicated user created below, NEVER on the shared admin --
// enabling MFA is a one-way, session-breaking mutation on whichever account
// it's applied to, so doing this to ADMIN_USERNAME would make every later
// spec's admin login order-dependent on this one running (or not) first.
async function enableMfaViaApi(username: string, password: string): Promise<string> {
    const token = await apiLogin(username, password);
    const auth = { Authorization: `Bearer ${token}` };
    // A separate, cookie-free context for the actual mutations -- see
    // apiLogin's comment for why this can't reuse the login context.
    const api = await apiRequestFactory.newContext({ baseURL: BACKEND_URL });
    try {
        const enrollRes = await api.post('/api/v1/auth/mfa/enroll', { headers: auth, data: {} });
        if (!enrollRes.ok()) throw new Error(`setup enroll failed: ${enrollRes.status()} ${await enrollRes.text()}`);
        const secret = (await enrollRes.json()).data.secret as string;

        const activateRes = await api.post('/api/v1/auth/mfa/activate', {
            headers: auth,
            data: { code: totpCode(secret), password },
        });
        if (!activateRes.ok())
            throw new Error(`setup activate failed: ${activateRes.status()} ${await activateRes.text()}`);

        return secret;
    } finally {
        await api.dispose();
    }
}

test('logging in with MFA enabled', async ({ page }) => {
    // https://github.com/keyorixhq/keyorix/issues/2442 -- FIXED by WEB-FIX1.
    // server/http/handlers/auth.go's Login returns HTTP 200 with
    // {mfa_required: true, mfa_challenge, ...} on a correct password for an
    // MFA account (no session cookie set). authStore.login() used to treat
    // any non-empty response.data as success; fixed to detect mfa_required
    // and park the challenge instead, and LoginPage now renders
    // MfaChallengeForm (a code-entry step) off that state, calling the real
    // VerifyMFA endpoint (server/http/handlers/mfa.go) to complete the login.
    const user = await createDedicatedUser('mfalogin');
    const totpSecret = await enableMfaViaApi(user.username, user.password);
    // See waitForNextTotpStep's own comment: without this, the code computed
    // below for login can land in the same 30s step enableMfaViaApi's own
    // activation call already consumed, and the server's anti-replay guard
    // correctly (not a bug) rejects it.
    await waitForNextTotpStep();

    await page.goto('/login');
    await submitLogin(page, user.username, user.password);

    // The code-entry step for the pending MFA challenge.
    await expect(page.getByPlaceholder('123456')).toBeVisible({ timeout: 10_000 });
    await page.getByPlaceholder('123456').fill(totpCode(totpSecret));
    await page.getByRole('button', { name: /verify/i }).click();
    await page.waitForURL('/dashboard', { timeout: 15_000 });
    // The dashboard actually renders real data post-login, not an error
    // boundary or a stuck spinner -- same load-bearing check pages.spec.ts
    // uses for a plain (non-MFA) login.
    await expect(page.getByText('Total Secrets')).toBeVisible();
});
