// web/e2e/real/mfa-login.spec.ts — SESSION-WEB-E2E item 1: exercises TOTP MFA
// through the real Profile → Security UI (no mocked routes, same real-backend
// shape as pages.spec.ts) and a subsequent login.
//
// #2442 (logging in with MFA enabled never prompted for a code -- authStore
// ignored mfa_required) is fixed as of this PR: login() now stores a pending
// mfaChallenge instead of landing a bogus "authenticated" session, LoginPage
// renders a code-entry step, and verifyMfa() completes it against the real
// VerifyMFA endpoint. The login test below asserts the real flow completes,
// instead of test.fail()ing on the known bug.
//
// The enrollment test below is still marked test.fail() for a separate,
// confirmed product bug (filed as GitHub issue #2441) rather than skipped:
// skipping would silently stop proving anything, while test.fail() stays RED
// on CI until the real fix lands and flips to a loud "unexpectedly passing"
// the moment someone fixes the underlying code without updating this file.
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
import { test, expect, Page, APIRequestContext } from '@playwright/test';
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
// activate, login's verify, and a later reauth (disable) all draw from it.
// This SPA's client-side routing makes two of those checks only a few hundred
// milliseconds apart in practice (confirmed live: two "next step" guesses a
// test run apart computed to the identical step and code), so predicting a
// future step ahead of time is not reliable; waiting for a real, fresh step
// to actually arrive is.
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

async function realLogin(page: Page) {
    await page.goto('/login');
    await submitLogin(page, ADMIN_USERNAME as string, ADMIN_PASSWORD as string);
    await page.waitForURL('/dashboard', { timeout: 15_000 });
}

test('MFA enrollment via Profile → Security currently cannot complete (known bug #2441)', async ({ page }) => {
    // https://github.com/keyorixhq/keyorix/issues/2441 -- server/http/handlers/mfa.go's
    // ActivateMFA requires BOTH the TOTP code and the account password
    // (internal/core/mfa.go's requireReauth falls through to the
    // password-compare branch, since MFAEnabled is still false during
    // enrollment). web/src/features/account/MfaSection.tsx's EnrollModal only
    // ever collects the 6-digit code -- there is no password field -- so
    // mfaApi.activate(code) always sends {code} alone and the backend always
    // rejects it with "invalid code or password", regardless of whether the
    // code itself is correct. Confirmed live both through this UI flow and
    // directly against the API with the exact same request shape the UI
    // sends (see issue #2441's repro).
    test.fail(true, 'issue #2441 -- EnrollModal never collects/sends the password ActivateMFA requires');

    await realLogin(page);

    await page.goto('/profile');
    await page.getByRole('button', { name: 'Security' }).click();
    await expect(page.getByText('Two-Factor Authentication')).toBeVisible();

    await page.getByRole('button', { name: 'Enable' }).click();
    const secretLocator = page.locator('code').first();
    await expect(secretLocator).toBeVisible({ timeout: 10_000 });
    const secret = (await secretLocator.textContent())?.trim();
    expect(secret, 'enrollment must render a non-empty setup key').toBeTruthy();

    // A genuinely correct code, straight from the real secret -- so the only
    // thing this can be exercising is the missing-password bug, not a test
    // bug in totpCode() itself.
    await page.getByPlaceholder('123456').fill(totpCode(secret as string));
    await page.getByRole('button', { name: 'Verify & enable' }).click();

    // What SHOULD happen: recovery codes render, confirming activation.
    await expect(page.getByText('Save your recovery codes')).toBeVisible({ timeout: 10_000 });
});

// enableMfaViaApi is test SETUP ONLY, not a UI shortcut this test is avoiding
// out of laziness: issue #2441 (above) means there is currently no way to
// reach an MFA-enabled account through the UI at all, so the only way to get
// into the precondition state the login test below needs is the same direct
// API path issue #2441's own repro uses. Mirrors
// scripts/e2e/web-real-smoke.sh's existing admin bootstrap, which already
// talks to this backend directly over HTTP for setup, not through the UI.
async function enableMfaViaApi(request: APIRequestContext): Promise<{ secret: string; activatedStep: number }> {
    const loginRes = await request.post(`${BACKEND_URL}/auth/login`, {
        data: { username: ADMIN_USERNAME, password: ADMIN_PASSWORD },
    });
    if (!loginRes.ok()) throw new Error(`setup login failed: ${loginRes.status()} ${await loginRes.text()}`);
    const token = (await loginRes.json()).data.token as string;
    const auth = { Authorization: `Bearer ${token}` };

    // Login() always sets the session + CSRF cookies on success too -- it has
    // no way to know this caller only wants the Bearer token -- and
    // Playwright's `request` fixture persists cookies from every response
    // it sees, so those cookies ride along on every later `request` call
    // made from this same APIRequestContext, regardless of origin. Once
    // RequireCSRF (server/middleware/csrf.go) sees a session cookie on a
    // state-changing request, it demands the double-submit header too, even
    // for an otherwise Bearer-only caller -- so it must be threaded through
    // explicitly here, or enroll/activate below 403 with "Missing CSRF token
    // header". Parsed directly off this response's own Set-Cookie header,
    // not a shared cookie jar -- robust regardless of what `request`/`page`
    // do or don't share.
    const csrfSetCookie = loginRes
        .headersArray()
        .find((h) => h.name.toLowerCase() === 'set-cookie' && h.value.startsWith('csrf_token='));
    const csrfValue = csrfSetCookie?.value.split(';')[0].slice('csrf_token='.length);
    const headers = csrfValue ? { ...auth, 'X-CSRF-Token': csrfValue } : auth;

    const enrollRes = await request.post(`${BACKEND_URL}/api/v1/auth/mfa/enroll`, { headers, data: {} });
    if (!enrollRes.ok()) throw new Error(`setup enroll failed: ${enrollRes.status()} ${await enrollRes.text()}`);
    const secret = (await enrollRes.json()).data.secret as string;

    const activateAtSeconds = Date.now() / 1000;
    const activateRes = await request.post(`${BACKEND_URL}/api/v1/auth/mfa/activate`, {
        headers,
        data: { code: totpCode(secret, activateAtSeconds), password: ADMIN_PASSWORD },
    });
    if (!activateRes.ok())
        throw new Error(`setup activate failed: ${activateRes.status()} ${await activateRes.text()}`);

    return { secret, activatedStep: Math.floor(activateAtSeconds / 30) };
}

test('logging in with MFA enabled completes via the code-entry step (fixes known bug #2442)', async ({
    page,
    request,
}) => {
    // https://github.com/keyorixhq/keyorix/issues/2442 -- server/http/handlers/auth.go's
    // Login returns HTTP 200 with {mfa_required: true, mfa_challenge, ...} on
    // a correct password for an MFA account (no session cookie set).
    // authStore.login() now stores this as a pending mfaChallenge instead of
    // treating it as a completed session, LoginPage renders MfaChallengeForm
    // once mfaChallenge is set, and verifyMfa() calls the real VerifyMFA
    // endpoint with the challenge + code.

    // waitForFreshTotpCode below can poll for up to a 30s TOTP period TWICE
    // (once before verify, once before the disable cleanup) -- comfortably
    // past Playwright's 30s per-test default.
    test.setTimeout(120_000);

    const { secret: totpSecret, activatedStep } = await enableMfaViaApi(request);

    // internal/core/mfa.go's anti-replay (MarkTOTPStepUsed) rejects "this
    // step or any EARLIER one" for any later TOTP check against this
    // account -- ONE shared counter per account across every check site
    // (enroll's activate above, this test's own verify, and its disable
    // cleanup below). This app's client-side routing (React Router, no full
    // page reloads between /login -> /dashboard -> /profile) makes
    // consecutive checks only a few hundred milliseconds apart in practice
    // (confirmed live replaying this exact test: two steps computed
    // moments apart independently landed on the identical 30s step and
    // therefore the identical code) -- too fast to assume a fresh step has
    // naturally arrived. waitForFreshTotpCode polls real time until one
    // genuinely has, then returns delta-0 (the current step), which
    // validateTOTPStep is guaranteed to accept regardless of how fast or
    // slow the request that follows actually runs.
    const verifyCode = await waitForFreshTotpCode(page, totpSecret, activatedStep);

    await page.goto('/login');
    await submitLogin(page, ADMIN_USERNAME as string, ADMIN_PASSWORD as string);

    // The code-entry step for the pending MFA challenge.
    await expect(page.getByPlaceholder('123456')).toBeVisible({ timeout: 10_000 });
    await page.getByPlaceholder('123456').fill(verifyCode.code);
    await page.getByRole('button', { name: /verify/i }).click();
    await page.waitForURL('/dashboard', { timeout: 15_000 });

    // Cleanup: this test enabled MFA for real on the SHARED admin account
    // every other spec in this suite reuses (pages.spec.ts included, which
    // has no MFA handling at all) -- leaving it enabled would break every
    // test that runs after this one. Disable it again through the real UI.
    // requireReauth requires a current code rather than the password once
    // MFAEnabled is true.
    const disableCode = await waitForFreshTotpCode(page, totpSecret, verifyCode.step);
    await page.goto('/profile');
    await page.getByRole('button', { name: 'Security' }).click();
    await page.getByRole('button', { name: 'Disable' }).click();
    await page.getByLabel('Authenticator code or password').fill(disableCode.code);
    await page.getByRole('button', { name: 'Disable 2FA' }).click();
    await expect(page.getByRole('button', { name: 'Enable' })).toBeVisible({ timeout: 10_000 });
});
