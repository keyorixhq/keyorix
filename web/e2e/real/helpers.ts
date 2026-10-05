// web/e2e/real/helpers.ts — the real-backend Playwright suite's shared setup helpers.
//
// Extracted from mfa-login.spec.ts when a second MFA spec file needed the same TOTP
// arithmetic, the same cookie-free Bearer login, and the same throwaway-user
// provisioning (#2738). Deliberately NOT a *.spec.ts file: web-real-smoke.sh discovers
// spec files with `find e2e/real -name '*.spec.ts'`, so a helpers module here is invisible
// to that discovery and never boots a server group of its own.
//
// Every comment below is carried over verbatim from the original file — each one records
// something confirmed live against a real server, not a guess.

import { request as apiRequestFactory, Page } from '@playwright/test';
import { createHmac } from 'node:crypto';

export const ADMIN_USERNAME = process.env.KEYORIX_E2E_ADMIN_USERNAME;
export const ADMIN_PASSWORD = process.env.KEYORIX_E2E_ADMIN_PASSWORD;
export const BACKEND_URL = process.env.KEYORIX_E2E_BACKEND_URL;

if (!ADMIN_USERNAME || !ADMIN_PASSWORD || !BACKEND_URL) {
    throw new Error(
        'KEYORIX_E2E_ADMIN_USERNAME/KEYORIX_E2E_ADMIN_PASSWORD/KEYORIX_E2E_BACKEND_URL are not set -- ' +
            'run scripts/e2e/web-real-smoke.sh, which bootstraps a real admin and sets them, rather than ' +
            'invoking a spec file directly.'
    );
}

// base32Decode implements RFC 4648 base32 (no padding tolerance needed --
// pquerna/otp's GenerateOpts never pads its generated secrets).
export function base32Decode(input: string): Buffer {
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
export function totpCode(base32Secret: string, atSeconds = Date.now() / 1000): string {
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
export async function waitForFreshTotpCode(
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

export async function submitLogin(page: Page, username: string, password: string) {
    await page.getByTestId('username-input').fill(username);
    await page.getByTestId('password-input').fill(password);
    await page.getByTestId('login-button').click();
}

export async function realLogin(page: Page, username: string, password: string) {
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
export async function apiLogin(username: string, password: string): Promise<string> {
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
export async function createDedicatedUser(usernamePrefix: string): Promise<{ username: string; password: string }> {
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
export async function enableMfaViaApi(username: string, password: string): Promise<{ secret: string; activatedStep: number }> {
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

