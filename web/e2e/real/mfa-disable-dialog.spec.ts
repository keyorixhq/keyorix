// web/e2e/real/mfa-disable-dialog.spec.ts — #2738: the Disable-2FA dialog hung forever
// after one rejected attempt. Spinner up, no error text, no further request, and closing
// and reopening the dialog did not clear it — only a full page reload did.
//
// Driven the way the reporter drove it, against a real backend: enrol TOTP through the
// real Profile → Security UI, open Disable, submit something the server refuses, and
// require that (a) the server's own reason appears, (b) the dialog is immediately usable
// again, and (c) a correct code submitted in that SAME dialog, with no page reload,
// genuinely disables 2FA.
//
// Why its own spec file rather than another test in mfa-login.spec.ts:
// server/http/handlers/auth.go's reserveLoginAttempt spends one slot from a per-IP budget
// of 10 per 15 minutes on EVERY login, success or failure (see its own doc comment — the
// budget is deliberately outcome-agnostic). mfa-login.spec.ts already spends 6, and
// web-real-smoke.sh's own group spends 1 seeding a project; adding this test there would
// have put that file at the ceiling with zero margin, which is exactly the trap that
// file's harness comment warns about. A separate file keeps each one well under budget —
// see web-real-smoke.sh's MAX_SPECS_PER_GROUP comment.
//
// Login cost of this file: 2 (one admin login to provision a throwaway user, one UI login
// as that user). MFA is enrolled through the UI rather than the API precisely because the
// calling session survives activation (internal/core's ActivateMFA keeps it and evicts
// only the others), so no second login is needed — and because that is the path #2738 was
// actually found on.
import { test, expect } from '@playwright/test';
import { createDedicatedUser, realLogin, totpCode, waitForFreshTotpCode } from './helpers';

// Generous, not slow-tolerant: this test has to wait for a real 30-second TOTP step to
// roll over before it can submit a code the server's anti-replay counter will accept
// (activation burned the current step), and it does that AFTER a full enrol-plus-refusal
// sequence. The default 30s budget cannot fit a 30s wall-clock wait. Timeouts here detect
// a hang; they are not a speed assertion.
test.setTimeout(150_000);

test('the Disable-2FA dialog survives a rejected attempt and completes without a reload (#2738)', async ({
    page,
}) => {
    const user = await createDedicatedUser('mfadisable');
    await realLogin(page, user.username, user.password);

    // ── Enrol TOTP through the real UI (the path the bug was found on) ───────
    await page.goto('/profile');
    await page.getByRole('button', { name: 'Security' }).click();
    await expect(page.getByText('Two-Factor Authentication')).toBeVisible();

    await page.getByRole('button', { name: 'Enable', exact: true }).click();
    const secretLocator = page.locator('code').first();
    await expect(secretLocator).toBeVisible({ timeout: 10_000 });
    const secret = (await secretLocator.textContent())?.trim();
    expect(secret, 'enrolment must render a non-empty setup key').toBeTruthy();

    const activateAtSeconds = Date.now() / 1000;
    await page.getByPlaceholder('123456').fill(totpCode(secret as string, activateAtSeconds));
    await page.getByPlaceholder('Your current password').fill(user.password);
    await page.getByRole('button', { name: 'Verify & enable' }).click();
    await expect(page.getByText('Save your recovery codes')).toBeVisible({ timeout: 10_000 });
    await page.getByRole('button', { name: 'Done' }).click();

    // Activation consumed this TOTP step (MarkTOTPStepUsed): every later code must come
    // from a strictly later step. ONE shared anti-replay counter per account.
    const activatedStep = Math.floor(activateAtSeconds / 30);

    // ── The dialog, and the label it now carries ────────────────────────────
    await expect(page.getByRole('button', { name: 'Disable', exact: true })).toBeVisible({ timeout: 10_000 });
    await page.getByRole('button', { name: 'Disable', exact: true }).click();
    await expect(page.getByText('Disable two-factor authentication')).toBeVisible();

    // The field is located by a PREFIX that matches the fixed label ("Authenticator code")
    // as well as the old one ("Authenticator code or password"), so the behavioural
    // assertions below genuinely run against main and this test fails there for the
    // behaviour it names rather than on a label lookup that never resolves. The label text
    // itself is asserted separately, further down.
    const codeField = page.getByLabel(/^Authenticator code/);
    await expect(codeField).toBeVisible();

    const confirm = page.getByRole('button', { name: 'Disable 2FA' });

    // ── A rejected code: the server's reason, and a dialog that still works ──
    let disableRequests = 0;
    page.on('request', (req) => {
        if (req.method() === 'POST' && req.url().includes('/api/v1/auth/mfa/disable')) {
            disableRequests++;
        }
    });

    await codeField.fill('000000');
    await expect(confirm).toBeEnabled();
    await confirm.click();

    // The server's own message, surfaced in the dialog — not a silent spinner.
    await expect(page.getByText(/invalid code or password/i)).toBeVisible({ timeout: 15_000 });
    // Usable again, in the same dialog, with no reload: this is the whole bug.
    await expect(confirm).toBeEnabled({ timeout: 15_000 });

    // One click, one request. On main a retried 4xx charged TWO of the account's lockout
    // slots per click (requireReauth calls recordFailedLogin on every refusal) — this is
    // the assertion that goes red there.
    await page.waitForTimeout(2_000);
    expect(disableRequests, 'one click must produce exactly one POST /auth/mfa/disable').toBe(1);

    // ── The label, and what it is now possible to submit ─────────────────────
    // The field used to say "Authenticator code or password", inviting the one submission
    // internal/core's requireReauth ALWAYS refuses once a second factor is enrolled (its
    // password branch additionally needs an MFAStepUpPurposeReauth grant that no web login
    // mints). The label now matches what the backend accepts; the backend check is
    // unchanged.
    await expect(page.getByLabel(/or password/i)).toHaveCount(0);
    await expect(page.getByText(/your password is not accepted here/i)).toBeVisible();
    // Submitting the account password is not even possible: the confirm button stays
    // disabled for anything that is not six digits, so a guaranteed-refusal attempt is
    // never spent against the per-account lockout requireReauth feeds.
    await codeField.fill(user.password);
    await expect(confirm).toBeDisabled();

    // ── A correct code in that same dialog really disables 2FA ───────────────
    const fresh = await waitForFreshTotpCode(page, secret as string, activatedStep);
    await codeField.fill(fresh.code);
    await confirm.click();

    // 2FA is genuinely off: the dialog closes and the section offers Enable again.
    await expect(page.getByText('Disable two-factor authentication')).toHaveCount(0, { timeout: 15_000 });
    await expect(page.getByRole('button', { name: 'Enable', exact: true })).toBeVisible({ timeout: 15_000 });
});
