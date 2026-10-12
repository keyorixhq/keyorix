// web/e2e/real/support/password.ts — one compliant-fixture-password generator
// for every real-backend spec, replacing hand-rolled literals that satisfied
// internal/core/rules.DefaultPasswordPolicy only by luck (#2815).
//
// WHY THIS EXISTS. mfa-login.spec.ts built its throwaway user's password as
//     `Quartz-Falcon-${Math.random().toString(36).slice(2, 10)}-Garnet!`
// which has NO literal digit: RequireDigit was satisfied only when the base-36
// chunk happened to contain one. An n-char base-36 chunk is digit-free with
// probability (26/36)^n -- 7.40% at n=8, measured at 7.5% over 200 local runs.
// The spec calls the generator twice per run, so ~14% of runs failed, matching
// the ~16% observed in #2815. It failed in test SETUP
// (`setup create-user failed: 400 ... password must contain a digit`), so it
// failed whichever PR happened to be running web-e2e-real-smoke -- #2729 merged
// with it red.
//
// A literal digit would have fixed that one instance. This module fixes the
// class instead: compliantPassword() satisfies every requirement BY
// CONSTRUCTION and then VERIFIES the result against the same policy before
// returning it, so a future policy change (a longer minimum, a new required
// class) surfaces as a loud throw naming the unmet requirement rather than as
// a 400 from the backend in an unrelated PR's CI.
//
// POLICY MIRROR, and its limits. The predicate below mirrors
// internal/core/rules/password_policy.go's DefaultPasswordPolicy() and
// containsPersonalInfo() as of 2026-10-05. It deliberately does NOT model:
//   - isCommonPassword (RejectCommonPasswords): the generator's output is a
//     20-char random string from a 60-odd character alphabet, so a common-list
//     hit is not a realistic failure mode, and duplicating that list here
//     would be a second copy to keep in sync.
//   - Go's full unicode.IsPunct/IsSymbol/IsSpace classification: the special
//     alphabet is ASCII punctuation only, which is unambiguously special under
//     both. isSpecial() below is correspondingly conservative -- it can only
//     under-count, never over-count, so a password it calls compliant is
//     compliant under the Go check too.
// This is a MIRROR, which means it can drift. It is not the enforcement point
// (the backend is); it exists so the drift shows up as a thrown error in the
// generator rather than a flaky 400 in setup.

import { randomInt } from 'node:crypto';

/** DefaultPasswordPolicy()'s character-class and length requirements. */
export const E2E_PASSWORD_POLICY = {
    minLength: 16,
    requireUppercase: true,
    requireLowercase: true,
    requireDigit: true,
    requireSpecial: true,
} as const;

// Ambiguous glyphs (0/O, 1/l/I) are left out so a failure message pasted into
// a terminal is unambiguous -- not a policy requirement, just legibility.
const UPPER = 'ABCDEFGHJKLMNPQRSTUVWXYZ';
const LOWER = 'abcdefghijkmnopqrstuvwxyz';
const DIGIT = '23456789';
const SPECIAL = '-_!@#%+=?.';

const isSpecial = (ch: string): boolean => SPECIAL.includes(ch);

// randomInt from node:crypto, not Math.random(). There is an open CodeQL alert
// (#1191, js/insecure-randomness) on the Math.random() password expression this
// module replaces; drawing fixture-password characters from a CSPRNG fixes that
// finding rather than relocating it to this file -- CLAUDE.md's point that
// editing near an alert marks the original "fixed" and respawns it at the new
// line. Math.random() is also simply the wrong tool for generating a
// credential, even a throwaway one, in a secrets product: randomInt costs
// nothing here and removes the need for anyone to reason about whether this
// particular password mattered.
//
// randomInt(max) is uniform over [0, max) -- no modulo bias to correct for,
// unlike a hand-rolled bytes-mod-alphabet-length.
function pick(alphabet: string, n: number): string {
    let out = '';
    for (let i = 0; i < n; i++) {
        out += alphabet[randomInt(alphabet.length)];
    }
    return out;
}

/**
 * passwordPolicyFailures returns the unmet requirements for `pw`, phrased like
 * the backend's own error, or [] when it is compliant.
 *
 * `personalInfo` is the set of strings DefaultPasswordPolicy's RejectPersonalInfo
 * check would reject the password for containing: the username, the local part
 * of the email, and each whitespace-separated word of the display name. Only
 * entries of 3+ characters are checked, matching containsPersonalInfo.
 */
export function passwordPolicyFailures(pw: string, personalInfo: string[] = []): string[] {
    const failures: string[] = [];
    if (pw.length < E2E_PASSWORD_POLICY.minLength) {
        failures.push(`be at least ${E2E_PASSWORD_POLICY.minLength} characters`);
    }
    // Classify exactly once per character, like the Go switch: an uppercase
    // letter is never also counted as "special".
    let hasUpper = false;
    let hasLower = false;
    let hasDigit = false;
    let hasSpecial = false;
    for (const ch of pw) {
        if (/[A-Z]/.test(ch)) hasUpper = true;
        else if (/[a-z]/.test(ch)) hasLower = true;
        else if (/[0-9]/.test(ch)) hasDigit = true;
        else if (isSpecial(ch)) hasSpecial = true;
    }
    if (E2E_PASSWORD_POLICY.requireUppercase && !hasUpper) failures.push('contain an uppercase letter');
    if (E2E_PASSWORD_POLICY.requireLowercase && !hasLower) failures.push('contain a lowercase letter');
    if (E2E_PASSWORD_POLICY.requireDigit && !hasDigit) failures.push('contain a digit');
    if (E2E_PASSWORD_POLICY.requireSpecial && !hasSpecial) failures.push('contain a special character');

    const lower = pw.toLowerCase();
    for (const raw of personalInfo) {
        const candidate = raw.trim().toLowerCase();
        if (candidate.length >= 3 && lower.includes(candidate)) {
            failures.push(`not contain ${JSON.stringify(raw)} (username, email or display name)`);
        }
    }
    return failures;
}

/**
 * personalInfoCandidates derives the strings containsPersonalInfo would check,
 * from the same three fields a create-user call sends. Pass the result to
 * compliantPassword so the generated password cannot collide with them.
 */
export function personalInfoCandidates(opts: { username?: string; email?: string; displayName?: string }): string[] {
    const out: string[] = [];
    if (opts.username) out.push(opts.username);
    if (opts.email) {
        const at = opts.email.indexOf('@');
        out.push(at > 0 ? opts.email.slice(0, at) : opts.email);
    }
    if (opts.displayName) out.push(...opts.displayName.split(/\s+/).filter(Boolean));
    return out;
}

/** How many attempts compliantPassword makes before giving up loudly. */
const MAX_ATTEMPTS = 20;

/**
 * compliantPassword returns a password that satisfies
 * internal/core/rules.DefaultPasswordPolicy.
 *
 * Every required class is placed explicitly, so compliance does not depend on
 * what the randomness happened to produce; the result is then re-checked
 * against passwordPolicyFailures (including `personalInfo`) and regenerated on
 * the vanishingly unlikely chance that a random run collides with a
 * personal-info word. It THROWS rather than returning a non-compliant password:
 * a loud failure here is a one-line fix, whereas a 400 in test setup reads as
 * "this PR broke MFA enrollment".
 *
 * Digits are deliberately non-adjacent (one digit per group, separated by
 * letters) so the output can never contain a 3+-character digit run -- the
 * `Date.now()` stamp that spec usernames and display names embed is a long
 * digit string, and containsPersonalInfo does a plain substring match.
 */
export function compliantPassword(personalInfo: string[] = []): string {
    for (let attempt = 1; attempt <= MAX_ATTEMPTS; attempt++) {
        const pw = [
            pick(UPPER, 1),
            pick(LOWER, 3),
            pick(DIGIT, 1),
            pick(LOWER, 2),
            pick(SPECIAL, 1),
            pick(UPPER, 2),
            pick(LOWER, 3),
            pick(DIGIT, 1),
            pick(LOWER, 2),
            pick(SPECIAL, 1),
            pick(LOWER, 3),
        ].join('');
        const failures = passwordPolicyFailures(pw, personalInfo);
        if (failures.length === 0) return pw;
        if (attempt === MAX_ATTEMPTS) {
            // Never echo the password itself -- only why it was rejected.
            throw new Error(
                `compliantPassword could not produce a policy-compliant password in ${MAX_ATTEMPTS} attempts; ` +
                    `last unmet requirements: ${failures.join(', ')}. This means the generator and ` +
                    `internal/core/rules.DefaultPasswordPolicy have diverged -- fix ` +
                    `web/e2e/real/support/password.ts rather than retrying.`
            );
        }
    }
    /* c8 ignore next */
    throw new Error('unreachable');
}
