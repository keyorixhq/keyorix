// Guards for evaluating *untrusted* regex patterns client-side.
//
// The secret-naming policy (`GET /system/secret-policy` or similar) is
// admin-configured, but it's still untrusted from the browser's point of
// view: a pathological pattern (classic catastrophic-backtracking shapes
// like `(a+)+$`) evaluated against a crafted or merely unlucky input can
// hang the tab that runs it. This is a self-tab-only availability issue —
// the server independently re-validates the name against the same policy
// regardless of what the client does — but it's still worth avoiding.
//
// JS regex execution is synchronous, and once a `.test()`/`.exec()` call has
// actually started backtracking exponentially, nothing on the same thread
// can interrupt it — a `setTimeout`-based "timeout" around the call cannot
// fire until the call itself returns, so it provides no real protection.
// The only genuine client-side mitigation is to refuse to run patterns that
// *look* dangerous before ever constructing/executing them.
//
// `safe-regex` performs that check statically (via `regexp-tree`, building
// an AST and rejecting well-known catastrophic-backtracking shapes such as
// nested/overlapping repetition). It's a heuristic, not a proof of safety —
// a pattern it doesn't flag can still be slow on sufficiently adversarial
// input — so callers should also cap the length of the value under test as
// defense-in-depth.
import safeRegexCheck from 'safe-regex';

/**
 * Returns true if `pattern` does not look like a known catastrophic-
 * backtracking shape. Never throws: a pattern the analyzer itself can't
 * parse is treated as unsafe (we shouldn't trust what we can't analyze).
 */
export function isPatternSafe(pattern: string): boolean {
    try {
        return safeRegexCheck(pattern);
    } catch {
        return false;
    }
}

/**
 * Defense-in-depth cap on the value tested against an admin-configured
 * pattern. Even a pattern `safe-regex` approves can still be slow given
 * long enough input (e.g. quadratic-time shapes); this bounds the worst
 * case without claiming every approved pattern is instant on any input.
 * 512 comfortably covers any realistic secret name.
 */
export const MAX_REGEX_TEST_INPUT_LENGTH = 512;

export type SafeRegexTestResult =
    | { skipped: true }
    | {
          skipped: false;
          matches: boolean;
      };

/**
 * Tests `value` against `pattern`, but only when it's safe to do so:
 * the pattern must pass the catastrophic-backtracking heuristic and
 * `value` must be within `MAX_REGEX_TEST_INPUT_LENGTH`.
 *
 * Returns `{ skipped: true }` when the check can't be safely performed
 * client-side (unsafe-looking pattern, oversized input, or a pattern that
 * fails to compile). Callers should treat `skipped` as "can't verify here,
 * defer to the server" — never as a validation failure.
 */
export function testPatternSafely(pattern: string, value: string): SafeRegexTestResult {
    if (!isPatternSafe(pattern)) {
        return { skipped: true };
    }
    if (value.length > MAX_REGEX_TEST_INPUT_LENGTH) {
        return { skipped: true };
    }
    try {
        return { skipped: false, matches: new RegExp(pattern).test(value) };
    } catch {
        return { skipped: true };
    }
}
