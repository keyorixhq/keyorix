import { describe, it, expect } from 'vitest';
import { isPatternSafe, testPatternSafely, MAX_REGEX_TEST_INPUT_LENGTH } from '../safeRegex';

// A worst-case input for the classic `(a+)+$` catastrophic-backtracking
// pattern: all-but-the-last character matches the inner group, the trailing
// character forces the overall match to fail, so the engine backtracks
// through exponentially many ways of partitioning the 'a's before giving up.
// Native (unguarded) `new RegExp('(a+)+$').test(...)` against this input
// does not return in any practical amount of time.
const CATASTROPHIC_PATTERN = '(a+)+$';
const CATASTROPHIC_INPUT = 'a'.repeat(35) + '!';

// Bound on how long our guard itself is allowed to take. It should be near-
// instant (a syntactic AST check), nowhere close to the exponential blowup
// the unguarded regex would exhibit.
const BOUND_MS = 2_000;

function timed<T>(fn: () => T): { result: T; ms: number } {
    const start = performance.now();
    const result = fn();
    return { result, ms: performance.now() - start };
}

describe('isPatternSafe', () => {
    it('accepts an ordinary, safe naming-policy pattern', () => {
        expect(isPatternSafe('^[a-z][a-z0-9_-]{2,63}$')).toBe(true);
    });

    it('flags a known catastrophic-backtracking shape', () => {
        expect(isPatternSafe(CATASTROPHIC_PATTERN)).toBe(false);
    });

    it('treats an unparseable pattern as unsafe rather than throwing', () => {
        expect(() => isPatternSafe('(unclosed')).not.toThrow();
        expect(isPatternSafe('(unclosed')).toBe(false);
    });
});

describe('testPatternSafely', () => {
    it('validates a normal safe pattern correctly and quickly', () => {
        const { result, ms } = timed(() => testPatternSafely('^[a-z][a-z0-9_-]{2,63}$', 'my-secret-name'));
        expect(result).toEqual({ skipped: false, matches: true });
        expect(ms).toBeLessThan(BOUND_MS);

        const bad = testPatternSafely('^[a-z][a-z0-9_-]{2,63}$', 'INVALID NAME');
        expect(bad).toEqual({ skipped: false, matches: false });
    });

    it('skips (never executes) a pathological pattern instead of hanging', () => {
        const { result, ms } = timed(() => testPatternSafely(CATASTROPHIC_PATTERN, CATASTROPHIC_INPUT));
        // This is the crux of the fix: skipped === true proves the dangerous
        // regex was never constructed/executed against the crafted input --
        // not merely that it "returned in time" (a same-thread timeout could
        // never guarantee that once backtracking has begun).
        expect(result).toEqual({ skipped: true });
        expect(ms).toBeLessThan(BOUND_MS);
    });

    it('skips oversized input even for an otherwise-safe pattern (defense-in-depth cap)', () => {
        const longValue = 'a'.repeat(MAX_REGEX_TEST_INPUT_LENGTH + 1);
        expect(testPatternSafely('^a+$', longValue)).toEqual({ skipped: true });

        const atLimit = 'a'.repeat(MAX_REGEX_TEST_INPUT_LENGTH);
        expect(testPatternSafely('^a+$', atLimit)).toEqual({ skipped: false, matches: true });
    });

    it('skips rather than throws for a pattern that fails to compile', () => {
        expect(testPatternSafely('(unclosed', 'anything')).toEqual({ skipped: true });
    });
});
