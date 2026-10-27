// WCAG AA (4.5:1, normal text) over the theme token pairs in index.css — DEMO-WALK-4 finding 5:
// light-theme secondary text (--text-muted, gray-400 on white) was 2.5:1. The ratios are computed
// from the tokens by the same resolver as the dialog guard (test/contrast.ts), never eyeballed.
//
// Scope: every text token on every surface it can sit on, in both themes, plus the semantic colours
// on their own tint. Not covered: hover and focus states, large-text (3:1) and non-text (borders,
// icons) contrast. Hard-coded hex text colours in components bypass the tokens; they are held by
// hardcodedTextColours.test.ts.
import { describe, expect, it } from 'vitest';
import { contrastRatio, parseColour, type Theme } from '../../test/contrast';

const AA = 4.5;

const ratio = (fg: string, bg: string, theme: Theme) =>
    contrastRatio(parseColour(`var(--${fg})`, theme)!, parseColour(`var(--${bg})`, theme)!);

const SURFACES = ['bg-app', 'bg-surface', 'bg-subtle'];
const PAIRS: Array<[fg: string, bg: string]> = [
    // neutral text on every surface and on the muted fill (inputs, dividers)
    ...['text-primary', 'text-secondary', 'text-muted'].flatMap((fg): Array<[string, string]> =>
        [...SURFACES, 'bg-muted'].map((bg) => [fg, bg])
    ),
    // semantic colours used as text, on the page surfaces
    ...['accent-text', 'danger', 'error', 'success', 'warning'].flatMap((fg): Array<[string, string]> =>
        SURFACES.map((bg) => [fg, bg])
    ),
    // semantic text on its own tint (alerts, badges)
    ['accent-text', 'accent-subtle'],
    ['error', 'error-subtle'],
    ['success', 'success-subtle'],
    ['warning', 'warning-subtle'],
    // button labels
    ['text-inverse', 'accent'],
    ['text-inverse', 'danger'],
];

describe('theme token contrast (WCAG AA 4.5:1)', () => {
    describe.each(['light', 'dark'] as const)('%s theme', (theme) => {
        it.each(PAIRS)('%s on %s', (fg, bg) => {
            const r = ratio(fg, bg, theme);
            expect(r, `${theme}: ${fg} on ${bg} is ${r.toFixed(2)}:1`).toBeGreaterThanOrEqual(AA);
        });
    });

    it('calibration: the pre-fix light --text-muted (gray-400 on white) is rejected', () => {
        const r = contrastRatio(parseColour('#9ca3af', 'light')!, parseColour('#ffffff', 'light')!);
        expect(r).toBeLessThan(AA);
        expect(r).toBeGreaterThan(2.4);
    });

    it('calibration: black on white is the 21:1 maximum', () => {
        expect(contrastRatio(parseColour('#000000', 'light')!, parseColour('#ffffff', 'light')!)).toBeCloseTo(21, 5);
    });
});
