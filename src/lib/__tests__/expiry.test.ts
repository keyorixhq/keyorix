import { describe, it, expect } from 'vitest';
import { expiresAtFromPreset, formatRemaining, EXPIRY_OPTIONS } from '../expiry';

describe('expiresAtFromPreset', () => {
    const base = Date.parse('2026-06-17T12:00:00.000Z');

    it('returns undefined for a permanent or unknown preset', () => {
        expect(expiresAtFromPreset('never', base)).toBeUndefined();
        expect(expiresAtFromPreset('bogus', base)).toBeUndefined();
    });

    it('resolves duration presets to an ISO timestamp from now', () => {
        expect(expiresAtFromPreset('1h', base)).toBe('2026-06-17T13:00:00.000Z');
        expect(expiresAtFromPreset('8h', base)).toBe('2026-06-17T20:00:00.000Z');
        expect(expiresAtFromPreset('24h', base)).toBe('2026-06-18T12:00:00.000Z');
        expect(expiresAtFromPreset('7d', base)).toBe('2026-06-24T12:00:00.000Z');
    });

    it('every non-permanent option resolves (no orphaned labels)', () => {
        for (const opt of EXPIRY_OPTIONS) {
            if (opt.value === 'never') continue;
            expect(expiresAtFromPreset(opt.value, base), opt.value).toBeDefined();
        }
    });
});

describe('formatRemaining', () => {
    const now = Date.parse('2026-06-17T12:00:00.000Z');
    const at = (iso: string) => formatRemaining(iso, now);

    it('renders days/hours/minutes buckets', () => {
        expect(at('2026-06-20T12:00:00.000Z')).toBe('expires in 3d');
        expect(at('2026-06-17T17:00:00.000Z')).toBe('expires in 5h');
        expect(at('2026-06-17T12:30:00.000Z')).toBe('expires in 30m');
    });

    it('handles imminent and past expiries', () => {
        expect(at('2026-06-17T12:00:30.000Z')).toBe('expires soon');
        expect(at('2026-06-17T11:00:00.000Z')).toBe('expired');
    });

    it('returns empty for an unparseable timestamp', () => {
        expect(at('not-a-date')).toBe('');
    });
});
