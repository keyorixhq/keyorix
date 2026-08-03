import { describe, it, expect } from 'vitest';
import { lastUsedLabel } from '../tokenUtils';

const daysAgo = (n: number) => new Date(Date.now() - n * 24 * 60 * 60 * 1000).toISOString();

describe('lastUsedLabel', () => {
    it('returns "never used" when there is no timestamp', () => {
        expect(lastUsedLabel(null)).toBe('never used');
        expect(lastUsedLabel(undefined)).toBe('never used');
        expect(lastUsedLabel('')).toBe('never used');
    });

    it('returns "used today" for a timestamp from earlier today', () => {
        expect(lastUsedLabel(daysAgo(0))).toBe('used today');
    });

    it('uses the singular "day" for exactly one day ago', () => {
        expect(lastUsedLabel(daysAgo(1))).toBe('used 1 day ago');
    });

    it('uses the plural "days" for more than one day ago', () => {
        expect(lastUsedLabel(daysAgo(5))).toBe('used 5 days ago');
    });
});
