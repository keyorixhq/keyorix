import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import {
    cn,
    maskSensitiveData,
    sanitizeInput,
    isValidEmail,
    formatRelativeTime,
    generateId,
    debounce,
    throttle,
} from '../index';

describe('cn', () => {
    it('joins truthy class names and drops falsy ones', () => {
        expect(cn('a', 'b')).toBe('a b');
        expect(cn('a', false, null, undefined, 'b')).toBe('a b');
        expect(cn(false, null, undefined)).toBe('');
    });
});

describe('maskSensitiveData', () => {
    it('keeps the first N chars and masks the rest', () => {
        expect(maskSensitiveData('secretvalue')).toBe('secr' + '*'.repeat('secretvalue'.length - 4));
        expect(maskSensitiveData('abcdefgh', 2)).toBe('ab******');
    });

    it('fully masks values no longer than the visible window', () => {
        expect(maskSensitiveData('abc')).toBe('***');
        expect(maskSensitiveData('abcd')).toBe('****');
    });
});

describe('sanitizeInput', () => {
    it('escapes HTML to prevent injection', () => {
        expect(sanitizeInput('<b>x</b>')).toBe('&lt;b&gt;x&lt;/b&gt;');
        expect(sanitizeInput('<script>alert(1)</script>')).toBe('&lt;script&gt;alert(1)&lt;/script&gt;');
    });

    it('leaves plain text untouched', () => {
        expect(sanitizeInput('hello world')).toBe('hello world');
    });
});

describe('isValidEmail', () => {
    it('accepts well-formed addresses', () => {
        expect(isValidEmail('user@example.com')).toBe(true);
        expect(isValidEmail('a.b+c@sub.domain.io')).toBe(true);
    });

    it('rejects malformed addresses', () => {
        expect(isValidEmail('nope')).toBe(false);
        expect(isValidEmail('user@host')).toBe(false); // no TLD dot
        expect(isValidEmail('user @example.com')).toBe(false); // space
        expect(isValidEmail('')).toBe(false);
    });
});

describe('formatRelativeTime', () => {
    it('buckets by elapsed time', () => {
        const ago = (ms: number) => new Date(Date.now() - ms).toISOString();
        expect(formatRelativeTime(ago(5_000))).toBe('just now');
        expect(formatRelativeTime(ago(2 * 60_000))).toBe('2 minutes ago');
        expect(formatRelativeTime(ago(3 * 3_600_000))).toBe('3 hours ago');
        expect(formatRelativeTime(ago(2 * 86_400_000))).toBe('2 days ago');
    });
});

describe('generateId', () => {
    it('returns a short alphanumeric id', () => {
        const id = generateId();
        expect(typeof id).toBe('string');
        expect(id.length).toBeLessThanOrEqual(9);
        expect(id).toMatch(/^[a-z0-9]*$/);
    });
});

describe('debounce / throttle', () => {
    beforeEach(() => vi.useFakeTimers());
    afterEach(() => vi.useRealTimers());

    it('debounce collapses rapid calls into a single trailing call', () => {
        const fn = vi.fn();
        const debounced = debounce(fn, 100);
        debounced();
        debounced();
        debounced();
        expect(fn).not.toHaveBeenCalled();
        vi.advanceTimersByTime(100);
        expect(fn).toHaveBeenCalledTimes(1);
    });

    it('throttle fires immediately then suppresses until the window passes', () => {
        const fn = vi.fn();
        const throttled = throttle(fn, 100);
        throttled();
        throttled();
        throttled();
        expect(fn).toHaveBeenCalledTimes(1);
        vi.advanceTimersByTime(100);
        throttled();
        expect(fn).toHaveBeenCalledTimes(2);
    });
});
