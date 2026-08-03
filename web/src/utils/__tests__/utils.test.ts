import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import {
    cn,
    maskSensitiveData,
    sanitizeInput,
    isValidEmail,
    formatRelativeTime,
    formatDateShort,
    generateId,
    generateSecret,
    triggerBlobDownload,
    copyToClipboard,
    debounce,
    throttle,
    storage,
    url,
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
    it('delegates to crypto.randomUUID and returns a string', () => {
        const id = generateId();
        expect(typeof id).toBe('string');
        expect(id.length).toBeGreaterThan(0);
        expect(crypto.randomUUID).toHaveBeenCalled();
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

describe('formatDateShort', () => {
    it('returns a dash for null/undefined/empty values', () => {
        expect(formatDateShort(null)).toBe('—');
        expect(formatDateShort(undefined)).toBe('—');
        expect(formatDateShort('')).toBe('—');
    });

    it('formats a valid ISO string as a short date', () => {
        expect(formatDateShort('2026-03-15T00:00:00Z')).toMatch(/2026/);
    });

    it('falls back to the raw input when formatting throws', () => {
        const spy = vi.spyOn(Date.prototype, 'toLocaleDateString').mockImplementation(() => {
            throw new Error('formatting blew up');
        });
        try {
            expect(formatDateShort('2026-03-15T00:00:00Z')).toBe('2026-03-15T00:00:00Z');
        } finally {
            spy.mockRestore();
        }
    });
});

describe('generateSecret', () => {
    it('delegates to crypto.getRandomValues and returns a 32-character URL-safe string', () => {
        const secret = generateSecret();
        expect(secret).toHaveLength(32);
        expect(secret).toMatch(/^[A-Za-z0-9_-]{32}$/);
        expect(crypto.getRandomValues).toHaveBeenCalled();
    });
});

describe('triggerBlobDownload', () => {
    it('creates an object URL, clicks a synthetic anchor, then revokes the URL', () => {
        const createObjectURLSpy = vi.spyOn(URL, 'createObjectURL').mockReturnValue('blob:mock-url');
        const revokeObjectURLSpy = vi.spyOn(URL, 'revokeObjectURL').mockImplementation(() => {});
        const clickSpy = vi.spyOn(HTMLAnchorElement.prototype, 'click').mockImplementation(() => {});

        const blob = new Blob(['csv,data'], { type: 'text/csv' });
        triggerBlobDownload(blob, 'export.csv');

        expect(createObjectURLSpy).toHaveBeenCalledWith(blob);
        expect(clickSpy).toHaveBeenCalledTimes(1);
        expect(revokeObjectURLSpy).toHaveBeenCalledWith('blob:mock-url');

        createObjectURLSpy.mockRestore();
        revokeObjectURLSpy.mockRestore();
        clickSpy.mockRestore();
    });
});

describe('copyToClipboard', () => {
    beforeEach(() => vi.useFakeTimers());
    afterEach(() => {
        vi.useRealTimers();
        vi.restoreAllMocks();
    });

    it('copies the text, then clears the clipboard after the timeout', async () => {
        const writeTextSpy = vi
            .spyOn(navigator.clipboard, 'writeText')
            .mockResolvedValueOnce(undefined) // initial copy
            .mockResolvedValueOnce(undefined); // scheduled clear

        await copyToClipboard('super-secret', 1000);
        expect(writeTextSpy).toHaveBeenNthCalledWith(1, 'super-secret');

        await vi.advanceTimersByTimeAsync(1000);
        expect(writeTextSpy).toHaveBeenNthCalledWith(2, '');
    });

    it('logs a warning (without throwing) when clearing the clipboard after the timeout fails', async () => {
        const warnSpy = vi.spyOn(console, 'warn').mockImplementation(() => {});
        vi.spyOn(navigator.clipboard, 'writeText')
            .mockResolvedValueOnce(undefined) // initial copy succeeds
            .mockRejectedValueOnce(new Error('clear failed')); // scheduled clear fails

        await copyToClipboard('super-secret', 1000);
        await vi.advanceTimersByTimeAsync(1000);

        expect(warnSpy).toHaveBeenCalledWith('Failed to clear clipboard:', expect.any(Error));
    });

    it('throws (wrapping the cause) when the initial copy itself fails', async () => {
        const errorSpy = vi.spyOn(console, 'error').mockImplementation(() => {});
        const cause = new Error('permission denied');
        vi.spyOn(navigator.clipboard, 'writeText').mockRejectedValueOnce(cause);

        await expect(copyToClipboard('super-secret', 1000)).rejects.toThrow('Failed to copy to clipboard');
        expect(errorSpy).toHaveBeenCalledWith('Failed to copy to clipboard:', cause);
    });
});

describe('storage', () => {
    afterEach(() => vi.restoreAllMocks());

    it('get parses and returns a stored JSON value', () => {
        vi.spyOn(localStorage, 'getItem').mockReturnValueOnce(JSON.stringify({ a: 1 }));
        expect(storage.get('key')).toEqual({ a: 1 });
    });

    it('get falls back to the default (or null) when nothing is stored', () => {
        vi.spyOn(localStorage, 'getItem').mockReturnValueOnce(null);
        expect(storage.get('missing')).toBeNull();
        vi.spyOn(localStorage, 'getItem').mockReturnValueOnce(null);
        expect(storage.get('missing', 'fallback')).toBe('fallback');
    });

    it('get returns the default (or null) and logs when reading/parsing throws', () => {
        const errorSpy = vi.spyOn(console, 'error').mockImplementation(() => {});
        vi.spyOn(localStorage, 'getItem').mockReturnValueOnce('{not valid json');
        expect(storage.get('bad')).toBeNull();
        expect(errorSpy).toHaveBeenCalledWith(
            expect.stringContaining('Error reading from localStorage key "bad"'),
            expect.any(Error)
        );

        vi.spyOn(localStorage, 'getItem').mockReturnValueOnce('{not valid json');
        expect(storage.get('bad', 'fallback')).toBe('fallback');
    });

    it('set writes the JSON-encoded value', () => {
        const setItemSpy = vi.spyOn(localStorage, 'setItem').mockImplementation(() => {});
        storage.set('key', { a: 1 });
        expect(setItemSpy).toHaveBeenCalledWith('key', JSON.stringify({ a: 1 }));
    });

    it('set logs (without throwing) when writing fails', () => {
        const errorSpy = vi.spyOn(console, 'error').mockImplementation(() => {});
        vi.spyOn(localStorage, 'setItem').mockImplementationOnce(() => {
            throw new Error('quota exceeded');
        });
        expect(() => storage.set('key', 'value')).not.toThrow();
        expect(errorSpy).toHaveBeenCalledWith(
            expect.stringContaining('Error writing to localStorage key "key"'),
            expect.any(Error)
        );
    });

    it('remove deletes the key', () => {
        const removeItemSpy = vi.spyOn(localStorage, 'removeItem').mockImplementation(() => {});
        storage.remove('key');
        expect(removeItemSpy).toHaveBeenCalledWith('key');
    });

    it('remove logs (without throwing) when removal fails', () => {
        const errorSpy = vi.spyOn(console, 'error').mockImplementation(() => {});
        vi.spyOn(localStorage, 'removeItem').mockImplementationOnce(() => {
            throw new Error('boom');
        });
        expect(() => storage.remove('key')).not.toThrow();
        expect(errorSpy).toHaveBeenCalledWith(
            expect.stringContaining('Error removing localStorage key "key"'),
            expect.any(Error)
        );
    });

    it('clear wipes all storage', () => {
        const clearSpy = vi.spyOn(localStorage, 'clear').mockImplementation(() => {});
        storage.clear();
        expect(clearSpy).toHaveBeenCalledOnce();
    });

    it('clear logs (without throwing) when clearing fails', () => {
        const errorSpy = vi.spyOn(console, 'error').mockImplementation(() => {});
        vi.spyOn(localStorage, 'clear').mockImplementationOnce(() => {
            throw new Error('boom');
        });
        expect(() => storage.clear()).not.toThrow();
        expect(errorSpy).toHaveBeenCalledWith('Error clearing localStorage:', expect.any(Error));
    });
});

describe('url', () => {
    describe('buildUrl', () => {
        it('sets query params for defined values and skips undefined/null ones', () => {
            const built = url.buildUrl('https://example.com/path', {
                keep: 'yes',
                zero: 0,
                flag: true,
                dropped: undefined as unknown as string,
                alsoDropped: null as unknown as string,
            });

            const parsed = new URL(built);
            expect(parsed.searchParams.get('keep')).toBe('yes');
            expect(parsed.searchParams.get('zero')).toBe('0');
            expect(parsed.searchParams.get('flag')).toBe('true');
            expect(parsed.searchParams.has('dropped')).toBe(false);
            expect(parsed.searchParams.has('alsoDropped')).toBe(false);
        });
    });

    describe('getQueryParams', () => {
        it('parses the current window location search string into a Map', () => {
            window.history.pushState({}, '', '/somewhere?foo=bar&baz=qux');
            const params = url.getQueryParams();
            expect(params).toBeInstanceOf(Map);
            expect(params.get('foo')).toBe('bar');
            expect(params.get('baz')).toBe('qux');
        });

        it('returns an empty Map when there is no query string', () => {
            window.history.pushState({}, '', '/somewhere');
            expect(url.getQueryParams().size).toBe(0);
        });
    });
});
