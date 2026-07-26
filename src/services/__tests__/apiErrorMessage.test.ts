import { describe, it, expect } from 'vitest';
import { AxiosError } from 'axios';
import { apiErrorMessage } from '../client';

// Build an AxiosError carrying a server error body { error, message, code }.
function axiosErr(data: unknown): AxiosError {
    const e = new AxiosError('Request failed with status code 400');
    // @ts-expect-error minimal response shape for the test
    e.response = { data };
    return e;
}

describe('apiErrorMessage', () => {
    it('prefers the server message (the human reason) over the error type', () => {
        const err = axiosErr({
            error: 'ValidationError',
            message: 'secret value is a known weak or placeholder value',
            code: 400,
        });
        expect(apiErrorMessage(err)).toBe('secret value is a known weak or placeholder value');
    });

    it('falls back to the error type when no message', () => {
        expect(apiErrorMessage(axiosErr({ error: 'Forbidden', code: 403 }))).toBe('Forbidden');
    });

    it('falls back to the axios message when no response body fields', () => {
        expect(apiErrorMessage(axiosErr(undefined))).toBe('Request failed with status code 400');
    });

    it('handles a plain Error', () => {
        expect(apiErrorMessage(new Error('boom'))).toBe('boom');
    });

    it('handles a non-error value', () => {
        expect(apiErrorMessage('nope')).toBe('An unexpected error occurred');
    });
});
