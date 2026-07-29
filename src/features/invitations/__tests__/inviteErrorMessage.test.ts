import { describe, it, expect } from 'vitest';
import { inviteErrorMessage } from '../inviteErrorMessage';

describe('inviteErrorMessage', () => {
    it('replaces a domain-not-allowed rejection with actionable copy', () => {
        const err = { response: { data: { message: 'email domain is not on the allowlist' } } };
        expect(inviteErrorMessage(err, 'fallback')).toBe(
            "This email domain isn't on the allowlist. Contact a system admin to update the allowlist, or use an allowed domain email."
        );
    });

    it('matches case-insensitively and via the data.error field', () => {
        const err = { response: { data: { error: 'Email Domain Is NOT ON THE ALLOWLIST' } } };
        expect(inviteErrorMessage(err, 'fallback')).toContain("isn't on the allowlist");
    });

    it('passes through any other backend message unchanged', () => {
        const err = { response: { data: { message: 'unknown role "bogus"' } } };
        expect(inviteErrorMessage(err, 'fallback')).toBe('unknown role "bogus"');
    });

    it('falls back when there is no response body', () => {
        expect(inviteErrorMessage({}, 'Failed to send invitation.')).toBe('Failed to send invitation.');
    });
});
