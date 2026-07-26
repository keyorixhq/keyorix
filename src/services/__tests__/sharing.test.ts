import { describe, it, expect } from 'vitest';
import { buildUpdateShareBody } from '../sharing';

// buildUpdateShareBody sends only the requested change so a permission-only edit
// never disturbs the share's existing expiry (the server preserves it).
describe('buildUpdateShareBody', () => {
    it('sends only the permission when neither expiry field is set (preserve)', () => {
        expect(buildUpdateShareBody({ permission: 'write' })).toEqual({ permission: 'write' });
    });

    it('sends clear_expiry to make a share permanent', () => {
        expect(buildUpdateShareBody({ permission: 'read', clearExpiry: true })).toEqual({
            permission: 'read',
            clear_expiry: true,
        });
    });

    it('sends expires_at to set/extend the expiry', () => {
        const iso = '2026-07-01T00:00:00.000Z';
        expect(buildUpdateShareBody({ permission: 'read', expiresAt: iso })).toEqual({
            permission: 'read',
            expires_at: iso,
        });
    });

    it('prefers clear over a stale expiresAt when both somehow arrive', () => {
        const body = buildUpdateShareBody({
            permission: 'read',
            clearExpiry: true,
            expiresAt: '2026-07-01T00:00:00.000Z',
        });
        expect(body.clear_expiry).toBe(true);
        // both keys may be present; the server treats clear_expiry as authoritative.
        expect(body.permission).toBe('read');
    });
});
