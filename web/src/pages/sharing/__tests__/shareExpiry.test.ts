import { describe, it, expect } from 'vitest';
import { shareExpiry } from '../SharingManagementPage';

describe('shareExpiry', () => {
    const now = Date.UTC(2026, 5, 17, 12, 0, 0); // 2026-06-17T12:00:00Z

    it('labels a share with no expiry as permanent', () => {
        expect(shareExpiry(undefined, now)).toMatchObject({ label: 'Permanent' });
        expect(shareExpiry('not-a-date', now).label).toBe('Permanent');
    });

    it('labels a past expiry as expired', () => {
        const past = new Date(now - 60_000).toISOString();
        const e = shareExpiry(past, now);
        expect(e.label).toBe('Expired');
        expect(e.className).toContain('red');
    });

    it('renders a short countdown for a future expiry', () => {
        expect(shareExpiry(new Date(now + 30 * 60_000).toISOString(), now).label).toBe('in 30m');
        expect(shareExpiry(new Date(now + 5 * 60 * 60_000).toISOString(), now).label).toBe('in 5h');
        expect(shareExpiry(new Date(now + 3 * 24 * 60 * 60_000).toISOString(), now).label).toBe('in 3d');
    });

    it('never shows 0m for an imminent expiry', () => {
        expect(shareExpiry(new Date(now + 5_000).toISOString(), now).label).toBe('in 1m');
    });
});
