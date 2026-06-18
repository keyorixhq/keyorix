import { describe, it, expect } from 'vitest';
import { isStaleMachineIdentity, MachineIdentity } from '../machineIdentities';

const now = Date.UTC(2026, 5, 18, 12, 0, 0); // 2026-06-18
const daysAgo = (d: number) => new Date(now - d * 24 * 60 * 60 * 1000).toISOString();

const mk = (over: Partial<MachineIdentity>): MachineIdentity => ({
    id: 1, projectId: 1, name: 'ci', identityType: 'ci', state: 'active',
    description: '', createdBy: 1, classification: '', ...over,
});

describe('isStaleMachineIdentity', () => {
    it('flags an active identity last seen beyond the window', () => {
        expect(isStaleMachineIdentity(mk({ lastSeenAt: daysAgo(120) }), now)).toBe(true);
    });

    it('does not flag one seen recently', () => {
        expect(isStaleMachineIdentity(mk({ lastSeenAt: daysAgo(10) }), now)).toBe(false);
    });

    it('uses creation time when never seen (brand-new is not stale)', () => {
        expect(isStaleMachineIdentity(mk({ createdAt: daysAgo(5) }), now)).toBe(false);
        expect(isStaleMachineIdentity(mk({ createdAt: daysAgo(200) }), now)).toBe(true);
    });

    it('never flags non-active identities', () => {
        expect(isStaleMachineIdentity(mk({ state: 'suspended', lastSeenAt: daysAgo(300) }), now)).toBe(false);
        expect(isStaleMachineIdentity(mk({ state: 'revoked', lastSeenAt: daysAgo(300) }), now)).toBe(false);
    });

    it('does not flag when there is no timestamp at all', () => {
        expect(isStaleMachineIdentity(mk({}), now)).toBe(false);
    });
});
