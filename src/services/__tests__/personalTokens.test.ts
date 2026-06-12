import { describe, it, expect } from 'vitest';
import { buildCreateTokenBody } from '../personalTokens';

// buildCreateTokenBody applies the ADR-042 least-privilege rules when assembling
// the create-token payload from the My Account form state.
describe('buildCreateTokenBody', () => {
    it('omits scopes/project for a full-access token', () => {
        const body = buildCreateTokenBody({
            name: 'ci',
            limited: false,
            permissions: ['secrets.read'], // ignored when not limited
            extraPermissions: 'secrets.write',
            projectScope: 5,
        });
        expect(body).toEqual({ name: 'ci' });
    });

    it('trims the name and serialises expiry to ISO', () => {
        const body = buildCreateTokenBody({
            name: '  ci  ',
            expiresAt: '2026-12-31',
            limited: false,
            permissions: [],
        });
        expect(body.name).toBe('ci');
        expect(body.expires_at).toBe(new Date('2026-12-31').toISOString());
    });

    it('includes the selected permissions when limited', () => {
        const body = buildCreateTokenBody({
            name: 'reader',
            limited: true,
            permissions: ['secrets.read'],
        });
        expect(body.scopes).toEqual(['secrets.read']);
        expect(body.project_scope).toBeUndefined();
    });

    it('merges preset + advanced permissions, trims, dedupes, drops blanks', () => {
        const body = buildCreateTokenBody({
            name: 't',
            limited: true,
            permissions: ['secrets.read'],
            extraPermissions: 'secrets.read, rotation.write   secrets.* , ',
        });
        // secrets.read deduped; comma/whitespace/newline split; blanks removed.
        expect(body.scopes).toEqual(['secrets.read', 'rotation.write', 'secrets.*']);
    });

    it('includes a project confinement only when > 0', () => {
        expect(
            buildCreateTokenBody({ name: 't', limited: true, permissions: [], projectScope: 7 }).project_scope
        ).toBe(7);
        expect(
            buildCreateTokenBody({ name: 't', limited: true, permissions: ['secrets.read'], projectScope: 0 })
                .project_scope
        ).toBeUndefined();
    });

    it('omits the scopes key entirely when limited but nothing chosen (stays unrestricted)', () => {
        const body = buildCreateTokenBody({
            name: 't',
            limited: true,
            permissions: [],
            extraPermissions: '   ',
            projectScope: 0,
        });
        expect(body.scopes).toBeUndefined();
        expect(body.project_scope).toBeUndefined();
        expect(body).toEqual({ name: 't' });
    });
});
