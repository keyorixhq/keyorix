// Parity between the audit event types the server can emit (read from the Go
// sources as text by scripts/audit-actions.mjs) and the web label table. An
// emitted event with neither a label nor a reasoned entry in
// scripts/audit-intentionally-unlabelled.mjs fails here, so a new server event
// cannot reach the audit page, dashboard or compliance views as a raw name.
//
// Limits (also in the extractor header): events built at run time are invisible
// to the extractor, so this proves "no known literal is unlabelled".
import { describe, it, expect } from 'vitest';
import { EVENT_LABELS } from '../eventLabels';
// @ts-expect-error plain .mjs helper without type declarations
import { extractEmittedActions, extractFromSource } from '../../../scripts/audit-actions.mjs';
// @ts-expect-error plain .mjs data file without type declarations
import { INTENTIONALLY_UNLABELLED } from '../../../scripts/audit-intentionally-unlabelled.mjs';

const emitted: Map<string, string[]> = extractEmittedActions();
const unlabelled: Record<string, string> = INTENTIONALLY_UNLABELLED;

describe('audit event label parity', () => {
    it('finds the server events at all (the extractor is not vacuous)', () => {
        expect(emitted.size).toBeGreaterThan(100);
        expect(emitted.has('auth.sso_login')).toBe(true);
        expect(emitted.has('secret.created')).toBe(true);
    });

    it('every emitted event has a label or an intentionallyUnlabelled entry', () => {
        const missing = [...emitted.keys()].filter((a) => !EVENT_LABELS[a] && !(a in unlabelled));
        expect(
            missing.map((a) => `${a} (${emitted.get(a)?.join(', ')})`),
            'add a label in web/src/utils/eventLabels.ts, or an entry with a reason in web/scripts/audit-intentionally-unlabelled.mjs'
        ).toEqual([]);
    });

    it('every intentionallyUnlabelled entry carries a reason and is still emitted and unlabelled', () => {
        for (const [action, reason] of Object.entries(unlabelled)) {
            expect(reason.trim().length, `${action}: reason`).toBeGreaterThan(10);
            expect(emitted.has(action), `${action} is no longer emitted: drop the entry`).toBe(true);
            expect(EVENT_LABELS[action], `${action} now has a label: drop the entry`).toBeUndefined();
        }
    });

    it('RED: an unlabelled synthetic event would be reported', () => {
        const synthetic = extractFromSource('const EventBogus = "bogus.never_labelled"');
        expect(synthetic.has('bogus.never_labelled')).toBe(true);
        expect(EVENT_LABELS['bogus.never_labelled']).toBeUndefined();
        expect('bogus.never_labelled' in unlabelled).toBe(false);
    });

    it('extractor expands a prefix + state concatenation', () => {
        const src = 'state := "enabled"\nif x { state = "disabled" }\nc.writeAuditEvent(ctx, "area.thing_"+state, nil)';
        expect([...extractFromSource(src)].sort()).toEqual(['area.thing_disabled', 'area.thing_enabled']);
    });

    it('extractor ignores commented-out examples', () => {
        expect(extractFromSource('// c.writeAuditEvent(ctx, "area.fake", nil)').size).toBe(0);
    });
});
