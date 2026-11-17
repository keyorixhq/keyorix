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
        // Emitted through idioms the first extractor missed: a lower-case
        // event constant, a lower-case audit helper, an identifier argument.
        expect(emitted.has('system.audit_chain_verification_failed')).toBe(true);
        expect(emitted.has('admin.reset_mfa')).toBe(true);
        expect(emitted.has('access_request.approved')).toBe(true);
        expect(emitted.has('machine_identity.oidc_bound')).toBe(true);
        // SAML-TAILS-1: an SSO login whose session could not be created is audited by
        // internal/core/sso.go under a named constant. Pinned here so a refactor of the
        // extractor cannot drop it, and the label assertion below then covers it.
        expect(emitted.has('auth.sso_login_session_failed')).toBe(true);
        expect(EVENT_LABELS['auth.sso_login_session_failed']).toBeTruthy();
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
        expect(extractFromSource('/* c.writeAuditEvent(ctx, "area.fake", nil)\n EventX = "area.fake2" */').size).toBe(
            0
        );
    });

    it.each([
        ['lower-case audit helper', 'c.auditProjectScopedOn(ctx, tgt, "a.b", 1, 2, "d")', 'a.b'],
        ['lower-case event constant', 'const eventAdminResetMFA = "a.reset"', 'a.reset'],
        ['constant with Event as a suffix', 'auditSealEvent = "a.seal"', 'a.seal'],
        ['recordAdminAction writer', 'recordAdminAction(cfg, "a.admin", "d", true)', 'a.admin'],
        ['setAccountState writer', 'c.setAccountState(ctx, id, "a.state", actor)', 'a.state'],
        ['logMachineEvent writer', 'c.logMachineEvent(ctx, "a.machine", m, actorID)', 'a.machine'],
        ['writer call split over lines', 'c.writeAuditEventFull(ctx,\n\t\t"a.multiline", &aid)', 'a.multiline'],
        ['dot prefix + word', 'action := "rotated"\nrecordAdminAction(cfg, "a.key."+action, d, true)', 'a.key.rotated'],
    ])('extractor finds a %s', (_name, src, want) => {
        expect(extractFromSource(src).has(want)).toBe(true);
    });

    it('extractor resolves an identifier argument against declarations it is given', () => {
        const decls = new Map([['actionApproved', 'a.approved']]);
        const src = 'c.writeAuditEvent(ctx, actionApproved, nil)\nx := AuditEvent{EventType: actionApproved}';
        expect([...extractFromSource(src, decls)]).toEqual(['a.approved']);
    });

    it('extractor skips notification constants (not audit events)', () => {
        expect(extractFromSource('NotificationEventSecretExpiring = "secret.expiring"').size).toBe(0);
    });
});
