// refusalMessage.test.ts -- DEMO-UI-1: a refused action shows the server's reason, never
// axios's own "Request failed with status code 403". Two layers:
//
//  1. humanizeRefusal (the response interceptor's last step) rewrites that generic text on
//     the error itself, so every `error.message` a dialog renders is already a reason.
//  2. A source ratchet over the failure alerts: a failure Alert whose message is a fixed
//     sentence hides the server's reason. New ones must call apiErrorMessage; the ones
//     below are admin-only/legacy screens and are listed so the list can only shrink.
//
// SHARE-2's guard (apiErrorMessageGuard.test.ts, #3012) recognises the
// `x.error instanceof Error ? x.error.message` shape; this one covers the static-sentence
// shape and the interceptor. They do not overlap.
import { readdirSync, readFileSync, statSync } from 'node:fs';
import { join, relative, resolve } from 'node:path';
import { describe, expect, it } from 'vitest';
import { AxiosError } from 'axios';
import { humanizeRefusal, NO_PERMISSION_MESSAGE, apiErrorMessage } from '../client';

function refused(status: number, data: unknown): AxiosError {
    const e = new AxiosError(`Request failed with status code ${status}`);
    e.response = { status, data } as AxiosError['response'];
    return e;
}

describe('humanizeRefusal', () => {
    it('keeps the server reason when the body has one', () => {
        const e = refused(403, { error: 'Forbidden', message: 'You need write access to rotate this secret.' });
        humanizeRefusal(e);
        expect(e.message).toBe('You need write access to rotate this secret.');
        expect(apiErrorMessage(e)).toBe('You need write access to rotate this secret.');
    });

    it('says what is true for a bare 403: not permitted, no reason given', () => {
        const e = refused(403, undefined);
        humanizeRefusal(e);
        expect(e.message).toBe(NO_PERMISSION_MESSAGE);
        expect(e.message).not.toMatch(/status code/);
        expect(apiErrorMessage(e)).toBe(NO_PERMISSION_MESSAGE);
    });

    it('leaves a message that is already specific, and non-403 bodiless errors, alone', () => {
        const specific = new AxiosError('timeout of 10000ms exceeded');
        humanizeRefusal(specific);
        expect(specific.message).toBe('timeout of 10000ms exceeded');

        const e404 = refused(404, undefined);
        humanizeRefusal(e404);
        expect(e404.message).toBe('Request failed with status code 404');
    });
});

const SRC = resolve(import.meta.dirname, '../..');
const sourceFiles = (dir: string): string[] =>
    readdirSync(dir).flatMap((name) => {
        const path = join(dir, name);
        if (statSync(path).isDirectory()) return name === '__tests__' || name === 'test' ? [] : sourceFiles(path);
        return /\.tsx$/.test(name) ? [path] : [];
    });

// <Alert ... title="Failed to ..." message="a fixed sentence"> -- a failure alert that
// does not look at the error. `Rotation failed` is the same shape.
const STATIC_FAILURE_ALERT = /title="((?:Failed to|Rotation failed)[^"]*)"\s*message="([^"]*)"/g;

// Known static failure alerts, "file :: title". Each one is a screen where a plain-language
// sentence is acceptable today (list/admin pages the walk did not refuse, or whose error is
// not an API refusal). Do not add to this list: call apiErrorMessage(error, fallback).
const KNOWN_STATIC = new Set([
    'pages/secrets/SecretExpiryPage.tsx :: Failed to load secrets',
    'pages/admin/UserDetailPage.tsx :: Failed to load user',
    'pages/secrets/SecretsHealthPage.tsx :: Failed to load health data',
    'pages/secrets/RotationPoliciesPage.tsx :: Failed to load rotation policies',
    'pages/admin/MachineIdentitiesPage.tsx :: Failed to load machine identities',
    'pages/admin/AdminPage.tsx :: Failed to load users',
    'pages/projects/ProjectSettingsTab.tsx :: Failed to update',
]);

describe('failure alerts show the server reason (DEMO-UI-1)', () => {
    const found = () =>
        sourceFiles(SRC).flatMap((file) =>
            [...readFileSync(file, 'utf8').matchAll(STATIC_FAILURE_ALERT)].map(
                (m) => `${relative(SRC, file)} :: ${m[1]}`
            )
        );

    it('scans a real tree (not vacuous) and recognises the shape', () => {
        expect(sourceFiles(SRC).length).toBeGreaterThan(100);
        const sample = `<Alert type="error" title="Failed to load audit log" message="Please try again." />`;
        expect([...sample.matchAll(STATIC_FAILURE_ALERT)]).toHaveLength(1);
        const fixed = `<Alert title="Failed to load audit log" message={apiErrorMessage(error, 'x')} />`;
        expect([...fixed.matchAll(STATIC_FAILURE_ALERT)]).toHaveLength(0);
    });

    it('the screens a read-only user walks (audit, secrets, rotate, value, members) call apiErrorMessage', () => {
        const hits = found().filter((f) =>
            /AuditLogPage|SecretsListPage|SecretDetailView|ProjectSecretsTab|ProjectMembersTab/.test(f)
        );
        expect(hits).toEqual([]);
    });

    it('no new fixed-sentence failure alert appears, and none listed above has been fixed without removing it', () => {
        const actual = new Set(found());
        const added = [...actual].filter((f) => !KNOWN_STATIC.has(f));
        const stale = [...KNOWN_STATIC].filter((f) => !actual.has(f));
        expect({ added, stale }).toEqual({ added: [], stale: [] });
    });
});
