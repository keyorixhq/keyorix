// INV-WEB-no-hardcoded-text-colour: a text colour in web/src comes from a theme token
// (`var(--success)`, `var(--danger)`, ...), not from a hex literal. The tokens in index.css are the only
// colours themeTokenContrast.test.ts proves reach WCAG AA in both themes; a hex literal is one nobody
// checked, and it does not switch with the theme (the green #16a34a that read 3.3:1 on white was
// invisible to the contrast guard because it bypassed the tokens).
//
// Parsed with the TypeScript compiler API over every non-test .ts/.tsx file under src/.
// Shapes recognised as a hard-coded text colour:
//   - an object property named `color` (identifier or string key) whose value holds a hex string
//     anywhere in it: `{ color: '#16a34a' }`, `color: isDark ? '#f87171' : '#dc2626'`, and a
//     `var(--token, #hex)` fallback, which hides an undefined token (`--text-danger` was never defined);
//   - a Tailwind arbitrary text colour in any string: `text-[#16a34a]`.
// Not recognised (this test does not see them): background, border, fill and stroke colours; a colour
// built at run time (`'#' + hex`, `rgb(...)`, a named colour such as `red`); a colour imported from
// another module; `color` set through `element.style.color = ...`; a hex that is not a text colour.
//
// Two rules:
//   1. The three status hexes the old badges used (BANNED) are not allowed in ANY string literal, not
//      only as a `color` (a hex held in a variable, `const activeRed = '#dc2626'`, is the same defect, and
//      a `var(--warning, #d97706)` fallback is dead code: the token is always defined).
//   2. Every other hard-coded text hex is a ratchet. KNOWN_HARDCODED lists the files that still have
//      some and how many; a count may not grow, and when it falls the entry has to be lowered or deleted
//      (the stale check), so the list only shrinks. A file that is not listed must have none.
import { readdirSync, readFileSync } from 'node:fs';
import { join, relative, resolve } from 'node:path';
import ts from 'typescript';
import { describe, expect, it } from 'vitest';

const webRoot = resolve(import.meta.dirname, '../../..');
const srcRoot = join(webRoot, 'src');

const BANNED = ['#16a34a', '#d97706', '#dc2626'];
const HEX = /#[0-9a-fA-F]{3,8}\b/g;
const TAILWIND_TEXT_HEX = /\btext-\[#[0-9a-fA-F]{3,8}\]/g;

// File -> number of hard-coded text hex literals still there (not counting BANNED, which must be 0).
const KNOWN_HARDCODED: Record<string, number> = {
    'src/components/ui/AbsoluteSessionExpiryWarning.tsx': 2,
    'src/components/ui/SessionTimeoutWarning.tsx': 3,
    'src/components/ui/TokenStatusBadge.tsx': 6,
    'src/features/account/MfaSection.tsx': 1,
    'src/features/admin/AccountStateBadge.tsx': 3,
    'src/features/admin/DeploymentHygieneSection.tsx': 4,
    'src/features/admin/MachineTokenHygieneSection.tsx': 4,
    'src/features/admin/OrgNameConformanceSection.tsx': 2,
    'src/features/admin/PATHygieneSection.tsx': 4,
    'src/features/admin/StaleAccountsSection.tsx': 6,
    'src/features/dynamic-secrets/LeasesPanel.tsx': 2,
    'src/features/invitations/InviteToProjectModal.tsx': 1,
    'src/features/invitations/PendingAccessRequestsSection.tsx': 2,
    'src/features/invitations/PendingOnboardingSection.tsx': 2,
    'src/features/invitations/ProjectInvitationsSection.tsx': 4,
    'src/features/machine-identities/MachineIdentitiesSection.tsx': 5,
    'src/features/notifications/NotificationBell.tsx': 1,
    'src/features/projects/EnvironmentPills.tsx': 1,
    'src/features/secrets/SecretDetailView.tsx': 3,
    'src/pages/admin/AdminPage.tsx': 2,
    'src/pages/admin/GroupsPage.tsx': 1,
    'src/pages/admin/UserDetailPage.tsx': 1,
    'src/pages/audit/AuditLogPage.tsx': 8,
    'src/pages/billing/BillingPage.tsx': 1,
    'src/pages/compliance/CompliancePage.tsx': 2,
    'src/pages/dashboard/DashboardPage.tsx': 6,
    'src/pages/profile/ProfilePage.tsx': 1,
    'src/pages/projects/EditProjectModal.tsx': 1,
    'src/pages/projects/ProjectAccessReviewCampaigns.tsx': 3,
    'src/pages/projects/ProjectAccessReviewTab.tsx': 1,
    'src/pages/projects/ProjectMembersTab.tsx': 1,
    'src/pages/projects/ProjectSettingsTab.tsx': 1,
    'src/pages/projects/ProjectsListPage.tsx': 3,
    'src/pages/secrets/RotationPoliciesPage.tsx': 14,
    'src/pages/secrets/SecretExpiryPage.tsx': 10,
    'src/pages/secrets/SecretsHealthPage.tsx': 18,
    'src/pages/secrets/SecretsListPage.tsx': 1,
    'src/pages/secrets/UsageAnalyticsPage.tsx': 2,
};

const isTestFile = (rel: string) =>
    /\.test\.tsx?$/.test(rel) || rel.split('/').includes('__tests__') || rel.startsWith('src/test/');

function sourceFiles(dir: string): string[] {
    const out: string[] = [];
    for (const entry of readdirSync(dir, { withFileTypes: true })) {
        const full = join(dir, entry.name);
        if (entry.isDirectory()) {
            out.push(...sourceFiles(full));
        } else if (/\.tsx?$/.test(entry.name) && !entry.name.endsWith('.d.ts')) {
            const rel = relative(webRoot, full).split('\\').join('/');
            if (!isTestFile(rel)) out.push(rel);
        }
    }
    return out;
}

const parse = (fileName: string, text: string) =>
    ts.createSourceFile(
        fileName,
        text,
        ts.ScriptTarget.Latest,
        true,
        fileName.endsWith('x') ? ts.ScriptKind.TSX : ts.ScriptKind.TS
    );

const isStringPart = (n: ts.Node): n is ts.StringLiteralLike | ts.TemplateHead | ts.TemplateMiddle | ts.TemplateTail =>
    ts.isStringLiteralLike(n) || ts.isTemplateHead(n) || ts.isTemplateMiddle(n) || ts.isTemplateTail(n);

// Every BANNED hex that appears in any string literal of `text`, lower-cased.
export function bannedHexes(fileName: string, text: string): string[] {
    const hits: string[] = [];
    const visit = (n: ts.Node) => {
        if (isStringPart(n)) {
            for (const m of n.text.matchAll(HEX))
                if (BANNED.includes(m[0].toLowerCase())) hits.push(m[0].toLowerCase());
        }
        ts.forEachChild(n, visit);
    };
    visit(parse(fileName, text));
    return hits;
}

// Every hex literal that is (part of) a text colour in `text`, as `#rrggbb` lower-cased.
export function hardcodedTextHexes(fileName: string, text: string): string[] {
    const sf = parse(fileName, text);
    const hits: string[] = [];
    const collectStrings = (n: ts.Node) => {
        if (isStringPart(n)) {
            for (const m of n.text.matchAll(HEX)) hits.push(m[0].toLowerCase());
        }
        ts.forEachChild(n, collectStrings);
    };
    const visit = (n: ts.Node) => {
        if (
            ts.isPropertyAssignment(n) &&
            (ts.isIdentifier(n.name) || ts.isStringLiteralLike(n.name)) &&
            n.name.text === 'color'
        ) {
            collectStrings(n.initializer);
        }
        if (isStringPart(n)) {
            for (const m of n.text.matchAll(TAILWIND_TEXT_HEX))
                hits.push(m[0].slice(m[0].indexOf('#'), -1).toLowerCase());
        }
        ts.forEachChild(n, visit);
    };
    visit(sf);
    return hits;
}

const scan = () => {
    const banned: Record<string, string[]> = {};
    const textHexes: Record<string, string[]> = {};
    for (const rel of sourceFiles(srcRoot)) {
        const text = readFileSync(join(webRoot, rel), 'utf8');
        const b = bannedHexes(rel, text);
        if (b.length > 0) banned[rel] = b;
        const t = hardcodedTextHexes(rel, text);
        if (t.length > 0) textHexes[rel] = t;
    }
    return { banned, textHexes };
};

describe('no hard-coded text colours (INV-WEB-no-hardcoded-text-colour)', () => {
    const found = scan();

    it('no file contains a status hex (#16a34a, #d97706, #dc2626): use --success / --warning / --danger', () => {
        const offenders = Object.entries(found.banned).map(([file, hexes]) => `${file}: ${hexes.join(', ')}`);
        expect(offenders, 'use var(--success), var(--warning) or var(--danger) instead').toEqual([]);
    });

    it('other hard-coded text hex literals only shrink (KNOWN_HARDCODED is a ceiling)', () => {
        const actual: Record<string, number> = {};
        for (const [file, hexes] of Object.entries(found.textHexes)) {
            const others = hexes.filter((h) => !BANNED.includes(h)).length;
            if (others > 0) actual[file] = others;
        }
        const grew = Object.entries(actual)
            .filter(([file, n]) => n > (KNOWN_HARDCODED[file] ?? 0))
            .map(([file, n]) => `${file}: ${n} (allowed ${KNOWN_HARDCODED[file] ?? 0})`);
        expect(grew, 'new hard-coded text colour: use a theme token from index.css').toEqual([]);

        const stale = Object.entries(KNOWN_HARDCODED)
            .filter(([file, n]) => (actual[file] ?? 0) < n)
            .map(([file, n]) => `${file}: ${actual[file] ?? 0} (listed ${n})`);
        expect(stale, 'lower or delete these KNOWN_HARDCODED entries').toEqual([]);
    });

    describe('calibration: the matchers see the shapes they claim to', () => {
        const banned = (src: string) => bannedHexes('x.tsx', src);
        it('a status hex held in a variable or a var() fallback is banned', () => {
            expect(banned(`const activeRed = isDark ? '#f87171' : '#DC2626';`)).toEqual(['#dc2626']);
            expect(banned(`<div style={{ borderColor: 'var(--warning, #d97706)' }} />`)).toEqual(['#d97706']);
        });
        it('other colours are not banned', () => {
            expect(banned(`const c = '#f87171'; const d = 'var(--danger)';`)).toEqual([]);
        });

        const hexes = (src: string) => hardcodedTextHexes('x.tsx', src);
        it('a plain style property', () => {
            expect(hexes(`const s = { color: '#16A34A' };`)).toEqual(['#16a34a']);
        });
        it('both arms of a ternary', () => {
            expect(hexes(`const s = { color: dark ? '#f87171' : '#dc2626' };`)).toEqual(['#f87171', '#dc2626']);
        });
        it('a var() fallback that hides an undefined token', () => {
            expect(hexes(`<div style={{ color: 'var(--text-danger, #dc2626)' }} />`)).toEqual(['#dc2626']);
        });
        it('a Tailwind arbitrary text colour', () => {
            expect(hexes(`<p className="text-sm text-[#d97706]" />`)).toEqual(['#d97706']);
        });
        it('leaves tokens, backgrounds and borders alone', () => {
            expect(
                hexes(
                    `const s = { color: 'var(--success)', backgroundColor: '#16a34a', borderColor: '#dc2626', fill: '#d97706' };`
                )
            ).toEqual([]);
        });
    });
});
