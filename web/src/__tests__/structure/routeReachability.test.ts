// INV-WEB-07 (#2532): the first repo-wide structural/completeness sweep in web/src.
// App.tsx's route table and the Sidebar's NAV are two hand-maintained lists of the same
// thing; nothing kept them in step. This derives both and checks them against each other:
//
//   1. every page route App.tsx declares is reachable from Sidebar NAV, or is in
//      ALLOWLIST with a stated reason (how it IS reached: an email link, a list row, a
//      header menu, ...);
//   2. every NAV href resolves to a declared page route (no dead sidebar links);
//   3. every redirect route's target resolves to a declared page route;
//   4. no ALLOWLIST entry is stale (undeclared, or now reachable from NAV anyway).
//
// How routes are enumerated: App.tsx is parsed with the TypeScript compiler API and
// every <Route> element is collected, at any nesting depth. `path` must be a string
// literal or a `ROUTES.X` member (resolved against the real ROUTES object); any other
// form FAILS the test rather than being skipped, so the enumeration cannot silently
// shrink. A route whose `element` contains a <Navigate> is a redirect (case 3), not a
// page — so an old URL kept alive as a redirect needs no allowlist entry.
//
// Not covered: routes nested inside page components (e.g. ProjectDetailPage's own tab
// <Routes>), whether a NAV leaf is hidden from the current user's role (adminOnly), and
// links from inside pages other than those named in ALLOWLIST reasons.
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import ts from 'typescript';
import { matchPath } from 'react-router';
import { describe, expect, it } from 'vitest';
import { ROUTES } from '../../constants';
import { NAV } from '../../components/layout/Sidebar';

const appPath = resolve(import.meta.dirname, '../../App.tsx');

const ALLOWLIST: Record<string, string> = {
    '/*': 'authenticated layout container — wraps every page route below, not a page itself',
    '*': 'not-found catch-all — reached by any unknown URL',
    '/login': 'public entry point; ProtectedRoute redirects here',
    '/auth/setup/:token': 'single-use setup link delivered by email (ADR-028)',
    '/auth/sso/complete': 'SSO identity-provider redirect target',
    '/profile': 'Header user menu (Header.tsx) and the RequirePasswordChange redirect',
    '/projects/:id/*': 'project rows on /projects, the ProjectSwitcher, and Cmd-K search',
    '/admin/users/:id': 'user rows on /admin/users',
    '/admin': 'alias of /admin/users (same AdminPage) kept for old links',
};

interface DeclaredRoute {
    path: string;
    line: number;
    redirectTo?: string;
}

function tagName(n: ts.JsxOpeningLikeElement): string {
    return n.tagName.getText();
}

function attr(n: ts.JsxOpeningLikeElement, name: string): ts.JsxAttribute | undefined {
    return n.attributes.properties.find((p): p is ts.JsxAttribute => ts.isJsxAttribute(p) && p.name.getText() === name);
}

function resolvePathValue(a: ts.JsxAttribute, sf: ts.SourceFile): string {
    const init = a.initializer;
    if (init && ts.isStringLiteral(init)) return init.text;
    if (init && ts.isJsxExpression(init) && init.expression) {
        const e = init.expression;
        if (ts.isStringLiteralLike(e)) return e.text;
        if (ts.isPropertyAccessExpression(e) && e.expression.getText(sf) === 'ROUTES') {
            const v = (ROUTES as Record<string, unknown>)[e.name.text];
            if (typeof v === 'string') return v;
        }
    }
    throw new Error(`App.tsx: unrecognised <Route path> form \`${a.getText(sf)}\` — teach this sweep about it`);
}

function findNavigateTarget(node: ts.Node, sf: ts.SourceFile): string | undefined {
    let target: string | undefined;
    const visit = (n: ts.Node) => {
        // Stop at a nested route table: a layout route's element contains its children's
        // elements, and a child redirect does not make the layout itself a redirect.
        if (ts.isJsxElement(n) && ['Routes', 'Route'].includes(tagName(n.openingElement))) return;
        if (ts.isJsxSelfClosingElement(n) && tagName(n) === 'Route') return;
        if ((ts.isJsxSelfClosingElement(n) || ts.isJsxOpeningElement(n)) && tagName(n) === 'Navigate') {
            const to = attr(n, 'to');
            if (!to) throw new Error(`App.tsx: <Navigate> without a \`to\` at ${n.getText(sf)}`);
            target = resolvePathValue(to, sf);
        }
        if (!target) ts.forEachChild(n, visit);
    };
    visit(node);
    return target;
}

function declaredRoutes(): DeclaredRoute[] {
    const text = readFileSync(appPath, 'utf8');
    const sf = ts.createSourceFile(appPath, text, ts.ScriptTarget.Latest, true, ts.ScriptKind.TSX);
    const routes: DeclaredRoute[] = [];
    const visit = (n: ts.Node) => {
        if ((ts.isJsxSelfClosingElement(n) || ts.isJsxOpeningElement(n)) && tagName(n) === 'Route') {
            const line = sf.getLineAndCharacterOfPosition(n.getStart(sf)).line + 1;
            const p = attr(n, 'path');
            if (!p) throw new Error(`App.tsx:${line}: <Route> without a path (index/layout route) — classify it here`);
            const el = attr(n, 'element');
            const redirectTo = el ? findNavigateTarget(el, sf) : undefined;
            routes.push({ path: resolvePathValue(p, sf), line, ...(redirectTo ? { redirectTo } : {}) });
        }
        ts.forEachChild(n, visit);
    };
    visit(sf);
    return routes;
}

function navHrefs(): string[] {
    return NAV.flatMap((item) => (item.kind === 'group' ? item.children : [item]))
        .filter((leaf) => !leaf.soon)
        .map((leaf) => leaf.href);
}

const isContainer = (path: string) => path === '/*' || path === '*';
const matches = (routePath: string, href: string) => matchPath({ path: routePath, end: true }, href) !== null;

describe('INV-WEB-07: App.tsx routes and Sidebar navigation agree', () => {
    const routes = declaredRoutes();
    const pages = routes.filter((r) => !r.redirectTo);
    const redirects = routes.filter((r) => r.redirectTo);
    const hrefs = navHrefs();

    it('enumerated the real route table and nav (non-vacuity)', () => {
        expect(pages.length).toBeGreaterThan(25);
        expect(hrefs.length).toBeGreaterThan(20);
        expect(pages.map((r) => r.path)).toContain(ROUTES.DASHBOARD);
        expect(redirects.map((r) => r.path)).toContain(ROUTES.HOME);
    });

    it('declares each route path once', () => {
        const seen = new Map<string, number>();
        const dupes = routes.filter((r) => {
            const first = seen.get(r.path);
            seen.set(r.path, first ?? r.line);
            return first !== undefined;
        });
        expect(dupes.map((r) => `${r.path} (App.tsx:${r.line})`)).toEqual([]);
    });

    it('every page route is reachable from the sidebar or allowlisted with a reason', () => {
        const orphans = pages
            .filter((r) => !(r.path in ALLOWLIST))
            .filter((r) => !hrefs.some((h) => matches(r.path, h)))
            .map((r) => `${r.path} (App.tsx:${r.line})`);
        expect(orphans).toEqual([]);
    });

    it('every sidebar href resolves to a declared page route', () => {
        const dead = hrefs.filter((h) => !pages.some((r) => !isContainer(r.path) && matches(r.path, h)));
        expect(dead).toEqual([]);
    });

    it('every redirect targets a declared page route', () => {
        const broken = redirects
            .filter((r) => !pages.some((p) => !isContainer(p.path) && matches(p.path, r.redirectTo!)))
            .map((r) => `${r.path} -> ${r.redirectTo} (App.tsx:${r.line})`);
        expect(broken).toEqual([]);
    });

    it('no allowlist entry is stale', () => {
        const declared = new Set(pages.map((r) => r.path));
        const stale = Object.keys(ALLOWLIST).filter(
            (p) => !declared.has(p) || (!isContainer(p) && hrefs.some((h) => matches(p, h)))
        );
        expect(stale).toEqual([]);
    });
});
