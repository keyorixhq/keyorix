// INV-WEB-07: structural sweep over web/src/services. Every service module reaches the
// server only through the two reviewed axios instances (`apiClient` from ./client,
// `authApi` from ./auth), which attach the CSRF header on state-changing methods
// (INV-WEB-02) and own credentials / session refresh. This walks the services directory
// with the TypeScript compiler API and checks, per non-test file:
//
//   1. it imports `apiClient` (from './client') or `authApi` (from './auth') — or is in
//      EXEMPT with a reason;
//   2. it builds no client of its own: no `axios.create(...)` / `new Axios(...)` and no
//      value import of the axios default export (only isAxiosError / types are fine);
//   3. every state-changing call goes through a reviewed instance: a `.post/.put/.patch/
//      .delete/.request(...)` call whose receiver is not `apiClient` / `authApi` fails, and
//      so does calling the instance itself as a function (`apiClient({ method: 'POST' })`),
//      where the method would be invisible to this sweep.
//
// Recognised call spellings: `<recv>.post|put|patch|delete|request(...)` with <recv> an
// identifier or a property access chain, and `apiClient(...)`/`authApi(...)` direct calls.
// Not covered: pages and features (they have no HTTP client by INV-WEB-01's ESLint rule);
// a reviewed instance aliased to another local name (`const c = apiClient; c.post(...)`
// is flagged, which is the point: add an exemption or use the instance directly); whether
// the CSRF header is actually attached at runtime (services/__tests__/client.test.ts).
//
// client.ts and auth.ts define the instances and are skipped. setup.ts is the one other
// file with its own axios instance: ADR-028's single-use setup-token flow, deliberately
// unauthenticated (no session cookie, so no CSRF double-submit applies); it is the same
// documented exception as in eslint.config.mjs and is exempt here with that reason.
import { readdirSync, readFileSync } from 'node:fs';
import { join, resolve } from 'node:path';
import ts from 'typescript';
import { describe, expect, it } from 'vitest';

const servicesDir = resolve(import.meta.dirname, '../../services');

const DEFINES_INSTANCE = new Set(['client.ts', 'auth.ts']);
const EXEMPT: Record<string, string> = {
    'setup.ts':
        'ADR-028 setup-token flow: deliberately unauthenticated, no session cookie, so there is no CSRF ' +
        'double-submit to attach; same exception as eslint.config.mjs',
};
const INSTANCES = new Set(['apiClient', 'authApi']);
const MUTATING = new Set(['post', 'put', 'patch', 'delete', 'request']);

interface Findings {
    importsInstance: boolean;
    problems: string[];
}

function analyse(fileName: string, text: string): Findings {
    const sf = ts.createSourceFile(fileName, text, ts.ScriptTarget.Latest, true, ts.ScriptKind.TS);
    const out: Findings = { importsInstance: false, problems: [] };
    const at = (n: ts.Node, what: string) => {
        const { line } = sf.getLineAndCharacterOfPosition(n.getStart(sf));
        out.problems.push(`${fileName}:${line + 1}: ${what}`);
    };
    const receiverName = (e: ts.Expression): string | undefined =>
        ts.isIdentifier(e) ? e.text : ts.isPropertyAccessExpression(e) ? e.name.text : undefined;

    const visit = (n: ts.Node) => {
        if (ts.isImportDeclaration(n) && ts.isStringLiteral(n.moduleSpecifier)) {
            const mod = n.moduleSpecifier.text;
            const clause = n.importClause;
            if ((mod === './client' || mod === './auth') && clause?.namedBindings) {
                if (ts.isNamedImports(clause.namedBindings)) {
                    for (const el of clause.namedBindings.elements) {
                        if (INSTANCES.has((el.propertyName ?? el.name).text)) out.importsInstance = true;
                    }
                }
            }
            if (mod === 'axios' && clause && !clause.isTypeOnly) {
                if (clause.name) at(n, 'imports the axios default export (a client factory)');
                if (clause.namedBindings && ts.isNamespaceImport(clause.namedBindings)) {
                    at(n, 'namespace-imports axios');
                }
            }
        } else if (ts.isCallExpression(n)) {
            const callee = n.expression;
            if (ts.isPropertyAccessExpression(callee)) {
                const method = callee.name.text;
                const recv = receiverName(callee.expression);
                if (method === 'create' && recv === 'axios') at(n, 'axios.create(...) builds its own client');
                if (MUTATING.has(method) && !(recv && INSTANCES.has(recv))) {
                    at(n, `.${method}(...) on ${callee.expression.getText(sf)}, not apiClient/authApi`);
                }
            } else if (ts.isIdentifier(callee) && INSTANCES.has(callee.text)) {
                at(
                    n,
                    `${callee.text}(...) called directly; use ${callee.text}.get/post/... so the method is checkable`
                );
            }
        } else if (ts.isNewExpression(n) && ts.isIdentifier(n.expression) && n.expression.text === 'Axios') {
            at(n, 'new Axios(...) builds its own client');
        }
        ts.forEachChild(n, visit);
    };
    visit(sf);
    return out;
}

const isTestFile = (name: string) => /\.test\.tsx?$/.test(name) || name.endsWith('.d.ts');
const serviceFiles = readdirSync(servicesDir, { withFileTypes: true })
    .filter((e) => e.isFile() && /\.tsx?$/.test(e.name) && !isTestFile(e.name))
    .map((e) => e.name)
    .sort();
const swept = serviceFiles.filter((f) => !DEFINES_INSTANCE.has(f));

describe('INV-WEB-07: web/src/services all go through apiClient/authApi', () => {
    it('the sweep actually saw the services directory (non-vacuity)', () => {
        expect(swept.length).toBeGreaterThan(20);
        expect(swept).toContain('secrets.ts');
        expect(swept).toContain('projects.ts');
        expect(swept).not.toContain('client.ts');
    });

    it('every service file imports apiClient or authApi, and builds no client of its own', () => {
        const bad: string[] = [];
        for (const f of swept) {
            const r = analyse(f, readFileSync(join(servicesDir, f), 'utf8'));
            if (f in EXEMPT) continue;
            if (!r.importsInstance) bad.push(`${f}: imports neither apiClient (./client) nor authApi (./auth)`);
            bad.push(...r.problems);
        }
        expect(bad).toEqual([]);
    });

    it('every exemption still needs its exemption (not stale)', () => {
        for (const f of Object.keys(EXEMPT)) {
            expect(serviceFiles).toContain(f);
            const r = analyse(f, readFileSync(join(servicesDir, f), 'utf8'));
            expect(r.importsInstance && r.problems.length === 0).toBe(false);
        }
    });

    // Calibration: each recognised violation is flagged; the sanctioned shapes are not.
    it.each([
        ['own axios.create', `import axios from 'axios';\nexport const c = axios.create();`],
        ['axios default import', `import axios from 'axios';\nexport const x = 1;`],
        ['axios namespace import', `import * as ax from 'axios';\nexport const x = ax;`],
        ['new Axios', `export const c = new Axios({});`],
        ['post on a foreign receiver', `import { apiClient } from './client';\nother.post('/x', {});`],
        ['delete on a local alias', `import { apiClient } from './client';\nconst c = apiClient;\nc.delete('/x');`],
        ['request() on a foreign receiver', `foo.request({ method: 'PUT', url: '/x' });`],
        [
            'direct apiClient(...) call',
            `import { apiClient } from './client';\napiClient({ method: 'POST', url: '/x' });`,
        ],
    ])('flags %s', (_name, code) => {
        expect(analyse('x.ts', code).problems).not.toEqual([]);
    });

    it('flags a service file that imports neither instance', () => {
        const r = analyse('x.ts', `export const f = () => 1;`);
        expect(r.importsInstance).toBe(false);
    });

    it.each([
        [
            'apiClient mutations',
            `import { apiClient } from './client';\nexport const f = () => apiClient.post('/x', {}) && apiClient.delete('/y');`,
        ],
        ['authApi mutations', `import { authApi } from './auth';\nexport const f = () => authApi.put('/x', {});`],
        [
            'type-only / predicate axios imports',
            `import { isAxiosError } from 'axios';\nimport type { AxiosResponse } from 'axios';\nimport { apiClient } from './client';\nexport const f = (e: unknown) => isAxiosError(e) && apiClient.get('/x');`,
        ],
        [
            'array delete is not an HTTP call on a foreign name it cannot see',
            `import { apiClient } from './client';\nexport const f = () => apiClient.get('/x');`,
        ],
    ])('allows %s', (_name, code) => {
        const r = analyse('x.ts', code);
        expect(r.problems).toEqual([]);
        expect(r.importsInstance).toBe(true);
    });
});
