// INV-WEB-06 (#2531), structural half: no code in web/src may branch on HTTP 404
// specifically, outside a small reviewed allowlist. A 404-specific branch is how the
// frontend would re-open the existence oracle ADR-096 closes on the backend (403 for both
// "doesn't exist" and "forbidden"): "This secret does not exist" vs "Access denied".
// The behavioural half — real per-resource pages rendering identically for 403 and 404 —
// is src/pages/__tests__/notFoundVsForbiddenRendering.test.tsx.
//
// Parsed with the TypeScript compiler API (not grepped), over every non-test .ts/.tsx
// file under src/. Shapes recognised:
//   - a comparison (=== == !== !=) with 404 or '404' on either side
//   - `case 404:` / `case '404':`
//   - a `HttpStatusCode.NotFound` reference (axios's status enum)
//   - an object-literal property keyed 404 (a status → message map)
// Not recognised: range checks that happen to include 404 (`status >= 400`), which treat
// it like every other 4xx; arithmetic or indirection that computes 404; branches on the
// response body's `error` string. 403-specific branches are deliberately NOT flagged: a
// "403 vs everything else" branch cannot distinguish a missing resource from a forbidden
// one, because a caller without the global permission receives 403 for both.
import { readdirSync, readFileSync, existsSync } from 'node:fs';
import { join, relative, resolve } from 'node:path';
import ts from 'typescript';
import { describe, expect, it } from 'vitest';

const webRoot = resolve(import.meta.dirname, '../../..');
const srcRoot = join(webRoot, 'src');

// Reviewed exceptions: path (relative to web/) → why the 404 branch is not an existence
// oracle. An entry whose file still exists must still contain a hit (else it is stale and
// fails below); an entry whose file has been deleted is inert — it can only ever match a
// NEW file created at the same path, which is why it should be removed when noticed.
const ALLOWLIST: Record<string, string> = {
    'src/pages/admin/OIDCFederationSection.tsx':
        'probes whether the /api/v1/oidc/trust FEATURE endpoint is deployed at all (404/501 = backend not ready) — ' +
        'not a per-resource lookup; the file is removed by #2486/#2550',
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

const is404 = (n: ts.Node): boolean =>
    (ts.isNumericLiteral(n) && Number(n.text) === 404) || (ts.isStringLiteralLike(n) && n.text === '404');

const COMPARISON = new Set([
    ts.SyntaxKind.EqualsEqualsEqualsToken,
    ts.SyntaxKind.EqualsEqualsToken,
    ts.SyntaxKind.ExclamationEqualsEqualsToken,
    ts.SyntaxKind.ExclamationEqualsToken,
]);

function findNotFoundBranches(fileName: string, text: string): string[] {
    const sf = ts.createSourceFile(
        fileName,
        text,
        ts.ScriptTarget.Latest,
        true,
        fileName.endsWith('x') ? ts.ScriptKind.TSX : ts.ScriptKind.TS
    );
    const hits: string[] = [];
    const at = (n: ts.Node, what: string) => {
        const { line } = sf.getLineAndCharacterOfPosition(n.getStart(sf));
        hits.push(`${fileName}:${line + 1}: ${what}`);
    };
    const visit = (n: ts.Node) => {
        if (ts.isBinaryExpression(n) && COMPARISON.has(n.operatorToken.kind) && (is404(n.left) || is404(n.right))) {
            at(n, `comparison with 404: ${n.getText(sf)}`);
        } else if (ts.isCaseClause(n) && is404(n.expression)) {
            at(n, 'case 404');
        } else if (
            ts.isPropertyAccessExpression(n) &&
            n.name.text === 'NotFound' &&
            ts.isIdentifier(n.expression) &&
            n.expression.text === 'HttpStatusCode'
        ) {
            at(n, 'HttpStatusCode.NotFound');
        } else if (ts.isPropertyAssignment(n) && is404(n.name)) {
            at(n, 'object key 404');
        }
        ts.forEachChild(n, visit);
    };
    visit(sf);
    return hits;
}

describe('INV-WEB-06: no 404-specific branching in web/src', () => {
    const files = sourceFiles(srcRoot);

    it('the sweep actually saw the tree (non-vacuity)', () => {
        expect(files.length).toBeGreaterThan(100);
        expect(files).toContain('src/App.tsx');
        expect(files).toContain('src/services/client.ts');
    });

    it('no file outside the allowlist branches on 404', () => {
        const violations = files
            .filter((f) => !(f in ALLOWLIST))
            .flatMap((f) => findNotFoundBranches(f, readFileSync(join(webRoot, f), 'utf8')));
        expect(violations).toEqual([]);
    });

    it('every allowlist entry whose file still exists still needs its exemption', () => {
        const stale = Object.keys(ALLOWLIST).filter(
            (f) =>
                existsSync(join(webRoot, f)) &&
                findNotFoundBranches(f, readFileSync(join(webRoot, f), 'utf8')).length === 0
        );
        expect(stale).toEqual([]);
    });

    // Calibration: each recognised shape is flagged, and the deliberately-allowed shapes
    // are not — proven in-tree, not only on a scratch branch.
    it.each([
        ['strict equality', `if (err.response?.status === 404) show('gone');`],
        ['reversed loose equality', `if (404 == status) show('gone');`],
        ['inequality', `const exists = status !== 404;`],
        ['string literal', `if (code === '404') x();`],
        ['switch case', `switch (s) { case 404: x(); }`],
        ['axios enum', `if (s === HttpStatusCode.NotFound) x();`],
        ['status map', `const MESSAGES = { 403: 'Denied', 404: 'Does not exist' };`],
        ['tsx ternary', `const el = s === 404 ? <p>Missing</p> : <p>Denied</p>;`],
    ])('flags %s', (_name, code) => {
        expect(findNotFoundBranches('x.tsx', code)).not.toEqual([]);
    });

    it.each([
        ['403 branch', `if (status === 403) show('denied');`],
        ['4xx range', `if (status >= 400 && status < 500) noRetry();`],
        ['JSX text', `const el = <h1>404</h1>;`],
        ['unrelated number', `const n = 4040; if (n === 405) x();`],
    ])('allows %s', (_name, code) => {
        expect(findNotFoundBranches('x.tsx', code)).toEqual([]);
    });
});
