// Response-field drift guard for the three responses behind #2450-class defects:
// the secret (list row), the secret version (list) and the user list.
//
// #2450 shipped because the web read a field (`EncryptedValue`) the response schema
// never had, and nothing connected the two. openapiDrift.test.ts already pins the
// exported wire interfaces in web/src/types, but these three responses are not
// exported wire interfaces there: the secret row is read as `any` inside the
// services/secrets.ts mapper, the version list is an inline type on
// secretsApi.getVersions, and the user list is typed in services/users.ts and
// services/admin.ts. This file closes that gap for exactly those three.
//
// The rule (one direction on purpose): FAIL when the web side REQUIRES a field the
// openapi.yaml response schema does not define. Fields the web only tolerates
// (optional in the type, or read with a `??` / `||` fallback) are not failures;
// the ones outside the schema are pinned in LEGACY_FALLBACK_READS so they cannot
// grow unnoticed. A field the schema defines and the web never reads is fine.
//
// How "the web side" is derived (all from the source, nothing re-typed here):
//   - secret row: every `s.<field>` read in the `.map((s) => ...)` callback inside
//     secretsApi.list. A bare read is required; a read that is an operand of `??` or
//     `||` is tolerant. Not recognised: reads through destructuring or an alias of `s`
//     (the extractor asserts it found `id`, so it cannot go silently vacuous).
//   - version list: the awaited return type of secretsApi.getVersions (TS checker).
//   - user list: the awaited return types of usersApi.list and adminApi.getUsers, and
//     the exported AdminUser row interface (TS checker).
//
// NOT covered (stated, not implied; also listed in the PR body): every other response
// type, the secret detail / `include_value` body, fields read in components rather than
// in the service layer, nested types under a field the schema does not define, and
// string formats / enums / nullability (openapiDrift.test.ts compares those for the
// exported wire interfaces).
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import ts from 'typescript';
import { parse } from 'yaml';
import { describe, expect, it } from 'vitest';
import { Locator, Shape, createProgram, exportedInterfaces, locate, toShape } from './openapiDriftLib';

type Doc = Record<string, any>;

const SRC = resolve(import.meta.dirname, '../..');
const OPENAPI = resolve(import.meta.dirname, '../../../../server/http/handlers/openapi.yaml');
const SECRETS_TS = resolve(SRC, 'services/secrets.ts');
const USERS_TS = resolve(SRC, 'services/users.ts');
const ADMIN_TS = resolve(SRC, 'services/admin.ts');

// ── engine ────────────────────────────────────────────────────────────────────

function deref(doc: Doc, s: Doc | undefined): Doc {
    let cur = s ?? {};
    for (let i = 0; cur.$ref && i < 20; i++) {
        const path = String(cur.$ref).replace(/^#\//, '').split('/');
        const next = path.reduce((n: any, k) => n?.[k], doc);
        if (!next) throw new Error(`unresolvable $ref ${cur.$ref}`);
        cur = next;
    }
    return cur;
}

/** Paths of web-REQUIRED fields that the schema does not define. Empty = no drift. */
export function requiredNotInSchema(doc: Doc, shape: Shape, rawSchema: Doc, at: string, out: string[] = []): string[] {
    const schema = deref(doc, rawSchema);
    if (schema.oneOf || schema.anyOf || schema.allOf) {
        throw new Error(`${at}: oneOf/anyOf/allOf is not supported by this check; extend it instead of skipping`);
    }
    if (shape.kind === 'array') {
        if (!shape.items) return out;
        if (!schema.items) {
            out.push(`${at}[]: web types the items but the schema declares none`);
            return out;
        }
        return requiredNotInSchema(doc, shape.items, schema.items, `${at}[]`, out);
    }
    if (shape.kind !== 'object' || !shape.props || shape.record) return out;
    const sProps: Doc = schema.properties ?? {};
    for (const [name, p] of Object.entries(shape.props)) {
        const here = `${at}.${name}`;
        if (!(name in sProps)) {
            if (!p.optional) out.push(here);
            continue;
        }
        requiredNotInSchema(doc, p.shape, sProps[name], here, out);
    }
    return out;
}

interface Reads {
    required: string[];
    tolerant: string[];
}

/** Fields read off the row parameter of the first `.map(cb)` inside `container.method`. */
export function mapperReads(sourceText: string, container: string, method: string): Reads {
    const sf = ts.createSourceFile('x.ts', sourceText, ts.ScriptTarget.ES2022, true);
    let body: ts.Node | undefined;
    const findMethod = (n: ts.Node) => {
        if (
            ts.isVariableDeclaration(n) &&
            ts.isIdentifier(n.name) &&
            n.name.text === container &&
            n.initializer &&
            ts.isObjectLiteralExpression(n.initializer)
        ) {
            for (const m of n.initializer.properties) {
                if (m.name && ts.isIdentifier(m.name) && m.name.text === method) body = m;
            }
        }
        ts.forEachChild(n, findMethod);
    };
    findMethod(sf);
    if (!body) throw new Error(`${container}.${method} not found`);

    let cb: ts.ArrowFunction | undefined;
    const findMap = (n: ts.Node) => {
        if (
            !cb &&
            ts.isCallExpression(n) &&
            ts.isPropertyAccessExpression(n.expression) &&
            n.expression.name.text === 'map'
        ) {
            const a = n.arguments[0];
            if (a && ts.isArrowFunction(a) && a.parameters.length === 1 && ts.isIdentifier(a.parameters[0]!.name))
                cb = a;
        }
        ts.forEachChild(n, findMap);
    };
    findMap(body);
    if (!cb) throw new Error(`${container}.${method}: no .map((row) => ...) mapper found`);
    const param = (cb.parameters[0]!.name as ts.Identifier).text;

    const required = new Set<string>();
    const tolerant = new Set<string>();
    const visit = (n: ts.Node) => {
        if (ts.isPropertyAccessExpression(n) && ts.isIdentifier(n.expression) && n.expression.text === param) {
            const p = n.parent;
            const fallback =
                ts.isBinaryExpression(p) &&
                (p.operatorToken.kind === ts.SyntaxKind.QuestionQuestionToken ||
                    p.operatorToken.kind === ts.SyntaxKind.BarBarToken);
            (fallback ? tolerant : required).add(n.name.text);
        }
        ts.forEachChild(n, visit);
    };
    visit(cb.body);
    for (const name of required) tolerant.delete(name);
    return { required: [...required].sort(), tolerant: [...tolerant].sort() };
}

const objectShape = (props: Record<string, boolean /* optional */>): Shape => ({
    kind: 'object',
    nullable: false,
    props: Object.fromEntries(
        Object.entries(props).map(([k, optional]) => [k, { optional, shape: { kind: 'unknown', nullable: false } }])
    ),
});

// ── engine calibration: red AND green on synthetic cases ────────────────────────

describe('requiredNotInSchema / mapperReads (calibration)', () => {
    const doc: Doc = {
        components: {
            schemas: {
                Row: { type: 'object', properties: { id: { type: 'integer' }, name: { type: 'string' } } },
                List: {
                    type: 'object',
                    properties: { rows: { type: 'array', items: { $ref: '#/components/schemas/Row' } } },
                },
            },
        },
    };
    const row = { $ref: '#/components/schemas/Row' };

    it('green: a field the schema defines, and an optional one it does not', () => {
        expect(requiredNotInSchema(doc, objectShape({ id: false, extra: true }), row, 'Row')).toEqual([]);
    });
    it('red: a required field the schema does not define', () => {
        expect(requiredNotInSchema(doc, objectShape({ id: false, extra: false }), row, 'Row')).toEqual(['Row.extra']);
    });
    it('red: reaches through $ref and arrays', () => {
        const shape: Shape = {
            kind: 'object',
            nullable: false,
            props: {
                rows: {
                    optional: false,
                    shape: { kind: 'array', nullable: false, items: objectShape({ gone: false }) },
                },
            },
        };
        expect(requiredNotInSchema(doc, shape, { $ref: '#/components/schemas/List' }, 'List')).toEqual([
            'List.rows[].gone',
        ]);
    });
    it('refuses a union schema instead of skipping it', () => {
        expect(() => requiredNotInSchema(doc, objectShape({}), { oneOf: [row] }, 'X')).toThrow(/not supported/);
    });
    it('mapperReads: bare reads are required, ?? / || operands are tolerant', () => {
        const text = `const api = { async list() { return rows.map((r: any) => ({ a: r.id, b: r.x ?? r.y ?? '', c: r.z || 1 })); } };`;
        expect(mapperReads(text, 'api', 'list')).toEqual({ required: ['id'], tolerant: ['x', 'y', 'z'] });
    });
});

// ── the three responses ──────────────────────────────────────────────────────

const doc = parse(readFileSync(OPENAPI, 'utf8')) as Doc;
const schemaOf = (loc: Locator): Doc => {
    const s = locate(doc, loc);
    // Guard the condition, not the conclusion: an empty / property-less schema would
    // make "no required field missing" vacuously true for any web type.
    const resolved = deref(doc, s);
    const hasShape = resolved.properties ? Object.keys(resolved.properties).length > 0 : !!resolved.items;
    if (!hasShape) throw new Error(`schema for ${JSON.stringify(loc)} defines no properties`);
    return s;
};

const program = createProgram({
    [SECRETS_TS]: readFileSync(SECRETS_TS, 'utf8'),
    [USERS_TS]: readFileSync(USERS_TS, 'utf8'),
    [ADMIN_TS]: readFileSync(ADMIN_TS, 'utf8'),
});
const checker = program.getTypeChecker();

/** Shape of what `container.method(...)` resolves to, per the TS checker. */
function awaitedReturnShape(file: string, container: string, method: string): Shape {
    const sf = program.getSourceFile(file)!;
    let found: ts.Type | undefined;
    const visit = (n: ts.Node) => {
        if (ts.isVariableDeclaration(n) && ts.isIdentifier(n.name) && n.name.text === container) {
            const prop = checker.getTypeAtLocation(n.name).getProperty(method);
            const sig = prop && checker.getTypeOfSymbolAtLocation(prop, n).getCallSignatures()[0];
            if (sig) found = checker.getAwaitedType(sig.getReturnType()) ?? sig.getReturnType();
        }
        ts.forEachChild(n, visit);
    };
    visit(sf);
    if (!found) throw new Error(`${container}.${method} not found in ${file}`);
    return toShape(checker, found);
}

/**
 * Known drift: `<source>.<field path>` -> why it is accepted and when to remove it.
 * Each entry must still suppress a real finding (the staleness check below), so a
 * fixed type forces its entry out.
 */
const KNOWN_DRIFT: Record<string, string> = {};

/**
 * Fields the secret-row mapper reads WITH a fallback that the schema does not define.
 * Tolerant, so not a failure; pinned so a new one (or a removal) is a visible diff.
 */
const LEGACY_FALLBACK_READS = ['environment', 'namespace', 'namespace_name', 'zone', 'zone_name'];

describe('response-field drift: web-required fields must exist in the openapi.yaml schema', () => {
    const findings: Record<string, string[]> = {};
    const secretReads = mapperReads(readFileSync(SECRETS_TS, 'utf8'), 'secretsApi', 'list');
    const secretRow = schemaOf({ schema: 'SecretListEntry' });

    findings['secretsApi.list row'] = requiredNotInSchema(
        doc,
        objectShape({
            ...Object.fromEntries(secretReads.required.map((f) => [f, false])),
            ...Object.fromEntries(secretReads.tolerant.map((f) => [f, true])),
        }),
        secretRow,
        'secretsApi.list row'
    );

    findings['secretsApi.getVersions'] = requiredNotInSchema(
        doc,
        awaitedReturnShape(SECRETS_TS, 'secretsApi', 'getVersions'),
        schemaOf({ op: { path: '/api/v1/secrets/{id}/versions', method: 'get' }, at: ['data', 'versions'] }),
        'secretsApi.getVersions'
    );

    const usersEnvelope = schemaOf({ op: { path: '/api/v1/users', method: 'get' }, at: ['data'] });
    findings['usersApi.list'] = requiredNotInSchema(
        doc,
        awaitedReturnShape(USERS_TS, 'usersApi', 'list'),
        usersEnvelope,
        'usersApi.list'
    );
    findings['adminApi.getUsers'] = requiredNotInSchema(
        doc,
        awaitedReturnShape(ADMIN_TS, 'adminApi', 'getUsers'),
        usersEnvelope,
        'adminApi.getUsers'
    );

    const adminUser = exportedInterfaces(program, [USERS_TS]).get('AdminUser');
    if (!adminUser) throw new Error('AdminUser interface not found in services/users.ts');
    findings['AdminUser'] = requiredNotInSchema(
        doc,
        toShape(checker, adminUser),
        schemaOf({ schema: 'UserSummary' }),
        'AdminUser'
    );

    it('the secret-row extractor found the reads it is meant to (not vacuous)', () => {
        expect(secretReads.required).toEqual(expect.arrayContaining(['id', 'name', 'type']));
    });

    it.each(Object.keys(findings))('%s: no web-required field is missing from the schema', (source) => {
        const unaccepted = findings[source]!.filter((p) => !(p in KNOWN_DRIFT));
        expect(unaccepted).toEqual([]);
    });

    it('every KNOWN_DRIFT entry still matches a real finding (none is stale)', () => {
        const all = new Set(Object.values(findings).flat());
        expect(Object.keys(KNOWN_DRIFT).filter((k) => !all.has(k))).toEqual([]);
    });

    it('fallback reads outside the schema are exactly the pinned legacy set', () => {
        const props = Object.keys(deref(doc, secretRow).properties ?? {});
        const outside = secretReads.tolerant.filter((f) => !props.includes(f));
        expect(outside).toEqual(LEGACY_FALLBACK_READS);
    });
});
