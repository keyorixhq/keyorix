// Engine shared by the two response-field drift guards:
//   - responseFieldsDrift.test.ts   (#4303: secret row, version list, user list)
//   - anyMappedResponsesDrift.test.ts (roles, groups, sharing, dashboard, audit, projects,
//     and the include_value read)
// Kept apart from the tests so the engine is calibrated on its own and the tests only
// say WHICH web reads are compared against WHICH part of openapi.yaml.
import ts from 'typescript';
import { Shape } from './openapiDriftLib';

export type Doc = Record<string, any>;

export function deref(doc: Doc, s: Doc | undefined): Doc {
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

/** The same shape with every field required, so an optional field is compared too. */
export function allRequired(shape: Shape, seen: Shape[] = []): Shape {
    if (seen.includes(shape)) return shape;
    const next = [...seen, shape];
    return {
        ...shape,
        ...(shape.items ? { items: allRequired(shape.items, next) } : {}),
        ...(shape.props
            ? {
                  props: Object.fromEntries(
                      Object.entries(shape.props).map(([k, p]) => [
                          k,
                          { optional: false, shape: allRequired(p.shape, next) },
                      ])
                  ),
              }
            : {}),
    };
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

// ── generalised reads: any function / method, any root expression ───────────────

/** Where a read happens: a function (declaration or `const f = ...`) or `container.method`. */
export type Scope = { fn: string } | { container: string; method: string };

const describeScope = (s: Scope): string => ('fn' in s ? s.fn : `${s.container}.${s.method}`);

function findScope(sf: ts.SourceFile, scope: Scope): ts.Node {
    let found: ts.Node | undefined;
    const visit = (n: ts.Node) => {
        if ('fn' in scope) {
            if (ts.isFunctionDeclaration(n) && n.name?.text === scope.fn) found = n;
            if (ts.isVariableDeclaration(n) && ts.isIdentifier(n.name) && n.name.text === scope.fn && n.initializer)
                found = n.initializer;
        } else if (
            ts.isVariableDeclaration(n) &&
            ts.isIdentifier(n.name) &&
            n.name.text === scope.container &&
            n.initializer &&
            ts.isObjectLiteralExpression(n.initializer)
        ) {
            for (const m of n.initializer.properties) {
                if (m.name && ts.isIdentifier(m.name) && m.name.text === scope.method) found = m;
            }
        }
        ts.forEachChild(n, visit);
    };
    visit(sf);
    if (!found) throw new Error(`${describeScope(scope)} not found`);
    return found;
}

const parse = (sourceText: string) => ts.createSourceFile('x.ts', sourceText, ts.ScriptTarget.ES2022, true);

/**
 * Every field read off `root` inside `scope`, as `root.<field>` where `root` is an
 * identifier (`r`, `feed`) or an access chain (`response.data.data`; `?.` is ignored).
 * Method calls (`p.split(...)`) are not fields. A read through destructuring or an alias
 * of `root` is NOT recognised, so callers assert the fields they expect to see.
 */
export function scopeReads(sourceText: string, scope: Scope, root: string): string[] {
    const node = findScope(parse(sourceText), scope);
    const out = new Set<string>();
    const visit = (n: ts.Node) => {
        if (
            ts.isPropertyAccessExpression(n) &&
            n.expression.getText().replace(/\?\./g, '.') === root &&
            !(ts.isCallExpression(n.parent) && n.parent.expression === n)
        ) {
            out.add(n.name.text);
        }
        ts.forEachChild(n, visit);
    };
    visit(node);
    return [...out].sort();
}

/** Query-parameter names (and the JSON kind of each literal value) of the `params: {...}` in `scope`. */
export function requestParams(sourceText: string, scope: Scope): Record<string, string> {
    const node = findScope(parse(sourceText), scope);
    const out: Record<string, string> = {};
    const kindOf = (e: ts.Expression): string =>
        e.kind === ts.SyntaxKind.TrueKeyword || e.kind === ts.SyntaxKind.FalseKeyword
            ? 'boolean'
            : ts.isNumericLiteral(e)
              ? 'number'
              : ts.isStringLiteralLike(e)
                ? 'string'
                : 'unknown';
    const objects = (n: ts.Node) => {
        if (ts.isObjectLiteralExpression(n)) {
            for (const p of n.properties) {
                if (ts.isShorthandPropertyAssignment(p)) out[p.name.text] = 'unknown';
                else if (ts.isPropertyAssignment(p) && (ts.isIdentifier(p.name) || ts.isStringLiteral(p.name)))
                    out[p.name.text] = kindOf(p.initializer);
            }
        }
        ts.forEachChild(n, objects);
    };
    const visit = (n: ts.Node) => {
        if (ts.isPropertyAssignment(n) && ts.isIdentifier(n.name) && n.name.text === 'params') objects(n.initializer);
        else ts.forEachChild(n, visit);
    };
    visit(node);
    return out;
}

// ── schema side ──────────────────────────────────────────────────────────────

/** The schema at a dotted path from `schema`; `name[]` means "property name, then its items". */
export function schemaAt(doc: Doc, schema: Doc, path: string): Doc {
    let cur = deref(doc, schema);
    for (const seg of path ? path.split('.') : []) {
        const isArray = seg.endsWith('[]');
        const name = isArray ? seg.slice(0, -2) : seg;
        const next = cur.properties?.[name];
        if (!next) throw new Error(`no property "${name}" at ${path}`);
        cur = deref(doc, next);
        if (isArray) {
            if (!cur.items) throw new Error(`${path}: "${name}" is not an array in the schema`);
            cur = deref(doc, cur.items);
        }
    }
    return cur;
}

/**
 * Fields the web reads that the schema does not define. Strict on purpose: a read with a
 * `?? default` fallback counts too, because the fallback is what turns a server rename
 * into a blank cell instead of an error. Fallback reads the schema never had are pinned
 * by the caller, with a reason.
 */
export function readsNotInSchema(doc: Doc, fields: string[], schema: Doc, label: string): string[] {
    const s = deref(doc, schema);
    if (s.oneOf || s.anyOf || s.allOf) {
        throw new Error(`${label}: oneOf/anyOf/allOf is not supported by this check; extend it instead of skipping`);
    }
    const props = Object.keys(s.properties ?? {});
    // Guard the condition, not the conclusion: an empty schema makes "no read is missing" vacuous.
    if (props.length === 0) throw new Error(`${label}: the schema defines no properties`);
    return fields.filter((f) => !props.includes(f)).map((f) => `${label}.${f}`);
}

/**
 * The 200 response `description` of an operation whose body has no schema. Prose is the
 * only contract there is, so the check on it is weaker (see proseMissing).
 */
export function proseOf(doc: Doc, path: string, method: string): string {
    const resp = deref(doc, doc.paths?.[path]?.[method]?.responses?.['200']);
    if (!resp.description) throw new Error(`${method.toUpperCase()} ${path}: no 200 description`);
    if (resp.content?.['application/json']?.schema) {
        throw new Error(`${method.toUpperCase()} ${path} now has a schema: move it to the schema tier`);
    }
    return String(resp.description);
}

/**
 * Fields that do not appear as a whole word in `prose`. WEAKER than a schema check: a
 * field name can occur in unrelated prose, and the nesting / kind are not checked. It
 * catches the case this guard exists for (the spec's description stops naming a field
 * the web still reads); it cannot prove the field is where the web expects it.
 */
export function proseMissing(prose: string, fields: string[], label: string): string[] {
    return fields.filter((f) => !hasWholeWord(prose, f)).map((f) => `${label}.${f}`);
}

const isWordChar = (c: string | undefined): boolean => c !== undefined && /[A-Za-z0-9_]/.test(c);

/** True when `word` occurs in `text` with no [A-Za-z0-9_] on either side (literal match, no RegExp built from `word`). */
function hasWholeWord(text: string, word: string): boolean {
    if (word === '') return false;
    for (let at = text.indexOf(word); at !== -1; at = text.indexOf(word, at + 1)) {
        if (!isWordChar(text[at - 1]) && !isWordChar(text[at + word.length])) return true;
    }
    return false;
}

/** Declared query parameters (path-level and operation-level) of an operation: name -> schema type. */
export function queryParams(doc: Doc, path: string, method: string): Record<string, string | undefined> {
    const item = doc.paths?.[path];
    const op = item?.[method];
    if (!op) throw new Error(`${method.toUpperCase()} ${path} not found in openapi.yaml`);
    const out: Record<string, string | undefined> = {};
    for (const raw of [...(item.parameters ?? []), ...(op.parameters ?? [])]) {
        const p = deref(doc, raw);
        if (p.in === 'query') out[p.name] = deref(doc, p.schema).type;
    }
    return out;
}
