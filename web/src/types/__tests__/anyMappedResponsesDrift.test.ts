// Response drift guard for the web readers that the type-level guard cannot see because
// they map `any`: roles, groups, sharing, dashboard, audit anomalies, projects, and the
// `include_value` read of a secret. Extends responseFieldsDrift.test.ts (#4303), which
// covers the secret row, the version list and the user list.
//
// The failure it exists for: the server renames a response field, the UI reads the old
// name through `any` (or behind a `?? default`) and shows a blank field in the demo; no
// compile error, no failing test. This compares what the web READS with openapi.yaml.
//
// Two tiers, because the spec itself is uneven (ADR-074: ~half the 200 bodies have only a
// prose `description`):
//   schema: the 200 body has a schema. Every field the web reads must be a property at
//     the matching place. STRICT: a read with a `?? default` fallback counts too (the
//     fallback is what turns a rename into a blank cell). A fallback read the schema
//     never had is pinned in LEGACY_READS with a reason, so a new one is a visible diff.
//   prose: the 200 body is a description only. Every field the web reads must still
//     appear as a whole word in that description. WEAKER: it cannot tell where the field
//     is nested and a name can occur in unrelated prose. It catches the description
//     dropping or renaming a field the UI still reads; nothing more.
// The web side is derived from the source, never re-typed here: `scopeReads` collects
// `<root>.<field>` reads in a named function, the TS checker gives the awaited return type
// of a typed service method, and `requestParams` reads the `params: {...}` literal.
//
// NOT covered (stated, not implied): fields read in components or hooks rather than in the
// service function named in a SOURCES entry; reads through destructuring or an alias of the
// root (the extractor asserts the reads it must find, so a refactor cannot make it vacuous);
// string formats / enums / nullability / optionality; GET /groups/{id}/shared-secrets and
// GET /projects/{id}/members (see UNGUARDED, with the reason); request bodies other than the
// include_value query parameter.
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import ts from 'typescript';
import { parse } from 'yaml';
import { describe, expect, it } from 'vitest';
import { Locator, Shape, createProgram, exportedInterfaces, locate, toShape } from './openapiDriftLib';
import {
    Doc,
    Scope,
    allRequired,
    proseMissing,
    proseOf,
    queryParams,
    readsNotInSchema,
    requestParams,
    requiredNotInSchema,
    schemaAt,
    scopeReads,
} from './responseDriftLib';

const SRC = resolve(import.meta.dirname, '../..');
const OPENAPI = resolve(import.meta.dirname, '../../../../server/http/handlers/openapi.yaml');
const file = (rel: string) => resolve(SRC, rel);
const RBAC_TS = file('services/rbac.ts');
const GROUPS_TS = file('services/groups.ts');
const SHARING_TS = file('services/sharing.ts');
const DASHBOARD_TS = file('services/dashboard.ts');
const PROJECTS_TS = file('services/projects.ts');
const SECRETS_TS = file('services/secrets.ts');
const TYPES_TS = file('types/index.ts');

const sourceText = (f: string) => readFileSync(f, 'utf8');
const realDoc = parse(sourceText(OPENAPI)) as Doc;

const program = createProgram(
    Object.fromEntries([RBAC_TS, GROUPS_TS, SHARING_TS, DASHBOARD_TS, TYPES_TS].map((f) => [f, sourceText(f)]))
);
const checker = program.getTypeChecker();

/** Shape of what `container.method(...)` resolves to, per the TS checker. */
function awaitedReturnShape(f: string, container: string, method: string): Shape {
    const sf = program.getSourceFile(f)!;
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
    if (!found) throw new Error(`${container}.${method} not found in ${f}`);
    return toShape(checker, found);
}

const interfaceShape = (name: string): Shape => toShape(checker, exportedInterfaces(program, [TYPES_TS]).get(name)!);
const keysOf = (s: Shape): string[] => Object.keys(s.props ?? {}).sort();

// ── the sources ──────────────────────────────────────────────────────────────

interface ReadGroup {
    /** `r`, `feed`, `response.data.data`: the expression the reads hang off. */
    root: string;
    /** Where those fields live under the located schema; `name[]` = items of array `name`. */
    at?: string;
    /** Fields that MUST be seen (the extractor is not vacuous). */
    expect: string[];
}

interface ReadSource {
    id: string;
    file: string;
    scope: Scope;
    groups: ReadGroup[];
    op: { path: string; method: string };
    /** Property path from the response root to the schema the groups' `at` is relative to. */
    dataAt: string[];
    tier: 'schema' | 'prose';
}

const GET = 'get';
const ROLES: ReadSource['op'] = { path: '/api/v1/roles', method: GET };
const ROLE: ReadSource['op'] = { path: '/api/v1/roles/{id}', method: GET };
const PROJECTS: ReadSource['op'] = { path: '/api/v1/projects', method: GET };
const PROJECT: ReadSource['op'] = { path: '/api/v1/projects/{id}', method: GET };

const ROLE_FIELDS = ['assignable_scope', 'bypasses_permission_checks', 'description', 'id', 'name', 'permissions'];
const PERMISSION_FIELDS = ['action', 'description', 'id', 'name', 'resource'];

const SOURCES: ReadSource[] = [
    {
        id: 'rbacApi.getRoles (normalizeRole)',
        file: RBAC_TS,
        scope: { fn: 'normalizeRole' },
        groups: [
            { root: 'r', at: 'roles[]', expect: ROLE_FIELDS },
            { root: 'p', at: 'roles[].permissions[]', expect: PERMISSION_FIELDS },
        ],
        op: ROLES,
        dataAt: ['data'],
        tier: 'schema',
    },
    {
        // getRole feeds `res.data.data` straight into normalizeRole; the spec says that is
        // `{role, permissions}`, not a role. See KNOWN_DRIFT.
        id: 'rbacApi.getRole (normalizeRole)',
        file: RBAC_TS,
        scope: { fn: 'normalizeRole' },
        groups: [
            { root: 'r', expect: ROLE_FIELDS },
            { root: 'p', at: 'permissions[]', expect: PERMISSION_FIELDS },
        ],
        op: ROLE,
        dataAt: ['data'],
        tier: 'schema',
    },
    {
        id: 'projectsApi.list (normalize)',
        file: PROJECTS_TS,
        scope: { fn: 'normalize' },
        groups: [{ root: 'p', at: 'projects[]', expect: ['description', 'id', 'name', 'require_mfa'] }],
        op: PROJECTS,
        dataAt: ['data'],
        tier: 'schema',
    },
    {
        id: 'projectsApi.get (normalize)',
        file: PROJECTS_TS,
        scope: { fn: 'normalize' },
        groups: [{ root: 'p', expect: ['description', 'id', 'name', 'require_mfa'] }],
        op: PROJECT,
        dataAt: ['data'],
        tier: 'schema',
    },
    {
        id: 'projectsApi.listEnvironments (normalizeEnv)',
        file: PROJECTS_TS,
        scope: { fn: 'normalizeEnv' },
        groups: [
            { root: 'e', at: 'environments[]', expect: ['deleted_at', 'id', 'name', 'project_id', 'secret_count'] },
        ],
        op: { path: '/api/v1/projects/{id}/environments', method: GET },
        dataAt: ['data'],
        tier: 'schema',
    },
    {
        id: 'projectsApi.rotationPlan (normalizeRotationPlan)',
        file: PROJECTS_TS,
        scope: { fn: 'normalizeRotationPlan' },
        groups: [
            { root: 'd', expect: ['due_soon_count', 'overdue_count', 'project_id', 'total_secrets', 'waves'] },
            { root: 'w', at: 'waves[]', expect: ['index', 'secrets'] },
            { root: 's', at: 'waves[].secrets[]', expect: ['secret_id', 'secret_name', 'status'] },
        ],
        op: { path: '/api/v1/projects/{id}/rotation-plan', method: GET },
        dataAt: ['data'],
        tier: 'schema',
    },
    {
        id: 'secretsApi.getValue (include_value=true)',
        file: SECRETS_TS,
        scope: { container: 'secretsApi', method: 'getValue' },
        groups: [{ root: 'response.data.data', expect: ['value'] }],
        op: { path: '/api/v1/secrets/{id}', method: GET },
        dataAt: ['data'],
        tier: 'schema',
    },
    {
        id: 'dashboardApi.getActivity (feed)',
        file: DASHBOARD_TS,
        scope: { container: 'dashboardApi', method: 'getActivity' },
        groups: [{ root: 'feed', expect: ['items', 'page', 'pageSize', 'total'] }],
        op: { path: '/api/v1/dashboard/activity', method: GET },
        dataAt: [],
        tier: 'prose',
    },
    {
        id: 'projectsApi.drift (normalizeDrift)',
        file: PROJECTS_TS,
        scope: { fn: 'normalizeDrift' },
        // Only the report root: the description names environments, drifted_keys and summary
        // but not the fields inside a drifted key, so those cannot be checked at this tier.
        groups: [{ root: 'd', expect: ['drifted_keys', 'environments', 'project_id', 'summary'] }],
        op: { path: '/api/v1/projects/{id}/drift', method: GET },
        dataAt: [],
        tier: 'prose',
    },
];

/** Typed service methods / interfaces whose (strict) field names are compared. */
interface TypedSource {
    id: string;
    shape: () => Shape;
    op: { path: string; method: string };
    dataAt: string[];
    tier: 'schema' | 'prose';
    /** prose: only the top-level keys of the shape are matched. */
    note?: string;
}

const TYPED: TypedSource[] = [
    {
        id: 'groupsApi.list',
        shape: () => awaitedReturnShape(GROUPS_TS, 'groupsApi', 'list'),
        op: { path: '/api/v1/groups', method: GET },
        dataAt: ['data'],
        tier: 'schema',
    },
    {
        id: 'rbacApi.getRolePermissions',
        shape: () => awaitedReturnShape(RBAC_TS, 'rbacApi', 'getRolePermissions'),
        op: { path: '/api/v1/roles/{id}/permissions', method: GET },
        dataAt: ['data'],
        tier: 'schema',
    },
    {
        id: 'sharingApi.listOwned',
        shape: () => awaitedReturnShape(SHARING_TS, 'sharingApi', 'listOwned'),
        op: { path: '/api/v1/shares/owned', method: GET },
        dataAt: ['data'],
        tier: 'schema',
    },
    {
        id: 'sharingApi.list',
        shape: () => awaitedReturnShape(SHARING_TS, 'sharingApi', 'list'),
        op: { path: '/api/v1/shares', method: GET },
        dataAt: [],
        tier: 'prose',
    },
    {
        id: 'dashboardApi.getStats (DashboardStats)',
        shape: () => interfaceShape('DashboardStats'),
        op: { path: '/api/v1/dashboard/stats', method: GET },
        dataAt: [],
        tier: 'prose',
    },
    {
        id: 'dashboardApi.getActivity (ActivityItem)',
        shape: () => interfaceShape('ActivityItem'),
        op: { path: '/api/v1/dashboard/activity', method: GET },
        dataAt: [],
        tier: 'prose',
    },
    {
        id: 'auditApi.getAnomalyAlerts (AnomalyAlert)',
        shape: () => interfaceShape('AnomalyAlert'),
        op: { path: '/api/v1/audit/anomalies', method: GET },
        dataAt: [],
        tier: 'prose',
    },
];

/** Readers the guard cannot compare, with why. Each is asserted still true so it cannot rot. */
const UNGUARDED: Record<string, { path: string; method: string; reason: string }> = {
    'rbacApi.getGroupSharedSecrets': {
        path: '/api/v1/groups/{id}/shared-secrets',
        method: GET,
        reason: 'the route exists (router.go) but openapi.yaml does not document it, so there is nothing to compare against',
    },
};

/**
 * Known drift: finding -> why it is accepted and when to remove it. Every entry must still
 * suppress a real finding (the staleness test below), so a fixed reader forces its entry out.
 */
const GET_ROLE = 'rbacApi.getRole (normalizeRole) @ data';
const GET_ROLE_WHY =
    'getRole feeds `data` of GET /roles/{id} into normalizeRole, but the server sends `{role, permissions}` ' +
    '(rbac.go GetRole), so every field but `permissions` reads its default and the role comes back blank. ' +
    'Nothing renders it today (useRole has no caller). Fix: unwrap `data.role` in rbacApi.getRole, then drop these.';
const PROJECT_COUNTS_WHY =
    'the server never sends it: projectWire (catalog_wire.go) has no secret/environment count, last activity or ' +
    '`deleted` (only deleted_at), so ProjectsListPage shows "0 secrets, 0 envs" for every real project. ' +
    'Needs the server to send counts (or the UI to stop showing them); then drop these.';

const KNOWN_DRIFT: Record<string, string> = {
    [`${GET_ROLE}.assignable_scope`]: GET_ROLE_WHY,
    [`${GET_ROLE}.bypasses_permission_checks`]: GET_ROLE_WHY,
    [`${GET_ROLE}.description`]: GET_ROLE_WHY,
    [`${GET_ROLE}.id`]: GET_ROLE_WHY,
    [`${GET_ROLE}.name`]: GET_ROLE_WHY,
    ...Object.fromEntries(
        ['deleted', 'environment_count', 'last_activity', 'secret_count'].flatMap((f) => [
            [`projectsApi.list (normalize) @ projects[].${f}`, PROJECT_COUNTS_WHY],
            [`projectsApi.get (normalize) @ data.${f}`, PROJECT_COUNTS_WHY],
        ])
    ),
};

const LIST_ITEM_INLINE =
    'GET /projects declares its items inline with only id, name and description; projectWire (catalog_wire.go) sends ' +
    'this too (GET /projects/{id} documents it as the Project schema). A spec gap, not a web defect.';
const PLAN_NOT_IN_SPEC =
    'sent by the server (internal/core/rotation_planner.go) but missing from the rotation-plan schema in openapi.yaml: a spec gap.';
const FALLBACK_CAMEL = 'camelCase fallback for an older payload; the server sends snake_case, which is in the spec.';
const NOT_NAMED =
    'the 200 description does not name it (the description is the only contract there), so it cannot be checked.';

/** Reads the spec does not cover: finding -> why. Pinned so a new one is a visible diff. */
const LEGACY_READS: Record<string, string> = {
    ...Object.fromEntries(
        ['created_at', 'require_mfa', 'updated_at'].map((f) => [
            `projectsApi.list (normalize) @ projects[].${f}`,
            LIST_ITEM_INLINE,
        ])
    ),
    'projectsApi.rotationPlan (normalizeRotationPlan) @ data.projectId': FALLBACK_CAMEL,
    ...Object.fromEntries(
        ['after_secret_ids', 'risk_score', 'urgency'].map((f) => [
            `projectsApi.rotationPlan (normalizeRotationPlan) @ waves[].secrets[].${f}`,
            PLAN_NOT_IN_SPEC,
        ])
    ),
    'projectsApi.drift (normalizeDrift) @ data.driftedKeys': FALLBACK_CAMEL,
    'projectsApi.drift (normalizeDrift) @ data.projectId': FALLBACK_CAMEL,
    'projectsApi.drift (normalizeDrift) @ data.project_id': NOT_NAMED,
    // GET /shares: the description says `data.shares`, but the handler returns the paginated page
    // (shares_query.go ListShares, same shape as /shares/owned). The description is stale.
    ...Object.fromEntries(
        ['page', 'pageSize', 'total', 'totalPages'].map((f) => [
            `sharingApi.list.${f}`,
            'GET /shares description says `data.shares`; the handler returns the paginated page (shares_query.go). Stale description.',
        ])
    ),
    'dashboardApi.getStats (DashboardStats).prevTotalSecrets':
        'sent by the server (core/dashboard.go PrevTotalSecrets, omitempty) but not named in the description.',
};

// ── findings ─────────────────────────────────────────────────────────────────

const locateData = (doc: Doc, op: ReadSource['op'], dataAt: string[]): Doc => {
    const l: Locator = { op: { path: op.path, method: op.method }, at: dataAt };
    return locate(doc, l);
};

/** Every finding, by source id. Pure in `doc`, so calibration can run it on a mutated copy. */
export function collectFindings(doc: Doc): Record<string, string[]> {
    const out: Record<string, string[]> = {};

    for (const s of SOURCES) {
        const text = sourceText(s.file);
        const findings: string[] = [];
        const prose = s.tier === 'prose' ? proseOf(doc, s.op.path, s.op.method) : '';
        for (const g of s.groups) {
            const reads = scopeReads(text, s.scope, g.root);
            const missingExpected = g.expect.filter((f) => !reads.includes(f));
            if (missingExpected.length) {
                throw new Error(`${s.id}: extractor did not see ${missingExpected} read off \`${g.root}\` (refactor?)`);
            }
            const label = `${s.id} @ ${g.at ?? 'data'}`;
            if (s.tier === 'prose') findings.push(...proseMissing(prose, reads, label));
            else {
                const schema = schemaAt(doc, locateData(doc, s.op, s.dataAt), g.at ?? '');
                findings.push(...readsNotInSchema(doc, reads, schema, label));
            }
        }
        out[s.id] = findings;
    }

    for (const t of TYPED) {
        const shape = t.shape();
        if (t.tier === 'prose') {
            out[t.id] = proseMissing(proseOf(doc, t.op.path, t.op.method), keysOf(shape), t.id);
        } else {
            out[t.id] = requiredNotInSchema(doc, allRequired(shape), locateData(doc, t.op, t.dataAt), t.id);
        }
    }

    // The include_value read: the query parameter the web sends must be declared, with the
    // JSON kind the web sends it as.
    const sent = requestParams(sourceText(SECRETS_TS), { container: 'secretsApi', method: 'getValue' });
    if (!('include_value' in sent)) throw new Error('secretsApi.getValue no longer sends include_value (refactor?)');
    const declared = queryParams(doc, '/api/v1/secrets/{id}', GET);
    out['secretsApi.getValue params'] = Object.entries(sent).flatMap(([name, kind]) =>
        !(name in declared)
            ? [`secretsApi.getValue params.${name}: not a declared query parameter`]
            : kind !== 'unknown' && declared[name] !== kind
              ? [`secretsApi.getValue params.${name}: web sends ${kind}, the spec declares ${declared[name]}`]
              : []
    );
    return out;
}

const accepted = (finding: string) => finding in KNOWN_DRIFT || finding in LEGACY_READS;

// ── engine calibration: red AND green on synthetic cases ────────────────────────

describe('scopeReads / requestParams / proseMissing / schemaAt (calibration)', () => {
    const text = `
        function norm(r: any) {
            return { a: r.id, b: r.x ?? r.y ?? '', c: (r.items ?? []).map((i: any) => i.k), d: r.name.split('.') };
        }
        const api = {
            async get() {
                const res = await c.get('/x', { params: { include_value: true, n: 3, s: 'a', v } });
                return res.data?.data?.value;
            },
        };`;
    it('scopeReads: reads off an identifier, off a chain, not method calls, not other roots', () => {
        expect(scopeReads(text, { fn: 'norm' }, 'r')).toEqual(['id', 'items', 'name', 'x', 'y']);
        expect(scopeReads(text, { fn: 'norm' }, 'i')).toEqual(['k']);
        expect(scopeReads(text, { container: 'api', method: 'get' }, 'res.data.data')).toEqual(['value']);
    });
    it('scopeReads: an unknown scope is an error, not an empty list', () => {
        expect(() => scopeReads(text, { fn: 'gone' }, 'r')).toThrow(/not found/);
    });
    it('requestParams: names and literal kinds', () => {
        expect(requestParams(text, { container: 'api', method: 'get' })).toEqual({
            include_value: 'boolean',
            n: 'number',
            s: 'string',
            v: 'unknown',
        });
    });
    const doc: Doc = {
        paths: {
            '/p': {
                get: {
                    parameters: [
                        { name: 'q', in: 'query', schema: { type: 'boolean' } },
                        { name: 'id', in: 'path' },
                    ],
                    responses: { '200': { description: 'data: items[], total' } },
                },
            },
            '/s': {
                get: { responses: { '200': { description: 'x', content: { 'application/json': { schema: {} } } } } },
            },
        },
        components: {
            schemas: {
                Row: {
                    type: 'object',
                    properties: { id: {}, tags: { type: 'array', items: { type: 'object', properties: { k: {} } } } },
                },
            },
        },
    };
    it('proseMissing: whole words only', () => {
        expect(proseMissing('data: items[], total', ['items', 'total'], 'X')).toEqual([]);
        expect(proseMissing('data: items[], total', ['item', 'totals', 'page'], 'X')).toEqual([
            'X.item',
            'X.totals',
            'X.page',
        ]);
    });
    it('proseOf: refuses an operation that has a schema (it belongs to the schema tier)', () => {
        expect(proseOf(doc, '/p', 'get')).toContain('items[]');
        expect(() => proseOf(doc, '/s', 'get')).toThrow(/now has a schema/);
    });
    it('queryParams: only query parameters, with their type', () => {
        expect(queryParams(doc, '/p', 'get')).toEqual({ q: 'boolean' });
    });
    it('schemaAt + readsNotInSchema: green on a defined field, red on a missing one, refuses an empty schema', () => {
        const at = schemaAt(doc, { $ref: '#/components/schemas/Row' }, 'tags[]');
        expect(readsNotInSchema(doc, ['k'], at, 'L')).toEqual([]);
        expect(readsNotInSchema(doc, ['k', 'gone'], at, 'L')).toEqual(['L.gone']);
        expect(() => readsNotInSchema(doc, ['k'], {}, 'L')).toThrow(/no properties/);
        expect(() => schemaAt(doc, { $ref: '#/components/schemas/Row' }, 'id[]')).toThrow(/not an array/);
    });
});

// ── the guard, on the real spec ───────────────────────────────────────────────

describe('response drift: what the web reads must exist in openapi.yaml (roles, groups, sharing, dashboard, audit, projects)', () => {
    const findings = collectFindings(realDoc);

    it.each(Object.keys(findings))('%s: every read field is in the spec', (id) => {
        expect(findings[id]!.filter((f) => !accepted(f))).toEqual([]);
    });

    it('every KNOWN_DRIFT / LEGACY_READS entry still matches a real finding (none is stale)', () => {
        const all = new Set(Object.values(findings).flat());
        expect([...Object.keys(KNOWN_DRIFT), ...Object.keys(LEGACY_READS)].filter((k) => !all.has(k))).toEqual([]);
    });

    it.each(Object.entries(UNGUARDED))('%s stays unguarded only while the spec lacks it', (_id, u) => {
        expect(
            realDoc.paths?.[u.path]?.[u.method],
            `${u.path} is now in the spec: move ${_id} into SOURCES`
        ).toBeUndefined();
    });
});

// ── red proof, kept in the suite: rename one field in a scratch copy of the spec ──────

describe('the guard goes red when the spec renames a field the web reads (scratch copy of the spec)', () => {
    const scratch = (edit: (d: Doc) => void): Doc => {
        const d = structuredClone(realDoc);
        edit(d);
        return d;
    };
    const unaccepted = (d: Doc) =>
        Object.values(collectFindings(d))
            .flat()
            .filter((f) => !accepted(f));

    it('green: the unmodified spec has no unaccepted finding', () => {
        expect(unaccepted(realDoc)).toEqual([]);
    });
    it('red (schema tier): a role property renamed in the spec', () => {
        const d = scratch((x) => {
            const p = x.components.schemas.RoleWithPermissions.properties;
            p.scope_kind = p.assignable_scope;
            delete p.assignable_scope;
        });
        expect(unaccepted(d)).toContain('rbacApi.getRoles (normalizeRole) @ roles[].assignable_scope');
    });
    it('red (schema tier, typed): a share property renamed in the spec', () => {
        const d = scratch((x) => {
            const items =
                x.paths['/api/v1/shares/owned'].get.responses['200'].content['application/json'].schema.properties.data
                    .properties.data.items.properties;
            items.recipient_label = items.recipientName;
            delete items.recipientName;
        });
        expect(unaccepted(d)).toContain('sharingApi.listOwned.data[].recipientName');
    });
    it('red (prose tier): a dashboard activity field renamed in the description', () => {
        const d = scratch((x) => {
            const r = x.paths['/api/v1/dashboard/activity'].get.responses['200'];
            r.description = r.description.replaceAll('secretName', 'subjectName');
        });
        expect(unaccepted(d)).toContain('dashboardApi.getActivity (ActivityItem).secretName');
    });
    it('red (include_value): the query parameter renamed in the spec', () => {
        const d = scratch((x) => {
            const p = x.paths['/api/v1/secrets/{id}'].get.parameters.find((q: Doc) => q.name === 'include_value');
            p.name = 'with_value';
        });
        expect(unaccepted(d)).toContain('secretsApi.getValue params.include_value: not a declared query parameter');
    });
    it('red (include_value response): the value property renamed in SecretGetResult', () => {
        const d = scratch((x) => {
            const p = x.components.schemas.SecretGetResult.properties;
            p.plaintext = p.value;
            delete p.value;
        });
        expect(unaccepted(d)).toContain('secretsApi.getValue (include_value=true) @ data.value');
    });
});
