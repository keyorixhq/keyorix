// INV-WEB-05 guard: the hand-written wire types in web/src/types must agree with
// the server's OpenAPI document (server/http/handlers/openapi.yaml, ADR-074).
//
// Why a comparison test rather than codegen: web/src/types mixes wire shapes
// (snake_case, 1:1 with a response body) with UI models the services layer
// builds by mapping (User, Secret, ShareRecord, DashboardStats, ... -- camelCase,
// not what the server sends), and ~half the endpoints the web app calls have
// only a prose `description` for their 200 body in openapi.yaml, so there is no
// schema to generate from. Generating would rewrite most of web/src for no gain;
// this test pins the part that CAN be pinned.
//
// Three checks:
//   1. Every wire-type pair in WIRE_TYPES matches its schema (see openapiDriftLib).
//   2. Partition: every exported interface in web/src/types is either in
//      WIRE_TYPES or in NOT_COMPARED with a reason -- a new interface cannot
//      slip in unchecked.
//   3. No exemption (ALLOW) is stale: each must still suppress a real mismatch.
//
// What this does NOT cover (stated, not implied): the NOT_COMPARED types; wire
// bodies read as `any` inside services/*.ts mapping code; request/response
// bodies openapi.yaml does not schema (the spec is the limit, see ADR-074).
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { parse } from 'yaml';
import { describe, expect, it } from 'vitest';
import { Locator, compare, createProgram, exportedInterfaces, locate, toShape } from './openapiDriftLib';

const TYPES_DIR = resolve(import.meta.dirname, '..');
const FILES = ['index.ts', 'rbac.ts'].map((f) => resolve(TYPES_DIR, f));
const OPENAPI = resolve(import.meta.dirname, '../../../../server/http/handlers/openapi.yaml');

interface Pair {
    locate: Locator;
    /** dotted field path (rooted at the interface name) -> why the mismatch is accepted. */
    allow?: Record<string, string>;
}

// The server still returns the session token in the body for non-browser clients
// (auth.go buildLoginResponse / RefreshToken); the web app is cookie-only and must
// never read or store it (INV-WEB-03), so the field is deliberately undeclared.
const TOKEN_NOT_READ = 'server sends the session token for non-browser clients; web is cookie-only (INV-WEB-03)';

const WIRE_TYPES: Record<string, Pair> = {
    SecretAccessLogEntry: { locate: { schema: 'SecretAccessLogEntry' } },
    SecretAuditEntry: { locate: { schema: 'SecretAuditEntry' } },
    SecretAccessor: { locate: { schema: 'SecretAccessor' } },
    SecretRiskFactor: { locate: { schema: 'SecretRiskFactor' } },
    SecretRiskScore: { locate: { schema: 'SecretRiskScore' } },
    RotationPolicy: { locate: { schema: 'RotationPolicy' } },
    RotationPolicyEvaluation: { locate: { schema: 'RotationPolicyEvaluation' } },
    CreateRotationPolicyPayload: {
        locate: { op: { path: '/api/v1/rotation-policies', method: 'post', request: true } },
    },
    LoginResponse: {
        locate: { op: { path: '/auth/login', method: 'post' }, at: ['data'] },
        allow: { 'LoginResponse.token': TOKEN_NOT_READ },
    },
    RefreshTokenResponse: {
        locate: { op: { path: '/auth/refresh', method: 'post' }, at: ['data'] },
        allow: { 'RefreshTokenResponse.token': TOKEN_NOT_READ },
    },
    ApiError: { locate: { response: 'Error' } },
    Permission: { locate: { schema: 'Permission' } },
    Role: { locate: { schema: 'Role' } },
    RoleWithPermissions: { locate: { schema: 'RoleWithPermissions' } },
    GroupRoleGrant: { locate: { schema: 'GroupRoleGrant' } },
    GroupRoles: { locate: { op: { path: '/api/v1/groups/{id}/roles', method: 'get' }, at: ['data'] } },
    UserRoleAssignment: { locate: { schema: 'UserRoleAssignment' } },
    Group: {
        locate: { schema: 'Group' },
        allow: {
            'Group.member_count':
                'the server never sends it (groupToAPIResponse), so GroupsPage\'s member-count column always renders "—"; ' +
                'the column needs a real count source, not a type change',
        },
    },
};

const NOT_COMPARED: Record<string, string> = {
    // UI models: built by services/*.ts mapping code, not a wire body.
    User: 'UI model (services/auth.ts, users.ts map the snake_case profile into it)',
    UserPreferences: 'UI model, client-side preferences',
    NotificationSettings: 'UI model, client-side preferences',
    Secret: 'UI model (services/secrets.ts maps the snake_case SecretNode into it)',
    SecretFormData: 'UI form state',
    ShareRecord: 'UI model (services/sharing.ts maps the share wire shape)',
    ShareFormData: 'UI form state',
    Recipient: 'UI model (services/groups.ts, users.ts normalise users and groups)',
    StatTrend: 'UI model',
    ExpiringSecret: 'UI model (services/dashboard.ts)',
    AnomalyAlert: 'UI model (services/dashboard.ts)',
    DashboardStats: 'UI model (services/dashboard.ts)',
    ActivityItem: 'UI model (services/dashboard.ts)',
    NavigationItem: 'UI only',
    ApiResponse: 'generic envelope; the spec has no envelope schema, every route inlines {data, message}',
    PaginatedResponse: 'UI model built by services; not a wire shape',
    ValidationError: 'UI only (form validation)',
    AppNotification: 'UI toast model',
    SecretFilters: 'UI filter state',
    PaginationState: 'UI state',
    LoginFormData: 'UI form state',
    AuthState: 'UI store state',
    ImpersonatedBy: 'UI model translated by authStore from ProfileImpersonation',
    PasswordResetRequest: 'UI form state',
    PasswordResetConfirm: 'UI form state',
    EnvironmentConfig: 'client build/runtime config',
    GroupSharedSecret: 'UI model normalised from the server SecretNode',
    // Wire types the spec does not schema (200 is a prose description only).
    SecretPolicy: 'GET /secrets/policy is not documented in openapi.yaml',
    ProfileImpersonation: 'GET /api/v1/auth/profile 200 has a prose description, no schema',
    SecretUsageStat: 'GET /secrets/usage/most-accessed 200 has a prose description, no schema',
    UnusedSecretStat: 'GET /secrets/usage/unused 200 has a prose description, no schema',
    RotationStatusEntry: 'GET /rotation-policies/status 200 has a prose description, no schema',
};

const ALLOW: Record<string, string> = {};

describe('web/src/types agree with openapi.yaml (INV-WEB-05)', () => {
    const doc = parse(readFileSync(OPENAPI, 'utf8'));
    const program = createProgram(Object.fromEntries(FILES.map((f) => [f, readFileSync(f, 'utf8')])));
    const checker = program.getTypeChecker();
    const interfaces = exportedInterfaces(program, FILES);

    it('every exported interface is compared or explicitly exempted', () => {
        const names = [...interfaces.keys()];
        const unclassified = names.filter((n) => !(n in WIRE_TYPES) && !(n in NOT_COMPARED));
        const both = names.filter((n) => n in WIRE_TYPES && n in NOT_COMPARED);
        const stale = [...Object.keys(WIRE_TYPES), ...Object.keys(NOT_COMPARED)].filter((n) => !interfaces.has(n));
        expect({ unclassified, both, stale }).toEqual({ unclassified: [], both: [], stale: [] });
    });

    it('wire types match their OpenAPI schemas (fields, kinds, nullability, enums)', () => {
        const drift: string[] = [];
        const used = new Set<string>();
        for (const [name, pair] of Object.entries(WIRE_TYPES)) {
            const shape = toShape(checker, interfaces.get(name)!);
            const request = 'op' in pair.locate && pair.locate.op.request === true;
            compare(doc, shape, locate(doc, pair.locate), name, { ...pair.allow, ...ALLOW }, used, drift, request);
        }
        expect(drift).toEqual([]);
        const unusedAllow = [
            ...Object.keys(ALLOW),
            ...Object.values(WIRE_TYPES).flatMap((p) => Object.keys(p.allow ?? {})),
        ].filter((k) => !used.has(k));
        expect(unusedAllow, 'stale exemptions: remove them').toEqual([]);
    });
});
