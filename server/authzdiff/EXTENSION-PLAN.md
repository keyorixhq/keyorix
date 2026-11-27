# authzdiff: ranking the uncovered operations and planning the model extension

Session V5-RANK-1, 2026-11-26. Docs only: no harness or product code changed.
Inputs: `COVERAGE-ALL.md`, `matrix.json`, `model_test.go` (Oracle 2), the router and core code cited below.

"Zero findings" from `FuzzAuthzDiff` means no violation of the current oracles on the current world. This file says
which authorization decisions that statement does not reach, in what order to reach them, and what stays out of reach.

## 1. Counts, re-derived

| | header says | I derived | how |
|---|---|---|---|
| REST in scope (mutating or secret-reading) | 212 | **212** | `jq` over `matrix.json`: `layer=rest` and (`mutating` or `secret_reading`) |
| gRPC in scope | 47 | **47** | same, `layer=grpc` |
| REST covered / uncovered | 110 / 102 | **110 / 102** | count of `- [x]` / `- [ ]` lines with a `REST` key |
| gRPC covered / uncovered | 36 / 11 | **36 / 11** | same, `GRPC` keys |
| "other" REST covered | 34 of 128 | 34 of 128 | per-section line count |
| "other" gRPC covered | 11 of 22 | 11 of 22 | per-section line count |

The header counts agree with the matrix. The list in section 3 has 113 rows: 102 REST + 11 gRPC. `COVERAGE-ALL.md`
is a checkbox list generated from the harness; I did not re-run the generator, so "covered" is the committed list, not a fresh
derivation of which harness op calls which route.

Two differences from the task brief's description of the model (read `model_test.go` lines 17-52 before relying on either):

1. The brief lists "environment-scoped grants" and "MFA" as not modelled. The model **does** model environment-scoped
   grants (V5b: `grant.envID`, `environmentLive`, `requirement.env`) and the per-account MFA state the MFA ops need
   (`mfaRequired`, `pendingMFARequired`, `accountState`). What it does not model is *project-level* MFA
   (`ProjectRequiresMFA` / `ProjectMFABlocked`; "no fixture project requires it") and the restricted-secret step-up gate.
2. Break-glass, access review and risk exceptions have **zero uncovered operations**: all of their REST and gRPC ops are
   covered (`breakglass.*`, `accessreview.*`, `campaign.*`, `riskexception.*`). Their model rules are `memberOnly`,
   `globalAdminRole` and plain permissions. The "does not model" statement is about their *conditions* (for example a
   break-glass window changing what a later read may do), see section 5.

## 2. How I classified

**Impact if its authorization were wrong** (what the worst wrong outcome is, not how likely):

- **P1** discloses a secret value or key material (a read, a render, a credential issued, or the approval that unlocks such a read).
- **P2** changes privilege or authority, or crosses a tenant/project boundary as its *primary effect*: role/ownership/classification
  changes, auth-factor changes, account lifecycle, identity and bootstrap flows. (A project-scoped write whose only damage is to that
  resource is P3, even though a wrong scope derivation could reach another project.)
- **P3** integrity or availability of data or of the system (deletes, audit-chain operations, jobs that purge or suspend, rotation).
- **P4** metadata only, notification plumbing, or a read-state flag.

**Reason uncovered**, normalised from the free text in `COVERAGE-ALL.md` into this set:

| code | meaning |
|---|---|
| OUT | outside the families requested for the campaign (design decision, not a technical limit) |
| JOB | on-demand job trigger (`system.write` / `alerts.write`), outside the families |
| DYN | needs a dynamic-secret backend |
| CONNECT | needs a Keyorix Connect connector |
| WEBAUTHN | needs a WebAuthn authenticator |
| IDP | needs a configured OIDC/SAML identity provider (added: the source text says this per op) |
| SCIM | SCIM-token gated, covered by the standalone sweep (verified in section 4) |
| SELF | self-service on the caller's own account or credentials |
| PREAUTH | pre-authentication endpoint, no principal to disagree on (added) |
| BOOT | one-time bootstrap of an uninitialised install (added) |
| IMPERS | needs an impersonation session (added) |
| MFA | MFA-reset approval or MFA enrolment, not modelled |
| STRUCT | structural: covered by a source-text test, not by a request |
| MODEL | a reference-model rule is missing; sub-tag says which (classification, ownership, schedule, sod, legal-hold, secret-access) |
| FIXTURE | needs one fixture the world does not have (render: a template referencing secrets) |

Not used because nothing is uncovered for that reason: BULK, BREAKGLASS, ACCESS-REVIEW, RISK-EXCEPTION (all their ops are covered).
The source text for some SELF/MFA/IDP/PREAUTH rows says only "design" or "fixture"; the normalised code is my reading of the stated reason.

For every gated op I read the route gate in `server/http/router.go`. `RequirePermission(p)` is **global scope**
(`server/middleware/auth.go:1242`), `RequireScopedPermission(p, scope)` is scoped; the scope source (`ScopeFromEnvParam`,
`ScopeFromDynamicSecretConfigParam`, `ScopeFromDynamicSecretLeaseParam`, `folderScope`, `policyScope`) is what the model has to reproduce.

## 3. Ranked table (all 113 uncovered operations)

Sorted by impact, then batch. Batches are defined in section 6. `G` = gRPC.

### P1: 6 ops

| # | operation | impact | reason | batch |
|---|---|---|---|---|
| 1 | PUT /api/v1/secret-access-requests/{requestId} (approve/reject) | P1 | MODEL: secret-access | B1 |
| 2 | POST /api/v1/projects/{id}/secrets/render | P1 | FIXTURE: template referencing secrets | B1 |
| 3 | POST /api/v1/connect/{name}/secret:read | P1 | CONNECT | B3 |
| 4 | G ConnectService.ReadSecret | P1 | CONNECT | B3 |
| 5 | POST /api/v1/dynamic-secrets/configs/{id}/issue | P1 | DYN | B2 |
| 6 | G DynamicSecretService.IssueLease | P1 | DYN | B2 |

### P2: 42 ops

| # | operation | impact | reason | batch |
|---|---|---|---|---|
| 7 | PATCH /api/v1/secrets/{id}/classification | P2 | MODEL: classification | B1 |
| 8 | POST /api/v1/secrets/{id}/transfer-ownership | P2 | MODEL: ownership | B1 |
| 9 | PUT /api/v1/secrets/{id}/schedule | P2 | MODEL: schedule | B1 |
| 10 | DELETE /api/v1/secrets/{id}/schedule | P2 | MODEL: schedule | B1 |
| 11 | POST /api/v1/dynamic-secrets/configs | P2 | DYN | B2 |
| 12 | PATCH /api/v1/dynamic-secrets/configs/{id}/admin-dsn | P2 | DYN | B2 |
| 13 | G DynamicSecretService.CreateConfig | P2 | DYN | B2 |
| 14 | G DynamicSecretService.UpdateConfigAdminDSN | P2 | DYN | B2 |
| 15 | POST /api/v1/connect/ref-grants | P2 | CONNECT | B3 |
| 16 | DELETE /api/v1/connect/ref-grants/{id} | P2 | CONNECT | B3 |
| 17 | G ConnectService.CreateRefGrant | P2 | CONNECT | B3 |
| 18 | G ConnectService.DeleteRefGrant | P2 | CONNECT | B3 |
| 19 | POST /api/v1/sod/policies | P2 | MODEL: sod | B5 |
| 20 | DELETE /api/v1/sod/policies/{id} | P2 | MODEL: sod | B5 |
| 21 | POST /api/v1/mfa-reset-requests | P2 | MFA | B5 |
| 22 | POST /api/v1/mfa-reset-requests/{id}/approve | P2 | MFA | B5 |
| 23 | POST /api/v1/mfa-reset-requests/{id}/cancel | P2 | MFA | B5 |
| 24 | POST /api/v1/admin/impersonate | P2 | IMPERS | B5 |
| 25 | POST /api/v1/auth/change-password | P2 | SELF | B5 |
| 26 | POST /api/v1/auth/tokens (PAT mint) | P2 | SELF | B5 |
| 27 | POST /api/v1/auth/mfa/enroll | P2 | STRUCT | B5 |
| 28 | POST /system/init | P2 | BOOT | B5 |
| 29 | DELETE /api/v1/auth/webauthn/credentials/{id} | P2 | WEBAUTHN | B7 |
| 30 | POST /api/v1/auth/webauthn/reauth/finish | P2 | WEBAUTHN | B7 |
| 31 | POST /api/v1/auth/webauthn/register/finish | P2 | WEBAUTHN | B7 |
| 32 | POST /auth/webauthn/login/finish | P2 | WEBAUTHN | B7 |
| 33 | POST /auth/webauthn/passwordless/finish | P2 | WEBAUTHN | B7 |
| 34 | POST /auth/login | P2 | PREAUTH | B8 |
| 35 | POST /auth/refresh | P2 | PREAUTH | B8 |
| 36 | POST /auth/mfa/verify | P2 | MFA (needs MFA principal mid-login) | B8 |
| 37 | POST /auth/password-reset | P2 | PREAUTH | B8 |
| 38 | POST /auth/setup/consume | P2 | PREAUTH | B8 |
| 39 | GET /auth/sso/{provider}/callback | P2 | IDP | B8 |
| 40 | POST /auth/saml/{provider}/acs | P2 | IDP | B8 |
| 41-44 | POST/PUT/PATCH/DELETE /scim/v2/Users (create, replace, patch, delete; `{id}` forms) | P2 | SCIM | covered (see section 4) |
| 45-48 | POST/PUT/PATCH/DELETE /scim/v2/Groups (create, replace, patch, delete) | P2 | SCIM | covered (see section 4) |

### P3: 26 ops

| # | operation | impact | reason | batch |
|---|---|---|---|---|
| 49 | POST /api/v1/audit/checkpoint | P3 | OUT | B6 |
| 50 | G AuditService.WriteAuditCheckpoint | P3 | OUT | B6 |
| 51 | POST /api/v1/audit/migrate-chain-encoding | P3 | OUT | B6 |
| 52 | POST /api/v1/audit/anomalies/{id}/acknowledge | P3 | OUT | B6 |
| 53 | POST /api/v1/admin/jobs/purge-audit-logs | P3 | JOB | B6 |
| 54 | POST /api/v1/admin/jobs/suspend-inactive-users | P3 | JOB | B6 |
| 55 | PUT /api/v1/admin/anomaly-config | P3 | OUT | B6 |
| 56 | POST /api/v1/legal-hold | P3 | MODEL: legal-hold | B6 |
| 57 | DELETE /api/v1/legal-hold | P3 | MODEL: legal-hold | B6 |
| 58 | DELETE /api/v1/environments/{id} | P3 | OUT | B4 |
| 59 | POST /api/v1/folders | P3 | OUT | B4 |
| 60 | DELETE /api/v1/folders/{id} | P3 | OUT | B4 |
| 61 | POST /api/v1/rotation-policies | P3 | OUT | B4 |
| 62 | PUT /api/v1/rotation-policies/{id} | P3 | OUT | B4 |
| 63 | DELETE /api/v1/rotation-policies/{id} | P3 | OUT | B4 |
| 64 | DELETE /api/v1/auth/sessions/{id} | P3 | SELF | B5 |
| 65 | DELETE /api/v1/auth/tokens/{id} | P3 | SELF | B5 |
| 66 | PATCH /api/v1/dynamic-secrets/configs/{id}/classification | P3 | DYN | B2 |
| 67 | PATCH /api/v1/dynamic-secrets/configs/{id}/enabled | P3 | DYN | B2 |
| 68 | POST /api/v1/dynamic-secrets/configs/{id}/revoke-all | P3 | DYN | B2 |
| 69 | POST /api/v1/dynamic-secrets/leases/{leaseID}/renew | P3 | DYN | B2 |
| 70 | POST /api/v1/dynamic-secrets/leases/{leaseID}/revoke | P3 | DYN | B2 |
| 71 | G DynamicSecretService.ClassifyConfig | P3 | DYN | B2 |
| 72 | G DynamicSecretService.RenewLease | P3 | DYN | B2 |
| 73 | G DynamicSecretService.RevokeAllLeases | P3 | DYN | B2 |
| 74 | G DynamicSecretService.RevokeLease | P3 | DYN | B2 |

### P4: 39 ops

| # | operation | impact | reason | batch |
|---|---|---|---|---|
| 75 | POST /api/v1/secret-access-requests | P4 | MODEL: secret-access | B1 |
| 76 | POST /api/v1/secret-access-requests/{requestId}/withdraw | P4 | MODEL: secret-access | B1 |
| 77 | POST /api/v1/admin/jobs/anomaly-alerts | P4 | JOB | B6 |
| 78 | POST /api/v1/admin/jobs/check-read-quotas | P4 | JOB | B6 |
| 79 | POST /api/v1/admin/jobs/compliance-digest | P4 | JOB | B6 |
| 80 | POST /api/v1/admin/jobs/expiry-reminders | P4 | JOB | B6 |
| 81 | POST /api/v1/admin/jobs/record-hygiene-snapshot | P4 | JOB | B6 |
| 82 | POST /api/v1/admin/jobs/role-expiry-check | P4 | JOB | B6 |
| 83 | POST /api/v1/admin/jobs/rotation-reminders | P4 | JOB | B6 |
| 84 | POST /api/v1/admin/jobs/run-alert-escalation | P4 | JOB | B6 |
| 85 | POST /api/v1/admin/jobs/token-expiry-check | P4 | JOB | B6 |
| 86 | POST /api/v1/alert-escalation-policies | P4 | OUT | B6 |
| 87 | PUT /api/v1/alert-escalation-policies/{id} | P4 | OUT | B6 |
| 88 | DELETE /api/v1/alert-escalation-policies/{id} | P4 | OUT | B6 |
| 89 | POST /api/v1/compliance/digest/send | P4 | OUT | B6 |
| 90 | POST /api/v1/compliance/evidence/verify | P4 | OUT | B6 |
| 91 | POST /api/v1/compliance/snapshots | P4 | OUT | B6 |
| 92 | POST /api/v1/notification-channels | P4 | OUT | B6 |
| 93 | PUT /api/v1/notification-channels/{id} | P4 | OUT | B6 |
| 94 | DELETE /api/v1/notification-channels/{id} | P4 | OUT | B6 |
| 95 | PUT /api/v1/notification-channels/{id}/retry-policy | P4 | OUT | B6 |
| 96 | POST /api/v1/rejection-reason-templates | P4 | OUT | B6 |
| 97 | DELETE /api/v1/rejection-reason-templates/{id} | P4 | OUT | B6 |
| 98 | POST /api/v1/secret-templates | P4 | OUT | B6 |
| 99 | PUT /api/v1/secret-templates/{id} | P4 | OUT | B6 |
| 100 | DELETE /api/v1/secret-templates/{id} | P4 | OUT | B6 |
| 101 | POST /api/v1/secret-templates/{id}/apply | P4 | OUT | B6 |
| 102 | POST /api/v1/notifications/read-all | P4 | OUT | B5 |
| 103 | POST /api/v1/notifications/{id}/read | P4 | OUT | B5 |
| 104 | POST /api/v1/auth/end-impersonation | P4 | SELF | B5 |
| 105 | PUT /api/v1/auth/profile | P4 | SELF | B5 |
| 106 | DELETE /api/v1/auth/tokens/expired | P4 | SELF | B5 |
| 107 | POST /api/v1/auth/webauthn/reauth/begin | P4 | WEBAUTHN | B7 |
| 108 | POST /api/v1/auth/webauthn/register/begin | P4 | WEBAUTHN | B7 |
| 109 | POST /auth/webauthn/login/begin | P4 | WEBAUTHN | B7 |
| 110 | POST /auth/webauthn/passwordless/begin | P4 | WEBAUTHN | B7 |
| 111 | GET /auth/sso/{provider}/login | P4 | IDP | B8 |
| 112 | GET /auth/saml/{provider}/login | P4 | IDP | B8 |
| 113 | POST /auth/logout | P4 | PREAUTH | B8 |

Rows 41-48 are two grouped rows standing for eight SCIM operations. Totals: P1 6, P2 42, P3 26, P4 39 = 113.
Reasons (counted from the rows above): OUT 29, JOB 11, MODEL 11 (secret-access 3, schedule 2, sod 2, legal-hold 2,
classification 1, ownership 1), DYN 15, CONNECT 6, WEBAUTHN 9, IDP 4, SCIM 8, SELF 7, PREAUTH 5, MFA 4, BOOT 1, IMPERS 1,
STRUCT 1, FIXTURE 1 = 113. Batches (counted from the batch column): B1 8, B2 15, B3 6, B4 6, B5 17, B6 34, B7 9, B8 10 = 105,
plus 8 SCIM ops already covered = 113. If a number here disagrees with a table, the table wins.

Cross-check against the source reasons: every `design: outside the families` row is OUT; every `on-demand job trigger` is JOB; the
`model:` rows are MODEL with the sub-tag the source gives.

### Reading the ranking

Two facts shape the order and neither is visible from the checkbox list:

- **The uncovered P1 operations are few (6), but the biggest P1 blind spot is in the covered ones.** The reference model
  decides every covered secret read from grant tables alone. Reads of a secret value are also governed by the restricted-classification
  gate (three independent config flags, all off by default: `restricted_requires_permission`, `..._approval`, `..._mfa_stepup`,
  `internal/core/classification_gate.go`), by project-level MFA, by secret ACLs and shares, and by time-window schedules.
  None is in the model. Today the harness reads secrets only in the world where those are off or absent, so
  `secret.value.byid`, `secret.value.byref`, `secret.read.env`, `secret.certificate` and gRPC `GetSecretValue` are covered for
  the RBAC question only. B1 therefore extends covered ops as well as the uncovered ones.
- **Most uncovered ops (about 70) need no new model rule at all.** Global-gated admin ops (jobs, audit, compliance, alerts,
  notification channels, templates) are expressible with the existing `requirement{perms, scope: 0}`; they are uncovered because
  the campaign scoped them out (OUT/JOB), not because of a technical blocker. That makes B6 cheap, but low impact, so it comes late.

## 4. "Covered elsewhere" claims, checked

| claim in `COVERAGE-ALL.md` | what exists | does it assert authorization? |
|---|---|---|
| SCIM x8: "covered by TestSCIMStrictSweep standalone sweep (V5EXT4)" | `sweep_v5ext4_test.go:175`. Eight cases (`scim.user.{create,replace,patch,delete}`, `scim.group.{...}`), each on a fresh SCIM-enabled router leg. Denied probes: no header, wrong bearer of equal length, global admin session token, full PAT, machine token; each must be exactly 401 (rate limiter reset per case so a 429 cannot hide a refusal). Allowed probe: the SCIM bearer gets the success code. | **Yes**, a real behavioural authentication assertion on all eight routes. Limits, stated in its own comment: skipped under `-short`; does not exercise the IdP-managed-user guard (fixture user always has an `ExternalID`), the privilege ceiling on SCIM group membership (granting a high-privilege group to an IdP user), or partial failures in PATCH. |
| `POST /api/v1/auth/mfa/enroll`: "structural ... covered by TestMFARouteGatesPresent" | `sweep_v5ext5_test.go:97`. Reads `server/http/router.go` and requires the exact `r.With(customMiddleware.BlockWhenImpersonating).Post("/auth/mfa/enroll", ...)` anchor once. | **No, not at runtime.** It is a source-text match: a reformat or alias rename breaks it with no behaviour change, and it proves nothing about the middleware refusing a request, the route group, or order. Its own comment says so. The other three MFA routes in the same test (`activate`, `disable`, `recovery-codes/regenerate`) are additionally driven by V5EXT5 with positive controls; `enroll` is not (`BeginMFAEnrollment` needs `authEncryptor`, absent in test mode). So `mfa/enroll` has no runtime authorization check. Counted as uncovered for ranking. |
| `bulk-rotate` router anchor (V5EXT4, line ~139) | same source-text pattern | Not in the uncovered list; noted because the same weakness applies. |

No other uncovered row cites another test. The "design", "fixture" and "model" reasons are statements about the harness, not pointers to another assertion.

## 5. What the model reads today, and what each batch adds

Current Oracle 2 inputs (`model_test.go`): role grants (direct and via live groups, project or global, expiry, soft-deleted
project or environment voids a grant, group membership scoped to a project), bypass flag for users only, role-grant ceiling,
restricted PAT narrowing, suspended account, human-only ops, owner/member rules for share ops (`ownerUserID`, `ownerOrPerm`),
requester-only (access-request withdraw), recipient-only (self-share removal), global-admin-role (OIDC binding), member-only
(break-glass activate), machine-token cover rule, MFA account state for the MFA ops.

A rule is "deny-direction safe" if the oracle only fires when **the model denies and the product allows** (a bypass). The
opposite direction (model allows, product refuses) is where an unmodelled product-side restriction produces a false positive.
Every batch below starts with the deny direction and adds the allow direction only after a calibration control passes
(an allow-direction control per rule, as the harness does with `pkMFAEnrollee`/`pkMFAUser`).

## 6. Extension batches, in the order they should enter the model

### B1: secret-read conditions and secret-scoped approval (P1) , size L

Ops: #1 #2 #7 #8 #9 #10 #75 #76, plus the covered reads (`secret.value.byid/byref`, `secret.read.env`, `secret.certificate`,
gRPC `GetSecretValue`) under the new conditions.

Model rules to add (one line each):

1. `restricted-permission`: with `restricted_requires_permission` on, a read of a `restricted` secret also needs `secrets.read.restricted` at the secret's project (admin bypass as in `Authorize`).
2. `restricted-approval`: with `restricted_requires_approval` on, the reader needs an approved, secret-scoped `AccessRequest` row for that secret.
3. `restricted-mfa-stepup`: with `restricted_requires_mfa_stepup` on, the reader needs an unexpired step-up grant of purpose restricted-read within the window.
4. `project-mfa`: a project with `require_mfa` refuses secret reads by a user without a step-up (`ProjectMFABlocked`); reads by machines follow the code, not a guess.
5. `acl-share-read`: a user with no grant but a live direct/group share or an ACL entry may read that one secret at the share's permission level, and nothing else (the share-only path `RenderSecretTemplate`'s comment relies on).
6. `schedule-window`: a secret with a time-window schedule refuses value reads outside the window; schedule set/delete require `secrets.manage` at the secret's scope.
7. `classify-actor`: classification change authorizes as `SecretActionClassify` at the secret's own environment; raising or lowering a `restricted` secret follows the same rule.
8. `transfer-owner`: actor is the current owner, or the owner is gone and the actor holds `roles.assign` at the scope; the new owner already holds `secrets.write` or `secrets.manage` there.
9. `access-request-resolve`: approve/reject needs admin authority at the request's own project; create is self-service on a readable secret; withdraw is requester-only (the existing `requesterUserID`).

World-fixture changes: three legs or a per-case config setter for the three flags (`SetClassificationRestrictedRequires...`);
a `restricted` secret; a principal with a share but no grant (`pkShareOnly`) and one with an ACL entry only; a project with
`require_mfa`; a secret with a schedule; an ownerless (machine-created) secret and one whose owner was deleted;
secret-scoped `AccessRequest` rows (pending, approved, withdrawn); a template that references one secret (for `render`).

Oracle direction that cannot false-positive: deny first. Fire on "model denies (no grant, no share, no ACL, gate on, no approval,
outside window) and product returns the value". Never fire on "model allows, product refuses" for B1 until a positive control
(`pkMFAUser` with a fresh step-up) passes on each rule.

### B2: dynamic secrets, REST and gRPC (P1 issue, P2 config, P3 lease) , size M

Ops: #5 #6 (P1), #11-#14 (P2), #66-#74 (P3), 15 ops.

Model rules:

1. `dyn-config-scope`: config ops authorize `secrets.write` at the project owning the config (`ScopeFromDynamicSecretConfigParam`), never at a project named in the caller's other grants.
2. `dyn-lease-scope`: lease renew/revoke authorize at the project of the lease's config (`ScopeFromDynamicSecretLeaseParam`); a lease id belonging to another project must not authorize through the caller's own project.
3. `dyn-create-scope`: `CreateConfig` (ungated at the route, `AuthorizePrincipal` in core) needs `secrets.write` at the project in the body; gRPC authorizes the same way.
4. `dyn-admin-dsn`: changing the admin DSN needs the same permission and scope as create (key material is replaced, so the deny direction is the one that matters).
5. `dyn-project-mfa`: all dynamic ops call `ProjectRequiresMFA`; reuse B1's `project-mfa`.
6. `dyn-rest-grpc-parity`: the REST and gRPC leg of each op must reach the same decision (the existing partition Oracle 1 does this once the ops are bound).

World-fixture changes: register `internal/dynamic/dynamictest.FakeEngine` (`BackendType() == "fake"`, exists today) as the backend; one
config and one live lease in each of two projects; an `enabled=false` config. Whether the harness router can accept a registered fake engine
is not verified; if not, that is a harness change, not a model one.

Oracle direction: deny-first on issue/create/admin-dsn (P1/P2). Lease revoke/renew deny-direction only until the fake engine's error
returns are mapped to outcomes.

### B3: Connect (P1 read, P2 grants) , size M

Ops: #3 #4 (P1), #15-#18 (P2), 6 ops.

Model rules:

1. `connect-read`: reading through a connector needs the global `connect.read` permission.
2. `connect-ref-grant`: when ref-grants exist for a connector, a role may read only references its grants cover (exact reference plus prefix boundary; `internal/core/connect_ref_prefix_boundary_test.go` documents the boundary cases).
3. `connect-grant-admin`: creating or deleting a ref-grant needs `roles.write` at global scope (REST gate) and the gRPC leg must match.

World-fixture changes: a connector configured in the harness (test connector, no external store), two reads that the ref-grants allow and refuse.

Direction: deny-first on read. Existing independent coverage: core RBAC tests (`internal/core/connect_rbac_test.go`, `connect_ownership_test.go`) and a gRPC ref-scoping fuzz (`server/http/connect_ref_scoping_grpc_fuzz_test.go`) exercise the same decisions outside authzdiff; I did not run them or read their assertions, so treat them as leads, not coverage.

### B4: project/environment-scoped resource ops, existing rules (P3) , size S

Ops: #58-#63, six ops: environment delete, folder create and delete, rotation-policy create, update, delete.

Model rules:

1. `scope-from-env`: environment delete authorizes `secrets.delete` at the environment's project via the env id (`ScopeFromEnvParam`), and an environment-scoped grant for another environment must not satisfy it.
2. `scope-from-folder`: folder delete authorizes at the folder's project/environment; folder create is core-authorized from the body.
3. `scope-from-policy`: rotation-policy update/delete authorize `secrets.write` at the policy's project (`policyScope`); create is core-authorized from the body.

World-fixture changes: one environment with no active secrets (delete must be reachable), one folder, one rotation policy per project.
Direction: deny-first and allow-too: the model already evaluates these requirements today, so this is binding work, not new model logic.

### B5: authority, account security and ownership rules (P2) , size M

Ops: #19-#28, #64 #65, #102-#106; 17 ops.

Model rules:

1. `sod-admin`: SoD policy create/delete needs global `system.write` (a plain permission rule; the SoD *effect* on covered grants is a separate unmodelled product-stricter rule, see section 7).
2. `mfa-reset-actor`: request needs `users.write` at global scope; approve and cancel additionally need a user (not machine) holding a global admin role **by role name** in core (`isGlobalAdminRoleName` / `isAdminRoleName`, `internal/core/sod.go:521`), not the bypass flag. This differs from the permission-derived principle the rest of the model follows. See the question in section 9.
3. `mfa-reset-dual-control`: the approver is not the requester and not the target (to be confirmed against `mfa_reset.go` when binding; I did not read the approve path).
4. `own-target`: session revoke, PAT revoke and notification read act only on the caller's own rows; another user's id gives not-found. Reuses `requesterUserID`-style rules; machine principals own none.
5. `impersonation-block`: while a session is an impersonation session, every route with `BlockWhenImpersonating` (the four MFA routes, WebAuthn registration, PAT mint, step-up) is refused; impersonation start needs the permission the code requires (the matrix shows no route gate, only `Authorize` in core: read before binding).
6. `init-closed`: `POST /system/init` is refused for every principal, including unauthenticated, once the install is initialised.

World-fixture changes: a second global admin; a pending MFA reset request; an SoD policy row; an impersonation session (and its token); a PAT, a session and a notification owned by each of two users.
Direction: deny-first on every rule; `init-closed` and `impersonation-block` are constant-deny, the cheapest high-value checks here.

### B6: global admin and operations configuration (P3/P4) , size S, many ops

Ops: #49-#57, #77-#101; 34 ops (jobs, audit checkpoint/migrate/acknowledge, compliance, legal hold, anomaly config, alert escalation, notification channels, rejection templates, secret templates).

Model rules: **none new.** Each op is `requirement{perms: [system.write | alerts.write | audit.read+system.write | audit.read], scope: 0}` from the matrix `gate_perms`. Legal hold is a plain `system.write` gate; its effect on covered delete ops is not part of this batch.
World-fixture changes: none for the gate question. Harness work: bind each op with a minimal valid body; run the destructive jobs (`purge-audit-logs`, `suspend-inactive-users`, `migrate-chain-encoding`) on the cloned template DB only, as the harness already does for covered mutations.
Direction: deny-first, then allow (the model is the same code path as covered global ops).
Note: `check-read-quotas`, `expiry-reminders`, `rotation-reminders`, `role-expiry-check`, `token-expiry-check` gate on `alerts.write`, the others on `system.write`; the bundle split (`audit.read` plus `system.write` on the audit ops) is in `matrix.json`.

### B7: WebAuthn (P2/P4) , size L

Ops: #29-#33, #107-#110; 9 ops. Needs a software authenticator (virtual FIDO2 credential) in the harness, and a principal with an enrolled credential. Model rules: `webauthn-own-credential` (delete only your own credential), `webauthn-reauth-grants-stepup` (a finished reauth mints the step-up that B1's rule 3 consumes), `webauthn-login-binds-user` (a finished login yields a session for the credential's owner only). Direction: deny-first on cross-user credential use. This is an authentication oracle more than an authorization one; do it last and only if the authenticator is cheap.

### B8: pre-authentication and IdP flows (P2/P4) , size L, **not authzdiff**

Ops: #34-#40, #111-#113; 10 ops. There is no principal whose grants the layers disagree on (the harness's own stated reason), so Oracle 2 cannot say anything. These need their own authentication oracle (credential in, session out, replay refused, wrong tenant refused), and a real or stub OIDC/SAML IdP. Listed so the coverage list stays honest about where authzdiff stops.

## 7. What the extension still cannot check (the honest limit)

1. **Conditions the model reads are only as good as the fixture.** A rule is exercised only if the world has a row that triggers it. `FuzzAuthzDiff` mutates programs over a fixed template DB; a flag or row the template does not contain is never explored. Each B1 flag and fixture row must be added to the template deliberately.
2. **Product-stricter rules that sit behind a model "allow".** SoD conflicts refusing a role grant, legal hold refusing a delete, break-glass or risk-exception state changing a later read, the dual-control rule on role-grant approval, rate limits and quotas (read-quota, login-attempt) all make the product refuse where the model allows. The oracle's deny-first direction will not see them and the allow direction will report them as false positives unless modelled or excluded. None of these is in B1-B8; they are the next layer after B5.
3. **Authentication is not authorization.** Login, refresh, MFA verify, password reset, setup, SSO/SAML and WebAuthn login (B7/B8) decide who the principal is. Oracle 2 starts after that. A bypass there (a forged session, a replayed assertion) is invisible to authzdiff however complete the model.
4. **Cross-request state.** A single op against a template world is checked. Sequences (the `seq_*` harness) cover some; a time-of-check/time-of-use race between an authorization read and the write is a race oracle's job, not the model's.
5. **Which layer enforces.** The model never decides which layer enforces a rule (its own comment on `patRefusesUngatedWrite`). A product that refuses at both layers and a product that refuses at one are indistinguishable when the outcome matches.
6. **The model shares assumptions with the author.** It is hand-written from the same reading of core as the code. The FIX-1 principle (derive from role permissions, never role names) is followed except where core itself uses a name (`mfa-reset-actor`), which the model must mirror or the oracle will fire on a product that is behaving as designed.
7. **Side-effect stubs.** B6 jobs and B2/B3 backends are exercised against stubs. An authorization check that depends on the real backend's answer (a lease issued by a real database role) cannot be reached.
8. **SCIM** (`TestSCIMStrictSweep`) stays authentication only: group-membership privilege ceiling and the IdP-managed-user guard are asserted by nothing in authzdiff.

## 8. Operations whose authorization is not enforced where the model assumes

I looked at every ungated or self-service uncovered op for the layer that actually enforces it. Result: **no confirmed finding.**

- `WithdrawAccessRequest` (`internal/core/invitations.go:1437`) refuses a request whose `UserID` differs from the caller (returns not-found).
- `RevokeOwnSession` (`internal/core/account.go:715`) and `RevokeOwnPAT` (`internal/core/pat.go:146`) refuse another user's id with the uniform not-found; machines own none.
- `MarkNotificationRead` scopes by `(id, userID)` in storage.
- `RenderSecretTemplate` (`internal/core/secret_render.go:42`) has **no authorization of its own**. Its own comment records this as a known residual (#G10: any authenticated caller can trigger a storage query on a project they have no role in; unknown environment and forbidden secret give the same error so nothing leaks). Enforcement is the route gate `RequireScopedPermission(secrets.read, projectScope)` (`router.go:629-632`), and `RenderSecretTemplate` has exactly one non-generated caller (`server/http/handlers/secrets_render.go:39`), so the gate is on every path today. A new transport that reached core directly would reach an unauthorized function. It is the one place where the model's assumption ("gate decides") is the only line of defence; I am reporting it as a design note for B1, not a finding.
- `CancelMFAReset` (`internal/core/mfa_reset.go:561`) requires a global admin role **by name** inside core, on top of the `users.write` route gate. That is stricter than the gate (fail-closed), so not a bypass; it is a model-fidelity question (section 9).
- `TestMFARouteGatesPresent` does not test `mfa/enroll` at runtime (section 4). A coverage gap, not an enforcement gap.

Nothing here met the bar for a finding under the COMMON-RULES security section, so no issue was filed and no product code was touched.

## 9. Question for the owner (one hard authorization judgement)

Core decides "global admin" for MFA reset (and for the SoD, legal-hold, risk-exception and license-expiry checks that share
`isGlobalAdminRoleName`) by **role name** (`isAdminRoleName`), while the rest of authorization, and the reference model, derives
from role permissions and the `bypasses_permission_checks` flag (FIX-1). Builtin roles cannot be renamed, so today the two agree.
Should the model mirror the name-based rule for B5 (so the oracle follows the product), or should this be filed as a design defect
to move onto the bypass flag (so the oracle stays permission-derived)? Recommendation: mirror it in B5 and file a design note, since
a name-derived admin is exactly the shape FIX-1 removed elsewhere and the model should not hide it. Filed as ask `v5-rank-1-admin-by-name`.

## 10. Order, and what it costs

| batch | scope | ops | new model rules | size | impact reached |
|---|---|---|---|---|---|
| B1 | secret-read conditions, secret-scoped approval | 8 uncovered + 5 covered read ops | 9 | L | P1 (covered reads too) |
| B2 | dynamic secrets | 15 | 6 | M | P1 issue, P2 config |
| B3 | Connect | 6 | 3 | M | P1 read, P2 grants |
| B4 | env / folder / rotation-policy scope | 6 | 3 (bindings of existing logic) | S | P3 |
| B5 | authority, account security, bootstrap | 17 | 6 | M | P2 |
| B6 | global admin and ops config | 34 | 0 | S | P3/P4 |
| B7 | WebAuthn | 9 | 3 | L | P2 (authentication) |
| B8 | pre-auth and IdP flows | 10 | n/a | L | outside authzdiff |
| SCIM | already covered | 8 | n/a | n/a | P2 |

Batch op counts: 8+15+6+6+17+34+9+10 = 105, plus the 8 SCIM ops covered by the standalone sweep = 113. Each operation carries exactly one batch (or "covered").
