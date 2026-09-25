# FINDING: ~26 REST routes across 9 handler files serialize raw, untagged `internal/storage/models` structs to JSON — PascalCase leaks the Go wire contract, and two sibling routes leak PII (`IPAddress`) their already-fixed sibling deliberately redacts

**Date:** 2026-09-25
**Component:** `server/http/handlers/{catalog,rbac,shares_crud,shares_query,
machine_identities,project_memberships,secret_access_requests,invitations,
audit_search,secrets_access_history}.go`
**Status:** Inventory only — reported per API-HYGIENE track Step 1 instructions, before any fix.
**Severity:** Mixed. Most instances are an API-contract/hygiene defect (PascalCase
instead of the documented snake_case convention), not a credential-material leak —
every genuinely sensitive field found during this pass (`TokenHash`, `SessionToken`,
`SecretEnc`, `CodeHash`-adjacent) was already independently `json:"-"`-protected by
an earlier hardening campaign. Two findings (marked below) are Medium: `IPAddress`
(real PII) leaks through `SearchAuditLogs` and `AccessHistory`, where each has an
already-fixed sibling route (`GetAuditLogs`, the secret-scoped `AuditTrail`) proving
the redaction was a deliberate, known design decision that these two routes never
received.

## Scope and method

`internal/storage/models` has ~78 exported structs; an AST-based scan (not
hand-counted, to avoid the exact miscounting this instruction warned about) found
**37 with zero `json` tags on any field**, matching the task's "about 30" estimate:

`APICallLog, AccessRequest, AccessRequestApproval, AuditEvent, ConnectRefGrant,
ConnectorProjectBinding, Environment, ExternalIdentity, GRPCService, GroupRole,
IdentityProvider, LoginAttempt, MFARecoveryCode, MFAStepupToken, MachineIdentity,
MachineIdentityOIDCBinding, MachineIdentityRole, Notification, Permission, Project,
ProjectInvitation, ProjectMembership, RateLimit, RolePermission, SSOLoginState,
SchedulerLockLease, SecretAccessLog, SecretListFilter, SecretMetadataHistory,
SecretTag, ShareRecord, StatsSnapshot, SystemMetadata, Tag, UserGroup, UserRole,
WebAuthnCredential`

For each, I traced every `internal/core` function returning that type, then every
`server/http/handlers` call site of those functions (excluding `*_proxy.go` — the
`/api/v1/system/*` RemoteStorage federation tier, which already has its own
explicit-json-tagged `*ProxyWire` types for every model here and is separately
slated for deletion, PR 14/Phase 5), and read each one to see whether the result
reaches `sendSuccess`/`sendCreated` raw or wrapped. This is exhaustive for the 37
zero-tag models; it is **not** exhaustive for partially-tagged models (e.g.
`SecretNode`, 2/30 tagged) — see "Not yet verified" below.

## Confirmed unsafe (raw model reaches the wire)

| Route | Handler | Model | Fields reaching the wire | Notes |
|---|---|---|---|---|
| `GET /api/v1/projects` | `ListProjects` | `[]*models.Project` | ID, Name, Description, RequireMFA, CreatedAt, UpdatedAt, DeletedAt (nested) | |
| `GET /api/v1/projects/{id}` | `GetProject` | `*models.Project` | same | |
| `POST /api/v1/projects` | `CreateProject` | `*models.Project` | same | |
| `PUT /api/v1/projects/{id}` | `UpdateProject` | `*models.Project` | same | |
| `GET /api/v1/environments` | `ListEnvironments` | `[]*models.Environment` | ID, ProjectID, Name, CreatedAt, UpdatedAt, DeletedAt | A safe `environmentProxyWire` for this exact model already exists (`environment_catalog_proxy.go`) — unused here |
| `GET /api/v1/projects/{id}/environments` | `ListProjectEnvironments` | `[]*models.Environment` | same | |
| `POST /api/v1/projects/{id}/environments` | `CreateProjectEnvironment` | `*models.Environment` | same | |
| `POST /api/v1/roles` | `CreateRole` | `*models.Role` + `[]*models.Permission` | Role: ID,Name,Description,IsSystem?,CreatedAt…; Permission: ID,Name,Resource,Action,Description | |
| `GET /api/v1/roles/{id}` | `GetRole` | same | same | |
| `GET /api/v1/roles/by-name` | `GetRoleByName` | `*models.Role` | same | Doc comment says this raw shape is an intentional contract for `RemoteStorage.GetRoleByName` — that caller is Go-to-Go (casing-blind), so fixing the JSON tags is safe, but confirm no other consumer depends on the current shape before changing it |
| `PUT /api/v1/roles/{id}` | `UpdateRole` | `*models.Role` + `[]*models.Permission` | same | |
| `GET /api/v1/permissions` | `ListPermissions` | `[]*models.Permission` | same | |
| `POST /api/v1/secrets/{id}/share` | `ShareSecret` | `*models.ShareRecord` | ID,SecretID,OwnerID,RecipientID,IsGroup,Permission,ExpiresAt,CreatedAt,UpdatedAt,DeletedAt (nested) | Confirmed live in production — `cli/cmd/share_test.go`'s golden-output fixture for this exact route is PascalCase JSON, built to match the real server's observed behavior |
| `PUT /api/v1/shares/{id}` | `UpdateSharePermission` | `*models.ShareRecord` | same | |
| `GET /api/v1/secrets/{id}/shares` | `ListSecretShares` | `[]*models.ShareRecord` | same | same golden-fixture evidence |
| `GET /api/v1/groups/{id}/shares` | `ListGroupShares` | `[]*models.ShareRecord` | same | |
| `GET /api/v1/projects/{id}/machine-identities/stale` | `ListStaleMachineIdentities` | `[]*models.MachineIdentity` | ID,ProjectID,Name,IdentityType,State,Description,CreatedBy,CreatedByMachineIdentityID,timestamps,Classification | **Sibling-inconsistency**: `ListMachineIdentities` (same file, 40 lines above) already wraps in `machineIdentityProxyWire` — this one doesn't |
| `POST /api/v1/projects/{id}/machine-identities/migrate-from-user` | `MigrateUserToMachine` | `*models.MachineIdentity` | same | |
| `PUT /api/v1/projects/{id}/machine-identities/{machineId}` | `TransitionMachineIdentity` | `*models.MachineIdentity` | same | |
| `PATCH /api/v1/projects/{id}/machine-identities/{machineId}/classification` | `ClassifyMachineIdentity` | `*models.MachineIdentity` | same | |
| `GET /api/v1/projects/{id}/memberships` | `ListProjectMemberships` | `[]*models.ProjectMembership` | ID,ProjectID,UserID,Role,State,InvitedBy,InvitedByMachineIdentityID,timestamps | A safe `membershipProxyWire` already exists (`project_memberships_proxy.go`) — unused here |
| `POST /api/v1/projects/{id}/memberships` | `InviteMember` | `*models.ProjectMembership` | same | |
| `PUT /api/v1/projects/{id}/memberships/{membershipId}` | `TransitionMembership` | `*models.ProjectMembership` | same | |
| `POST /api/v1/secret-access-requests` | `CreateSecretAccessRequest` | `*models.AccessRequest` | ID,SecretID,ProjectID,RequesterID,ApproverID,SuggestedRole,GrantedRole,Reason,State,timestamps | |
| `GET /api/v1/secret-access-requests` | `ListSecretAccessRequests` | `[]*models.AccessRequest` (×2, "mine" + "pending_approval") | same | |
| `GET /api/v1/secret-access-requests/{requestId}` | `GetSecretAccessRequest` | `*models.AccessRequest` | same | |
| `GET /api/v1/projects/{id}/invitations` | `ListInvitations` | `[]*models.ProjectInvitation` | ID,ProjectID,Email,Role,State,InvitedBy,InvitedByMachineIdentityID,ValidationModeAtInvite,SystemRole,AssignmentsJSON,timestamps | A safe `invitationProxyWire` already exists (`invitations_proxy.go`) — unused here. No credential material (the setup token itself is a separate, already-`json:"-"`-protected model) |
| `POST /api/v1/projects/{id}/invitations` | `CreateInvitation` | `*models.ProjectInvitation` | same | Read only the delivery-error branch; the plain-success branch likely matches but wasn't individually confirmed |
| `GET /api/v1/audit/search` | `SearchAuditLogs` | `[]*models.AuditEvent` | **Includes `IPAddress` (PII), `PrevHash`/`EntryHash` (tamper-chain), raw `UserID`/`MachineIdentityID`/`ActingAs`/`ImpersonatedBy` IDs** | **Sibling-inconsistency, Medium severity**: the general `GetAuditLogs` (`GET /api/v1/audit/logs`) deliberately excludes `IPAddress` and the hash-chain fields, and resolves actor IDs to human-readable usernames via a purpose-built `AuditLogEntry` wire type — `SearchAuditLogs` bypasses all of that |
| `GET /api/v1/secrets/{id}/access-log` | `AccessHistory` | `[]models.SecretAccessLog` | **Includes `IPAddress`, `UserAgent` (PII)** | **Medium severity**, same PII class as above; the sibling `AuditTrail` (`GET /api/v1/secrets/{id}/audit`) uses a proper `secretAuditEntry` wire type with no such fields |

That's 26 confirmed routes. `Project`/`Environment`/`ShareRecord`/`MachineIdentity`/
`ProjectMembership`/`AccessRequest`/`ProjectInvitation`/`Role`/`Permission` carry no
credential or secret-value material themselves — the finding there is casing/contract
inconsistency (PascalCase instead of snake_case) and incidental internal-ID exposure
(`OwnerID`, `CreatedByMachineIdentityID`, etc. — already visible to an authenticated,
scoped caller through other routes, so not a new enumeration vector on its own).

## Confirmed safe (traced and verified during this pass — no fix needed)

- **`WebAuthnCredential`** — every route (`ListWebAuthnCredentials`,
  `FinishWebAuthnRegistration`, `webauthn_proxy.go`) explicitly picks
  `id`/`name`/`created_at`/`last_used_at` only. `CredentialID`/`PublicKey`/`SignCount`
  never reach any response.
- **`MFARecoveryCode`** — never serialized anywhere; `RegenerateRecoveryCodes`
  returns the plaintext `[]string` codes (intended, shown-once UX), never the model
  (so `CodeHash`, which carries no `json:"-"` of its own, is not actually at risk).
- **`Notification`** (`notifications_handler.go`) — `notificationToAPI` wraps every
  route.
- **`AuditEvent` via `GET /api/v1/audit/logs`** (general) and
  **`GET /api/v1/secrets/{id}/audit`** (secret-scoped) — both use purpose-built DTOs
  (`AuditLogEntry`, `secretAuditEntry`) that deliberately exclude `IPAddress`,
  `PrevHash`/`EntryHash`, and resolve actor IDs to usernames. (Contrast with
  `SearchAuditLogs` above, which doesn't.)
- **`ConnectRefGrant`** (`connect.go`) — explicit field selection on both list and
  create.
- **`MachineIdentity` via `ListMachineIdentities`, `CreateMachineIdentity`,
  `CreateOIDCBinding`, `ListOIDCBindings`, `ClassifyMachineToken`** — already wrapped
  (only 4 of this model's 8 route family are unsafe; see table above).
- **`ExternalIdentity`** — zero references anywhere in `server/http/handlers`; not
  reachable via any REST route today.
- **`Session`, `PersonalAccessToken`, `SetupToken`, `MFAChallenge`, `MFASecret`** —
  each carries a hash/secret field (`SessionToken`, `TokenHash`, `SecretEnc`,
  `SecretMeta`, `LastUsedStep`) already individually `json:"-"`-tagged by an earlier
  campaign, even though the rest of the struct has no tags. No handler was found
  raw-serializing any of these models as a whole.
- **`ProjectMembership` via `ListUserProjectMemberships`** (`users_roles.go`) —
  wrapped in `apiUserMembership`.
- **`ListProjects`/`ListEnvironments` used internally** (`secrets_handler.go`'s
  `resolveSecretNames`, `users_roles.go`'s membership-name resolution) — used only to
  build an ID→name lookup map, never serialized directly.

## Web UI is already compensating — confirms this is live, not latent

`web/src/services/projects.ts`'s `normalize()`/`normalizeEnv()` explicitly read
**both** casings (`p.ID ?? p.id`, `p.Name ?? p.name`, `p.RequireMFA ?? p.require_mfa`,
`e.DeletedAt ?? e.deleted_at`) — the same defensive pattern
`useRotationPolicies.ts` uses elsewhere. This confirms the `Project`/`Environment`
PascalCase leak is not hypothetical: the frontend team already had to work around it
by hand rather than fix the source. I did not check whether every other affected
resource (roles, shares, machine identities, memberships, access requests,
invitations) has equivalent client-side dual-casing coverage — Step 2 needs to grep
each one individually before changing its wire shape, per the track's own
instruction.

## Not yet verified (flag for Step 2, not asserted clean)

- The 15 zero-tag models with no direct handler reference found at all
  (`APICallLog, ConnectorProjectBinding, GRPCService, GroupRole, IdentityProvider,
  LoginAttempt, MachineIdentityRole, RateLimit, RolePermission, SchedulerLockLease,
  SecretMetadataHistory, SecretTag, StatsSnapshot, SystemMetadata, Tag, UserGroup`)
  — likely internal-only (rate limiting, gRPC service registry, scheduler locks,
  etc.), but not individually traced through every intermediate function call the
  way the other 22 were.
- **`SecretNode`** (2/30 fields tagged) — the highest-traffic model in the product.
  Not traced in this pass. `cli/internal/apiclient/gen/filterspec.go`'s own comment
  states a dedicated `Secret`/`SecretGetResult`/`SecretListEntry` schema was
  purpose-built for the main secret CRUD routes (PR 4's scope) and
  `SecretWithSharingInfo`/`SecretListResponse` (in `secret_with_sharing.go`) are
  fully json-tagged wrapper types that appear designed for exactly this — so risk is
  assessed **low**, but I did not read `secrets_handler.go`'s actual
  `GetSecret`/`ListSecrets` response construction to confirm it uses them rather than
  `SecretNode` directly. Recommend this be the first thing Step 2 checks, given the
  model's centrality.
- Partially-tagged models in general (this pass only covers the 37 fully-untagged
  ones) — a partially-tagged struct's untagged fields are exactly as exposed as a
  fully-untagged one's, if the struct itself is ever raw-serialized.

## Scope note per CENSUS-GAPS coordination

Per the track brief, I did not touch or re-verify `billing report`, `usage show`, or
`migrate-from-user`'s response shape beyond what was already necessary to classify
`MachineIdentity` above (`MigrateUserToMachine`'s own handler, not the CLI port
CENSUS-GAPS is doing) — leaving those response shapes for that session to land
first.
