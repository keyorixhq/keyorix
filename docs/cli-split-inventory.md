# CLI/server split — Phase 2 inventory

Inventory-only deliverable for the program ADR-108 (`docs/adr-108-cli-server-split.md`, Accepted,
Andrei, 2026-09-23 — not yet merged to `main`, lives on branch `docs/adr-108-109-cli-split-decoupling`
at the time of writing) describes. Builds on ADR-107 (CLI over the human-facing API, Proposed),
ADR-083 (`storage.type: remote` is CLI/client-mode only, Accepted), ADR-102 (`system.write` blast
radius, Proposed/open), ADR-106 (proto-first API definition — direction Accepted, migration
**not yet implemented**: the HTTP surface is still 151 hand-written handler files today, so "the
CLI's client is generated from the canonical API definition" per ADR-108 §Decision 1 is aspirational,
not current state).

This report walks every `keyorix` CLI command (`internal/cli/main.go`'s cobra tree, 35 top-level
groups, ~240 leaf subcommands) as it exists on `origin/main` (`db6dacfa`) as of 2026-09-23, and for
each one records: what it calls today, the REST route that does the same thing, a classification
(API / ADMIN-B1..B4 / CLIENT-ONLY / DROP), behavior differences between the local and remote code
paths, and candidate security findings. No code was changed to produce this report.

**Methodology note**: this pass was done as parallel per-command-group research (one pass per
package cluster below), each independently cross-referencing `server/http/router.go` +
`server/http/handlers/*.go` + `internal/core/*.go` against the CLI source. Citations are file:line
against the worktree used for this inventory; "not independently verified" is stated explicitly
wherever a claim rests on a router/handler comment rather than a direct read of the handler body.

## Contents

1. [Summary](#1-summary)
2. [Per-command-group inventory](#2-per-command-group-inventory)
3. [`/system` route caller census](#3-system-route-caller-census)
4. [CLI-side state today](#4-cli-side-state-today)
5. [Version skew: what exists today](#5-version-skew-what-exists-today)
6. [Top 5 GAPs by user impact](#6-top-5-gaps-by-user-impact)
7. [Phase 3 PR breakdown](#7-phase-3-pr-breakdown)
8. [Candidate security findings — consolidated](#8-candidate-security-findings--consolidated)

---

## 1. Summary

| Metric | Count |
|---|---|
| Top-level command groups | 35 |
| Leaf cobra subcommands inventoried | ~240 |
| Classified **API** (moves to thin CLI, already or trivially REST-backed) | ~190 |
| Classified **ADMIN-B1** (server won't start: diagnose/repair/migrate) | 3 (`system init` local mode, `system audit`, `system validate`) |
| Classified **ADMIN-B2** (recover-admin) | 0 — this mechanism does not exist anywhere in the codebase yet; it is wholly prospective (ADR-108 §Decision B.2) |
| Classified **ADMIN-B3** (exclusive-DB ops incl. KEK/DEK re-encryption) | 15 (all of `encryption/`) |
| Classified **ADMIN-B4** (offline audit-chain verification) | 0 — does not exist in any form today; `audit verify` is REST-only and asks the *live server* to grade its own audit chain, which is the opposite of B4's premise |
| Classified **CLIENT-ONLY** (config/credential files, output formatting, offline tooling) | ~25 |
| Classified **DROP** (dead, duplicate, or removed-by-design under ADR-108 Decision A) | ~10 |
| Hard GAPs (CLI operation with no REST route and one is needed) | 7 (see §6) |
| Candidate security findings (report only, not fixed) | 14 distinct findings across the whole surface (see §8) |
| `/system` routes (current count) | 151 registered routes (`rg`-verified; ADR-102's own snapshot was 148 — see §3) |
| `/system` routes with a non-CLI caller | **0** — confirmed by repo-wide grep (web UI, k8s-sync, mcp, operator, SDKs all checked); every `/system` route is either CLI-only-reachable or zero-caller |

**Headline findings, most important first:**

1. **A live, un-guarded privilege-escalation-adjacent gap on the human-facing `PUT /api/v1/users/{id}`
   route itself** — not a local-mode artifact. This route (ADR-107's own recommended sole path for
   `user update`) lacks the `RequireEqualOrGreaterAdminAuthority` admin-rank ceiling its `/system`
   proxy sibling (`UpdateUserIfActiveStateMatchesProxy`) already had to acquire to close the F5
   finding from the 2026-09-21 authority-ceiling campaign. See §8, Finding S1.
2. **Two live, independent-of-the-split correctness/security bugs on `main` today**: `secret rotate`
   and `secret render` build a broken, silently-ignored `?environment=<name>` query filter and then
   name-match unscoped across every secret the caller can read — `rotate` can silently overwrite the
   WRONG secret's value. See §8, Finding S2. Recommend filing and fixing independently of this
   program, not gated on it.
3. **`keyorix run`'s embedded/local-mode secret-value fetch has zero authorization check and zero
   audit event**, while the functionally identical remote path (in the same file) correctly hits the
   permission-checked, audited REST route. See §8, Finding S18 (the sharpest finding in this batch).
4. **B4 (offline, don't-trust-the-running-server audit-chain verification) does not exist.** `audit
   verify` is 100% REST and asks the live server to grade its own chain — the opposite of what
   ADR-108 §B.4 wants. This needs to be built new as `keyorix-server admin`, not reclassified from
   an existing command.
5. Every `/system` route is reachable from at most one place: the CLI's narrow
   `NewRemoteClient()`-fails fallback. No web UI, SDK, k8s-sync, MCP server, or operator code calls
   any `/system` route. This confirms ADR-107/ADR-108(C)'s premise directly, not by inference.

---

## 2. Per-command-group inventory

Legend: **F** = tries `common.NewRemoteClient()` first, falls back to `common.InitializeCoreService()`
(or `InitializeStorage()+core.NewKeyorixCore`) for local/embedded mode — the ADR-107 pattern. **R** =
remote-only, no fallback (refuses loudly if not connected). **L** = local-only, no remote path at all
(rare — mostly `encryption/`). Unless noted, "no behavior difference" means the local-mode path is a
plain, unauthenticated re-implementation of the same operation (the general ADR-108 "local mode
bypasses the API's authorization, audit and rate limits" pattern) with nothing command-specific to
add — that systemic pattern is stated once here rather than repeated on every row.

### 2.1 `secret` (internal/cli/secret/) — 62 leaf subcommands, the largest and highest-stakes group

Every `secret` subcommand already has a working REST route; **0 hard GAPs** in this group (2
CLI-feature-only notes: `create` has no `--tags`/`--metadata`/`--classification` flags though the
REST DTO accepts them; `template apply`'s REST route has no CLI subcommand).

| Command | File:line | Pattern | REST route | Permission | Class |
|---|---|---|---|---|---|
| `secret create` | create.go:57-115 | F | `POST /secrets` (in-handler auth) | `secrets.write` + per-project MFA policy | API |
| `secret get` (`--id`/`--name`/`--ref`) | get.go:69-219 | F | `GET /secrets/{id}[?include_value]`, `/secrets/value?ref=`, `/secrets?...` (name, client-filtered) | `secrets.read` scoped | API |
| `secret update` | update.go:64-192 | F | `PUT /secrets/{id}` | `secrets.write` scoped | API |
| `secret delete` | delete.go:45-229 | F (via `InitializeStorage()`, not `InitializeCoreService()`) | `DELETE /secrets/{id}` | `secrets.delete` scoped | API |
| `secret list` | list.go:55-180 | F | `GET /secrets` (in-handler auth, union-of-scopes) | in-handler | API — local mode documented as "lists everything, admin tool" in its own `--help` |
| `secret info` | info.go:42-92 | R | `GET /secrets/{id}` + `GET /secrets/{id}/tags` | `secrets.read` scoped | CLIENT-ONLY |
| `secret versions` | versions.go:38-206 | F (`InitializeStorage()`) | `GET /secrets/{id}/versions` | `secrets.read` scoped | API |
| `secret version comment {add,list,delete}` | version_comments.go | R | `POST/GET/DELETE /secrets/{id}/versions/{v}/comments[/{c}]` | write/read/manage scoped | CLIENT-ONLY |
| `secret rollback` | rollback.go:33-37 | R | `POST /secrets/{id}/rollback` | `secrets.write` scoped | CLIENT-ONLY — the one mutation core method (`RollbackSecret`) that audits itself directly, unlike create/update/delete |
| `secret diff <name> <from> <to>` | diff.go:57-111 | F (`InitializeStorage()`) | `GET /secrets/by-name`, `GET /secrets/{id}/versions/{from}/diff/{to}` | `secrets.read` scoped | API — remote resolves by name+project/env filter; embedded requires `--id` (capability asymmetry, own doc string) |
| `secret tags` | tags.go:34-37 | R | `GET/PUT /secrets/{id}/tags` | read/write scoped | CLIENT-ONLY |
| `secret description` | description.go:33-36 | R | `GET /secrets/{id}`, `PATCH /secrets/{id}/description` | write scoped | CLIENT-ONLY |
| `secret acl {list,grant,revoke}` | acl.go:128-134 | R | `GET/POST/DELETE /secrets/{id}/acl[/{aclId}]` | `secrets.manage` scoped | CLIENT-ONLY — correctly so: `RemoteStorage`'s ACL storage methods are hard stubs, so an embedded fallback couldn't work under `storage.type: remote` anyway |
| `secret folder {create,list,delete}` | folder.go:48-250 | F | `POST/GET/DELETE /folders[/{id}]` | in-handler create / `secrets.read` scoped list / `secrets.delete` scoped delete | API — **`folder delete`'s embedded path has a real footgun, see §8 Finding S4** |
| `secret move` | move.go:35-38 | R | `POST /secrets/{id}/move` | write scoped | CLIENT-ONLY |
| `secret copy` | copy.go:30-33 | R | `POST /secrets/{id}/copy` | read (source, route) + write (target, in-handler) | CLIENT-ONLY |
| `secret copy-environment` | copy_environment.go:33-36 | R | `POST /projects/{id}/environments/{envId}/copy-secrets` | write (project) + read (source env) dual-gate | CLIENT-ONLY — dual-gate exists specifically to stop write-only exfiltration; having only one caller (no embedded path) removes the risk of under-replicating that logic |
| `secret templates {list,get,create,delete}` | templates.go | R | `GET/POST/DELETE /secret-templates[/{id}]` | read/write | CLIENT-ONLY |
| `secret deps {list,add,rm,impact}` | dependencies.go:222-228 | R | `GET/POST/DELETE /secrets/{id}/dependencies[/{depId}]`, `GET .../impact` | read/write scoped | CLIENT-ONLY |
| `secret access` / `access-log` | access.go:43-76 | R | `GET /secrets/{id}/access`, `GET /secrets/{id}/access-log` | read scoped | CLIENT-ONLY |
| `secret {set,get,clear}-schedule` | schedule.go:158-164 | R | `PUT/GET/DELETE /secrets/{id}/schedule` | `secrets.manage` scoped | CLIENT-ONLY |
| `secret suspend` / `resume` | suspend.go:29-49 | R | `POST /secrets/{id}/suspend`, `.../resume` | write scoped | CLIENT-ONLY — distinct from the `/system` CAS route `TransitionSecretStatusProxy`; unaffected by that route's fate |
| `secret trash` / `restore` | recycle.go:38-72 | R | `GET /projects/{id}/secrets/deleted`, `POST /secrets/{id}/restore` | read (project) / write (deleted-secret scope) | CLIENT-ONLY |
| `secret classify` | classify.go:33-36 | R | `PATCH /secrets/{id}/classification` | write scoped | CLIENT-ONLY |
| `secret export` | export.go:88-202 | R | `GET /projects`, `GET .../environments`, `GET /secrets?...`, `GET /secrets/{id}?include_value` ×N | read scoped | API — N+1 per-secret fetch is *more* audit fidelity than a hypothetical bulk endpoint, not less |
| `secret import` (file mode) | import.go:119-270 | R | `GET /projects`, `GET .../environments`, `POST /secrets` ×N | in-handler | API |
| `secret import --source {vault,aws,azure,gcp}` | import.go | R (never touches Keyorix for the fetch half) | n/a | n/a | **CLIENT-ONLY** — reads live cloud/Vault credentials locally, never sends them to Keyorix; in tension with ADR-108's "SBOM lists no cloud SDKs" goal unless deliberately dropped or shipped as a plugin — flagged as an open scope question |
| `secret render` | render.go:41-137 | R | *should* use `POST /projects/{id}/secrets/render` (exists, unused) | `secrets.read` (project) | API, **wrong route today — see §8 Finding S2** |
| `secret explain` | explain.go:143 | L (no calls at all) | n/a | n/a | CLIENT-ONLY — static lookup table |
| `secret expiring` | expiring.go:27-63 | R | `GET /projects/{id}/secrets/expiring` | read (project) | API |
| `secret orphaned` | orphaned.go:23-55 | R | `GET /projects/{id}/secrets/orphaned` | read (project) | API |
| `secret name-conformance` | name_conformance.go:36-101 | R | `GET /projects/{id}/secrets/name-conformance`, `GET /secrets/name-conformance` (org-wide) | read (project) / **`audit.read`** (org-wide) | API — org-wide help text wrongly says `system.read` (doc-only mismatch, §8 Finding S7) |
| `secret quota-report` | quota.go:21-50 | R | `GET /secrets/quota-report` | `audit.read` | API — help text wrongly says `secrets.read` (doc-only, §8 Finding S7) |
| `secret ownership-history` | ownership_history.go:24-57 | R | `GET /secrets/{id}/ownership-history` | read scoped | API |
| `secret reassign-owner` | reassign_owner.go:18-44 | R | `POST /projects/{id}/secrets/reassign-owner` | **`roles.assign`** (project) | API — help text wrongly claims `secrets.write` + per-secret auth; actual is one project-level `roles.assign` check gating the whole bulk op (§8 Finding S7) |
| `secret rotate` | rotate.go:43-89 | R | lookup step broken (same bug as `render`), `POST /secrets/{id}/rotate` correct | write scoped | API, **broken lookup — §8 Finding S2, the write-path (worse) half** |
| `secret rotation-simulate` | rotation_dryrun.go:38-72 | R | `POST /secrets/{id}/rotation/simulate` | read scoped | API |
| `secret auto-rotate` | autorotate.go:21-56 | R | `PATCH /secrets/{id}/auto-rotate` | write scoped | API |
| `secret bulk-rotate` | bulk_rotate.go:34-145 | R | `POST /projects/{id}/secrets/bulk-rotate` | write (project) | API |
| `secret bulk-rename` | bulk_rename.go:42-119 | R | `POST /projects/{id}/secrets/bulk-rename` | write (project) | API |
| `secret bulk-delete` | bulk_delete.go:38-201 | **F** | `POST /projects/{id}/secrets/bulk-delete` | delete (project) | API (remote) / **DROP** (embedded — see §8 Finding S5) |
| `secret scan` | scan.go:19-159 | L | n/a | n/a | CLIENT-ONLY — local filesystem/git regex scan for hardcoded secrets |
| `secret score` | score.go:29-180 | **F** | `GET /secrets/{id}/risk` | read scoped | API (remote) / **DROP** (embedded — no authz, possibly no audit either, §8 Finding S6) |
| `secret blast-radius` | blast_radius.go:34-68 | R | `GET /secrets/{id}/blast-radius` | read scoped | API |
| `secret fix` | fix.go:47-212 | L | n/a | n/a | CLIENT-ONLY — local source-tree rewriter |
| `secret cert` | certificate.go:31-47 | R | `GET /secrets/{id}/certificate` | read scoped | API |
| `secret audit` | audit.go:27-60 | R | `GET /secrets/{id}/audit` | read scoped | API |

**Systemic findings for this group** (detailed in §8): embedded-mode `create`/`update`/`delete`
perform no authorization check and emit no `secret.created`/`secret.updated`/`secret.deleted` audit
event at all (`internal/core/secrets.go`'s `CreateSecret`/`UpdateSecret`/`DeleteSecret` call no
`LogSecret*` helper — that only happens in the HTTP handler layer). Embedded-mode `get --show-value`/
`get --ref` never audit a value read either, though max-reads enforcement is unaffected (it lives in
`GetSecretValue` itself, called from both paths). `secret folder delete`'s embedded path has no
type-guard the REST route has and can silently delete a SECRET instead of a folder. `bulk-delete` and
`score` are the only two `secret` commands with a genuine embedded/local-DB fallback (not a
`/system`-proxy one) — see Findings S5/S6.

### 2.2 `project`, `group`, `invite`, `share`, `user` — 51 leaf subcommands

All five packages follow the ADR-107 `NewRemoteClient()`-first pattern almost without exception.
ADR-107 itself directly traced 5 commands (`user update`, `group create/update/delete`, `invite
revoke`) and found their embedded/`RemoteStorage` fallback is real but narrow, and — for the 3 group
commands — **already authority-equivalent** to the REST path (the `/system` proxy's
`requireGroupsProxyUsersWrite` re-derives the identical `users.write` check, closed independently of
ADR-107 during the F5/F6 campaign). This inventory re-verified all 5 and extended the same trace to
every other command in these packages.

**`project` (14 leaf + 1 container):**

| Command | File:line | Pattern | REST route | Permission | Class |
|---|---|---|---|---|---|
| `project create` | create.go:19-83 | F | `POST /projects` | `secrets.write` (global) | API |
| `project list` | list.go:12-60 | F | `GET /projects` | `secrets.read` (global) | API |
| `project use <name>` | use.go:14-76 | F (validate only) | `GET /projects` (validate) | — | CLIENT-ONLY — mutation is writing `active_project` to `~/.keyorix/cli.yaml` |
| `project current` | current.go:13-32 | L | n/a | n/a | CLIENT-ONLY |
| `project describe [name]` | describe.go:16-136 | F | `GET /projects`, `GET .../environments` | read scoped | API — **GAP**: remote branch never prints a secret count the embedded branch does; no missing route, `describe` just never calls `/projects/{id}/stats` |
| `project stats <name>` | stats.go:22-208 | F | `GET /projects/{id}/stats` | read scoped | API |
| `project hygiene <id>` | hygiene.go:21-59 | **R** (no fallback at all, unlike siblings) | `GET /projects/{id}/hygiene[?unused_days=&expiring_days=&stale_days=]` | read scoped | API — CLI never sends the optional query overrides the route supports (CLI-completeness gap, not a REST gap); also the one `project` command with no local-mode path even though `core.ProjectHygieneSummary` exists and could back one |
| `project health <name>` | health.go:32-177 | F | `GET /projects/{id}/health[?limit=]` | read scoped | API |
| `project environments <id>` (legacy alias) | environments.go:13-50 | F | same as `env list` | read scoped | **DROP candidate** — confirmed backward-compat alias (`project.go:34-35`'s own comment), functionally identical to `env list`; flag for a product decision on whether to keep, not a unilateral drop |
| `project env list` | env.go:29-64 | F | `GET /projects/{id}/environments` | read scoped | API |
| `project env create` | env.go:71-113 | F | `POST /projects/{id}/environments` | write scoped | API |
| `project env delete <id>` | env.go:120-213 | F | `DELETE /environments/{id}` | delete, scoped from the env's own project | API — CLI's optional `--project` cross-check is a client-only safety net with no server equivalent; REST's own scope resolution is correct either way, but the CLI safety net must be ported forward deliberately, not assumed |
| `project env clone <src> <dst>` | env_clone.go:17-122 | F | `POST /projects/{id}/environments/{envId}/clone` | write (project) + read (source env), dual-gate | API (remote) / functionally broken (embedded) — **§8 Finding S8**: hardcoded `"cli"`/`0` actor, fails closed on the resulting zero-ID permission check, but misreports the 100%-failure as "already exist in destination" |

**`group` (8 leaf):**

| Command | File:line | Pattern | REST route | Permission | Class |
|---|---|---|---|---|---|
| `group create` | create.go:18-68 | F | `POST /groups` | `users.write` | API — ADR-107-confirmed, authority-equivalent via `/system` proxy's `requireGroupsProxyUsersWrite` |
| `group get` | get.go:15-51 | F | `GET /groups/{id}` | `users.read` | API |
| `group update` | update.go:20-67 | F | `PUT /groups/{id}` | `users.write` | API — ADR-107-confirmed |
| `group delete` | delete.go:21-95 | F | `DELETE /groups/{id}` | `users.write` | API — ADR-107-confirmed |
| `group list` | list.go:11-52 | F | `GET /groups` | `users.read` | API |
| `group members` | members.go:15-74 | F | `GET /groups/{id}/members` | `users.read` | API |
| `group add-member` | add-member.go:19-58 | F | `POST /groups/{id}/members` | `roles.assign` | API |
| `group remove-member` | remove-member.go:19-60 | F | `DELETE /groups/{id}/members/{userId}` | `roles.assign` | API |

**`invite` (4 leaf):**

| Command | File:line | Pattern | REST route | Permission | Class |
|---|---|---|---|---|---|
| `invite send` | send.go:38-95 | F | `POST /projects/{id}/invitations` | `roles.assign` (project) | API — embedded's `requireInviteAuthority` matches exactly |
| `invite list` | list.go:34-86 | F | `GET /projects/{id}/invitations` | `users.read` (project) | API — **embedded's `requireInviteAuthority` checks `roles.assign`, STRICTER than the route's actual `users.read`** — fails closed, not open, but a real parity gap (§8 Finding S9) |
| `invite revoke` | revoke.go:34-71 | F | `DELETE /projects/{id}/invitations/{invitationId}` | `roles.assign` (project) | API — the exact command ADR-107 traced; re-confirmed accurate |
| `invite resend` | resend.go:25-70 | F | `POST /projects/{id}/invitations/{invitationId}/resend` | `roles.assign` (project) | API |

**`share` (7 leaf):**

| Command | File:line | Pattern | REST route | Permission | Class |
|---|---|---|---|---|---|
| `share create` | create.go:40-114 | F | `POST /secrets/{id}/share` | write scoped + in-core live-owner check | API |
| `share list` | list.go:29-88 | F | `GET /secrets/{id}/shares` | read scoped + in-handler owner-only re-check | API — **embedded path uses the non-authorization-checked core variant** (documented in-repo as accepted, `list.go:41-55` "cli-connect-007") — §8 Finding S10 |
| `share update` | update.go:37-92 | F | `PUT /shares/{id}` | write scoped (share) + in-core live-owner check | API — minor CLI output-parity gap only (remote branch prints 3 of ~8 available fields) |
| `share revoke` | revoke.go:27-51 | F | `DELETE /shares/{id}` | write scoped (share) + in-core live-owner check | API |
| `share self-remove` | self_remove.go:15-35 | **R**, no fallback | `DELETE /secrets/{id}/self-share` | self-service (RecipientID == caller) | API — the one command in the package already at ADR-107's target shape; structurally distinct from `revoke` (own-share removal vs. owner-driven revocation of anyone's share) |
| `share shared-secrets [--user-id]` | shared_secrets.go:29-88 | F | `GET /shared-secrets` (self only, hardcoded to caller) | `secrets.read` (global) | API, with a **GAP**: no REST route can query an arbitrary user's shared-secrets list; embedded's `--user-id` can, with zero check (§8 Finding S10) — needs new admin-scoped REST surface, not a `keyorix-server admin` item |
| `share group-shares` | group_shares.go:32-77 | F | `GET /groups/{id}/shares` | `secrets.read` (global) + in-core `#G10` actor-authorization check | API — the strongest-parity command in the package; `#G10` already closed the enumeration gap here specifically |

**`user` (11 leaf):**

| Command | File:line | Pattern | REST route | Permission | Class |
|---|---|---|---|---|---|
| `user create` | create.go:56-229 | F | `POST /users` (all 3 credential modes) | `users.write` | API — plain-password local branch has NO `--by`/authority check at all (weaker even than its own sibling modes) |
| `user get` | get.go:59-112 | F | `GET /users/{id}`, `GET /users/by-email` | `users.read` (group-level) | API |
| `user update` | update.go:54-103 | F | `PUT /users/{id}` | `users.write` (group-level only — **no admin-rank ceiling**, §8 Finding S1) | API — **local mode has NO `--by`/authority check at all, unlike every other lifecycle command in this package (§8 Finding S1b)**; ADR-107's "2 round trips" claim undercounts (3, for the deactivating case) and its "different response struct" claim is confirmed with a sharper edge: the local response is never confirmed by the server at all |
| `user delete` | delete.go:35-107 | F | `DELETE /users/{id}` | `users.delete` | API — local `--by` actually attributes the audit actor; remote `--by` is silently ignored (real UX divergence, not a security gap — remote's real-session attribution is the more correct one) |
| `user list` | list.go:30-85 | F | `GET /users` | `users.read` (group-level) | API |
| `user suspend` | lifecycle.go:34-53 | F | `POST /users/{id}/suspend` | `users.write` | API |
| `user reactivate` | lifecycle.go:55-74 | F | `POST /users/{id}/reactivate` | `users.write` | API |
| `user force-password-reset` | lifecycle.go:76-96 | F | `POST /users/{id}/require-password-reset` | `users.write` | API |
| `user revoke-sessions` | lifecycle.go:103-138 | F | `POST /users/{id}/revoke-sessions` | `users.write` | API |
| `user resend-setup-link` | setup_link.go:24-52 | F | `POST /users/{id}/resend-setup-link` | `users.write` | API — checked explicitly against ADR-108 B2 and found unrelated: normal `users.write`-gated onboarding redelivery, not a "everyone locked out" recovery mechanism |
| `user suspend-inactive` | inactivity_suspend.go:38-97 | F | `POST /admin/jobs/suspend-inactive-users` | **`system.write`** (deployment-wide sweep, not a resource-scoped `users.*` permission) | API — the most symmetric command in the package: both paths call the identical `core.SuspendInactiveUsers`, actor `0` on both |

### 2.3 `machine`, `pat`, `rbac`, `auth` — 35 leaf subcommands

**`machine` (14 leaf, ADR-023/030/031):**

| Command | File:line | Pattern | REST route | Permission | Class |
|---|---|---|---|---|---|
| `machine create` | create.go:34-74 | F | `POST /projects/{id}/machine-identities` | `roles.assign` (project) | API |
| `machine list` | list.go:24-36 | F | `GET /projects/{id}/machine-identities` | `users.read` (project) | API |
| `machine describe <ref>` | describe.go:24-50 | F | (fetches list, filters client-side; no dedicated by-ref GET route used) | `users.read` (project) | API |
| `machine suspend/reactivate/revoke <ref>` | lifecycle.go:17-93 | F | `PUT /projects/{id}/machine-identities/{machineId}` (action body) | `roles.assign` (project) | API |
| `machine binding add/list/rm` | binding.go:33-205 | F | `POST/GET/DELETE .../oidc-bindings[/{id}]` | `roles.assign`/`users.read` scoped | API |
| `machine token issue/list/revoke` | token.go:44-268 | F | `POST/GET/DELETE .../tokens[/{id}]` | `roles.assign`/`users.read` scoped, `BlockWhenImpersonating` on issue | API |
| `machine token-hygiene` | token_hygiene.go:25-56 | R | `GET /machine-token-hygiene` | `audit.read` | API |
| `machine audit` | audit.go:22-52 | R | `GET /machine-identities/audit` (+`.csv`) | `audit.read` | API |

Every `machine` command with a fallback correctly threads `common.ResolveActorID()` through to the
core call — this package is the positive counter-example to rbac's D1 finding below.

**`pat` (6 leaf, self-service — no local mode anywhere in the package):**

| Command | File:line | REST route | Permission | Class |
|---|---|---|---|---|
| `pat create` | pat.go:72-115 | `POST /auth/tokens` | self-service, `BlockWhenImpersonating` | API |
| `pat list` | pat.go:118-145 | `GET /auth/tokens` | self-service | API |
| `pat revoke <id>` | pat.go:159-178 | `DELETE /auth/tokens/{id}` | self-service | API |
| `pat list-expired` | expired.go:21-48 | `GET /auth/tokens/expired` | self-service | API |
| `pat cleanup-expired` | expired.go:50-64 | `DELETE /auth/tokens/expired` | self-service | API |
| `pat hygiene` | hygiene.go:33-57 | `GET /pat-hygiene` | `audit.read` | API |

**`rbac` (11 leaf — dual-mode via `InitializeStorage()+core.NewKeyorixCore`, not `InitializeCoreService()`):**

| Command | File:line | REST route | Permission | Class |
|---|---|---|---|---|
| `rbac assign-role` | assign_role.go:51-88 | `POST /user-roles` | `roles.assign` scoped to body target | API — **§8 Finding S11 (D1)**: embedded path's core method takes no actor param at all |
| `rbac remove-role` | remove_role.go:40-67 | `DELETE /user-roles` (body-carrying) | same | API — same Finding S11 |
| `rbac list-roles` | list_roles.go:18-47 | `GET /roles` | `roles.read` | API |
| `rbac list-user-roles --user` | list_user_roles.go:26-57 | `GET /users/{id}/roles` | `roles.read` | API |
| `rbac list-permissions --user` | list_permissions.go:26-57 | no single by-email route; assembled client-side from `GET /roles/{id}/permissions` per role | `roles.read` per call | API — not a GAP, matches the documented "no single endpoint, composed client-side" shape |
| `rbac check-permission --user --permission` | check_permission.go:33-66 | same composition | same | API |
| `rbac assign-role-to-group` / `remove-role-from-group` | group_role.go:41-139 | `POST/DELETE /groups/{id}/roles[/{roleId}]` | `roles.assign` | API — embedded path correctly threads `common.ResolveActorID()`, contrast with Finding S11 |
| `rbac list-group-roles` | group_role.go:187+ | `GET /groups/{id}/roles` | `roles.read` | API |
| `rbac audit-logs` | audit_logs.go:29-97 | `GET /audit/rbac-logs` | `audit.read` (group) | API — embedded path calls a `RemoteStorage`-backed core method whose live/stub status wasn't found in the reachability census's explicit lists (unresolved, flag for Phase 0) |
| `rbac export-matrix` | export_matrix.go:34+ | `GET /rbac/permission-matrix` | `roles.read` | API — explicitly relocated OUT of `/system` (#G79) specifically to fix this CLI command's 404 |

**`auth` (4 leaf):**

| Command | File:line | Calls today | REST route | Class |
|---|---|---|---|---|
| `auth login [--server]` | auth.go:74-169 | Writes `storage.type: remote`+credentials to **`./keyorix.yaml`** (CWD-relative, `#G73`/`#G74`-flagged untrusted); verifies via `GET /auth/profile` first | `GET /auth/profile` (self-service) | CLIENT-ONLY |
| `auth logout` | auth.go:194-217 | Local config edit only, does NOT revoke the server-side PAT | none | CLIENT-ONLY — §8 Finding S12 (informational) |
| `auth status` | auth.go:219-254 | Local config read only, no live verification | none | CLIENT-ONLY |
| `auth mfa stepup --code` | mfa_stepup.go:40-68 | R | `POST /auth/mfa/stepup` | API |

### 2.4 `encryption`, `breakglass`, `migrate`, `dynamic-secret`, `rotation` — 35 leaf subcommands

**`encryption` (15 leaf) — the flagship ADMIN-B3 cluster.** Every command operates on local key
files and/or a directly-opened DB (`storage.OpenGormDB`); none has ever had a `NewRemoteClient()`
branch, and every write-path command explicitly refuses `cfg.Storage.Type == "remote"`. The only
related REST route in the whole router is the read-only `GET /system/encryption-config`
(config dump, not an operation) — **GAP is total for this package by design**, not an oversight;
this is exactly ADR-108 §B.3's "full KEK re-encryption sweep" family.

| Command | File:line | Local mechanism | Server-stop required? | Class |
|---|---|---|---|---|
| `encryption init` | encryption.go:174-201 | shared key lock | No | ADMIN-B3 |
| `encryption status` | encryption.go:203-238 | shared key lock, read-only | No | ADMIN-B3 |
| `encryption rotate` | encryption.go:279-358 | exclusive key lock + raw `*gorm.DB`, full re-encryption sweep (ADR-010) | **Yes**, enforced twice (CLI gate + inside `RotateDEKWithSweep`) | ADMIN-B3 — the literal textbook case |
| `encryption upgrade-aad` | encryption.go:413-460 | shared lock (brief per-table write lock only) | No | ADMIN-B3 |
| `encryption validate` | encryption.go:471-510 | shared lock, read-only | No | ADMIN-B3 (borderline B1/diagnose) |
| `encryption fix-perms` | encryption.go:512-545 | shared lock | No | ADMIN-B3 (borderline B1/repair) |
| `encryption shamir-split` | shamir_split.go:29-134 | pure crypto + local file write, **no config/DB import at all** | N/A | **not ADMIN — genuinely CLIENT-ONLY**, the one command in this package that structurally satisfies ADR-108's thin-CLI constraint today, unmodified |
| `encryption rotate-kek` | rotate_kek.go:64-149 | exclusive lock, no DB access at all | **Yes**, doc comment states it plainly, double-enforced | ADMIN-B3 |
| `encryption migrate-provider` | migrate_provider.go:348-428 | exclusive lock enforced INSIDE `RewrapDEKWithProvider`, not at the CLI's own call site | **Yes** | ADMIN-B3 — flag for whoever builds the admin subcommand: a thin wrapper calling a different re-wrap path would silently lose this |
| `encryption migrate-provider cleanup` | migrate_provider.go:153-183 | no lock at all — operates only on backup files | Not obviously, **not fully determined** (a narrow TOCTOU against a concurrent migrate-provider run is theoretically possible, not confirmed reachable) | ADMIN-B3 |
| `encryption auth-encryption status/enable/migrate/validate` | auth_encryption.go, auth_encryption_migrate.go, auth_encryption_validate.go | shared lock, direct `*gorm.DB` | No | ADMIN-B3 |
| `encryption auth-encryption rotate` | auth_encryption.go:173-198 | **no lock call at all**, unlike its 4 siblings in the same file | Unverified — §8 Finding S13 | ADMIN-B3 |

**`breakglass` (3 leaf) — already fully conforms, zero migration work:**

| Command | File:line | REST route | Permission | Class |
|---|---|---|---|---|
| `break-glass activate` | breakglass.go:52-78 | `POST /projects/{id}/break-glass` | un-gated by design (justification + audit + auto-expiry instead), `BlockWhenImpersonating` | API |
| `break-glass list` | breakglass.go:80-110 | `GET /projects/{id}/break-glass` | `roles.read` (project) | API |
| `break-glass revoke` | breakglass.go:112-132 | `POST /projects/{id}/break-glass/{activationId}/revoke` | `roles.assign` (project) | API |

Not ADR-108 §B.2 ("recover-admin") — break-glass is project-scoped, self-service, and requires an
already-authenticated session; B2 is specifically for when no admin session exists at all.

**`migrate` (1 leaf):**

| Command | File:line | REST route | Class |
|---|---|---|---|
| `migrate user-to-machine <username>` | user_to_machine.go:48-100 | `POST /projects/{id}/machine-identities/migrate-from-user` (route exists, matching both permissions the local path hand-derives: `roles.assign`@project + `users.write`@global) | Currently local-DB-only by deliberate design (refuses if remote is configured) — **should collapse to API**, not a genuine ADMIN item; nothing is lost by dropping the local path and adding a remote-calling branch instead |

**`dynamic-secret` (9 leaf) — fully conforms, zero migration work.** All 9 commands (`get-config`,
`classify`, `list`, `issue`, `leases`, `renew`, `revoke`, `revoke-all`, `create`) are pure REST, no
fallback: `POST/GET/PATCH` under `/dynamic-secrets/{configs,leases}*`, `secrets.read`/`secrets.write`
scoped to the config/lease's project+environment.

**`rotation` (7 leaf) — fully conforms, zero migration work.** `list`/`create`/`show`/`delete`/
`status` under `/rotation-policies*`, `plan [project-id | --all-projects]` under
`/projects/{id}/rotation-plan` or global `/rotation-plan`, `order <project-id>` under
`/projects/{id}/rotation-order` — all `secrets.read`/`secrets.write` scoped as expected;
`--all-projects` deliberately steps up to a GLOBAL `secrets.read` grant (documented, not a gap).

### 2.5 `audit`, `anomalies`, `notification`, `accessreview`, `request` — 37 leaf subcommands

**`audit` (6 leaf) — REST-only, `audit.read`-gated (except checkpoint/migrate which need
`system.write`):**

| Command | File:line | REST route | Permission | Class |
|---|---|---|---|---|
| `audit verify` | audit.go:135-195 | `GET /audit/verify` | `audit.read` | API today — **but does NOT satisfy ADR-108 §B4** (see §6 GAP-1: it asks the live server to verify its own chain, the opposite of B4's "without trusting the running server" premise) |
| `audit export` | audit.go:227-274 | `GET /audit/export` (paginated) | `audit.read` | API |
| `audit checkpoint` | audit.go:332-351 | `POST /audit/checkpoint` | `system.write` | API |
| `audit migrate-chain-encoding` | audit.go:382-413 | `POST /audit/migrate-chain-encoding` | `system.write` | API |
| `audit logs` | audit.go:455-475 | `GET /audit/logs` | `audit.read` | API |
| `audit search` | audit.go:579-599 | `GET /audit/search` | `audit.read` | API |

**`anomalies` (8 leaf across anomalies.go/config.go/escalation.go), all REST-only:**

`anomalies list`/`acknowledge` → `GET/POST /audit/anomalies[/{id}/acknowledge]` (`system.read`/
`system.write`). `anomaly config get/set` → `GET/PUT /admin/anomaly-config` (`system.read`/
`system.write` — registered outside the `/system` proxy group; naming coincidence only).
`anomaly escalation list/create/delete/run` → `GET/POST/DELETE /alert-escalation-policies[/{id}]`,
`POST /admin/jobs/run-alert-escalation` — all `system.write`, including the two GETs (a router
design choice, not a CLI/REST mismatch). All API, 0 GAPs.

**`notification channel` (5 leaf), REST-only:**

`list`/`add`/`get`(list+filter)/`update`(resolve+PUT)/`delete`(resolve+DELETE) →
`GET/POST/PUT/DELETE /notification-channels[/{id}]`, `system.write`. All API. Aside: REST also
exposes `PUT/GET /notification-channels/{id}/retry-policy` with no CLI subcommand — feature gap,
not a REST gap.

**`accessreview` (3 + 5 campaign leaf), REST-only:**

`access-review [--project-id]`/`revoke`/`attest` → `GET/POST /projects/{id}/access-review[/revoke|/attest]`,
`roles.read`/`roles.assign` (project). `access-review campaign open/list/show/decide/close` →
`/projects/{id}/access-review/campaigns*`, same permission split. All API, 0 GAPs. The `/system`
proxy's separate `access-review-campaigns*` family is confirmed dead-to-CLI (zero matches anywhere
in `internal/cli/`).

**`request` (8 top-level + 3 template leaf) — the one genuinely dual-mode package in this cluster:**

| Command | File:line | REST route | Class |
|---|---|---|---|
| `request access` | access.go | `POST /projects/{id}/access-requests` (self-service, no permission middleware) | API — local `--user` can file "as" an arbitrary user; remote is hard-wired to the caller's own session (§8 Finding S14) |
| `request list` | list.go | `GET /projects/{id}/access-requests` | API — local `requireListAuthority` matches the route's `roles.assign` exactly, no skip |
| `request withdraw` | withdraw.go | `POST /projects/{id}/access-requests/{id}/withdraw` (self-service) | API — same `--user` shape as `access` |
| `request review` (role-scoped) | review.go | `PUT /projects/{id}/access-requests/{id}` | API |
| `request review` (secret-scoped approve) | review.go:90,162-176 | **none** — remote explicitly refused with a loud error rather than silently mis-routed | **GAP** — see §6 GAP-1 |
| `request secret-access` | secret_access.go:44-84 | **none anywhere** — local-only by explicit, runtime-enforced design | **GAP** — see §6 GAP-1 |
| `request bulk-approve` | bulk.go:47-52 | `POST /access-requests/bulk-approve` (exists) | API, **but the CLI never calls it** — §8 Finding S15 (GAP-F-BULK) |
| `request bulk-reject` | bulk.go:105-110 | `POST /access-requests/bulk-reject` (exists) | API, same bug — Finding S15 |
| `request rejection-templates list/add` | bulk.go:189-248 | `GET/POST /rejection-reason-templates` | API — correctly checks `NewRemoteClient()` |
| `request rejection-templates delete` | bulk.go:294-299 | `DELETE /rejection-reason-templates/{id}` (exists) | API, same bug as bulk-approve/reject — Finding S15 |

Every core method reached by `request`'s local-mode paths that has a REST sibling was checked for a
skipped authority/audit check — none found; local mode re-implements the identical `Authorize(...)`
call the router middleware would do, with in-code comments explaining why. The one systemic pattern
here (§8, noted once) is that 4 local-mode commands (`access`, `withdraw`, `list --by`,
`review --by`) resolve identity from a caller-supplied email flag with no session to verify it against
— already documented in-repo as accepted for embedded mode, and structurally eliminated once ADR-108
removes local mode.

### 2.6 `risk`, `sod`, `legalhold`, `compliance`, `hygiene`, `trust` — 24 leaf subcommands

**None of these 23 non-`trust` commands has a local-mode or `/system`-proxy fallback at all** — every
one is `common.NewRemoteClient()`-only, confirmed by grep (zero matches for
`InitializeCoreService|core.KeyorixCore|RemoteStorage` anywhere in these 5 packages). This means
Finding-5's "does local mode skip an authz/audit check" question is structurally inapplicable here —
there is only one code path per command. All routes below already exist; 0 hard GAPs except the
compliance evidence round-trip bug (§8, Finding S16 / §6 GAP-2).

**`risk` (4 leaf):** `list[--all]`/`add`/`approve`/`revoke` → `/risk-exceptions*`, `audit.read`
(list) / `system.write` (mutations). Doc-comment inaccuracy only: CLI help says list needs
`system.read`, actual gate is `audit.read`.

**`sod` (4 leaf):** `policy list/create/delete`, `violations` → `/sod/policies*`, `/sod/violations`;
`system.read`/`system.write`/`audit.read` respectively. Same doc-comment class of inaccuracy on
`violations` (says `system.read`, actual `audit.read`).

**`legalhold` (3 leaf):** `status`/`place`/`lift` → `/legal-hold*`, `audit.read` (status) /
`system.write` (mutations). CLI's `--yes` confirm on `lift` is the one genuinely CLIENT-ONLY piece;
server-side authorization is independent of it. Same doc-inaccuracy class on `status`.

**`hygiene` (1 leaf):** `hygiene [--unused-days --expiring-days --stale-days]` →
`GET /hygiene[?...]`, `audit.read`. CLI's own printed `--help` text (not just a source comment) is
wrong here — says `system.read`.

**`compliance` (10 leaf):** `report`/`export`/`controls[.csv]`/`verify`/`digest[/send]`/
`permission-changes`/`permission-baseline[.csv]`/`inventory`/`credential-trends`/
`rotation-by-backend` — all `audit.read`-gated REST routes matching 1:1, this package's own doc
comments are the one correct-permission-doc set found across the whole G cluster. **The one real
functional GAP in this whole cluster**: `compliance export` followed by `compliance verify` can
**never produce VALID for a genuinely untampered pack** — `export` calls `GenerateComplianceEvidence`
(never signs, never assigns a canonical filename, never writes `.sig`), while the ONLY function that
ever produces a valid `(signature, filename)` pair, `ExportComplianceEvidence`, has exactly one
caller in the whole repo: the scheduled job in `server/main.go`. `verify`'s own POST body has no
`filename` field at all, though `VerifyComplianceEvidence`'s request struct declares one specifically
for AUD-009 filename-bound signatures. See §6 GAP-2 and §8 Finding S16.

**`trust` (1 leaf):** `trust keygen` — pure local ed25519 keypair generation via `internal/trust`,
no server call of any kind (confirmed: no `internal/cli/common`, no `net/http` import in the file).
CLIENT-ONLY, by design (ADR-062 — the private key must never touch the server).

### 2.7 `bundle`, `license`, `usage`, `billing`, `system`, `status`, `connect`, `config`, `run` — 23 leaf subcommands

**Correction to this batch's own framing**: `internal/cli/connect/` is CLI connection-mode state
(embedded↔client switch, `~/.keyorix/cli.yaml`), **not** cloud-connector (AWS/Azure/GCP backend)
registration — that lives under `internal/connect`, a different, non-CLI package out of scope here.

**`bundle`/`license`** (ADR-062/065, air-gap update tooling) — purely offline, no server call
anywhere in either package.

| Command | What it does | Class |
|---|---|---|
| `bundle build` | Signs a release tarball with an offline key | N/A/out of scope — Keyorix-internal release tooling |
| `bundle verify` | Verifies against the embedded pinned trust registry | CLIENT-ONLY, deliberately offline |
| `bundle import` | Same verify + license-gated (`airgap_updates`) local staging | CLIENT-ONLY |
| `license issue` | Mints a signed license token (Keyorix-internal signing key) | N/A/out of scope |
| `license install` | Writes a token file the server reads at its own startup | CLIENT-ONLY / undecided-admin — closer to B3 in spirit but not enumerated in ADR-108; flag as an open question |
| `license status` | Evaluates a local token file offline | CLIENT-ONLY as implemented; **GAP** if operators need the *running server's* actual license state remotely — no such route exists (`system info`'s `Features` map is feature-flags, not licensee/plan/expiry detail) |

**`usage`/`billing`** — one subcommand each, genuinely dual-mode:

| Command | REST route | Permission | Class |
|---|---|---|---|
| `usage show` | `GET /admin/usage[?days=&project_id=]` | `audit.read` | API — **embedded mode calls `core.GetUsageReport` directly with literally no `userID` parameter on the method signature — nothing for a permission check to even thread through** (§8 Finding S17) |
| `billing report` | `GET /admin/billing/report[?from=&to=&project_id=]` | `audit.read` | API — same shape, same missing-signature-parameter root cause (§8 Finding S17); the license-feature gate itself IS shared (lives inside `core.GenerateBillingReport`), only the `audit.read` authorization is skipped |

**`system` (6 leaf)** — a genuine mix, half ADMIN-B1, half already-correct API:

| Command | What it does | Class |
|---|---|---|
| `system init` (no `--server`) | Writes `keyorix.yaml`, creates DEK/salt dirs, creates an empty DB file (`O_EXCL`), touches a log file — pure host-filesystem setup, no server interaction | **ADMIN-B1** — literally provisions the files a server needs to start at all |
| `system init --server <url>` | `POST /system/init` (unauthenticated, bootstrap-token-gated, public-path listed) | API — already correct, needs only a module move |
| `system audit` | Local file-permission/ownership diagnostics on config + every key-material path | **ADMIN-B1** |
| `system validate` | `startup.ValidateStartup` — explicitly "the same validation that runs on system startup" | **ADMIN-B1** — the clearest literal match to B1's language of any command in this report |
| `system info` | `GET /system/info` | API, `system.read` |
| `system role-expiry-check` / `token-expiry-check` | `POST /admin/jobs/{role,token}-expiry-check` | API, `system.write` — a stale comment in `admin_jobs.go` claims these are nested under `/system`; verified by brace-matching they are NOT (the `/admin/jobs` group opens at router.go:2205, well after `/system` closes at :2078) — the CLI code is correct, only the handler's own comment is wrong |

**`status`** — branches on FOUR config states, not simple remote-vs-embedded. Remote branch
(`GET /health`, unauthenticated) is **API**, already correct. The `storage.type: remote`-in-config
and local/sqlite branches both go through `InitializeCoreService()`+`HealthCheck` — **DROP** under
ADR-108 Decision A (no local DB mode; "is my local SQLite file reachable" is meaningless to a
thin, DB-less CLI). **Version-skew relevance**: `status` reads literally nothing from `/health`'s
response body today (`rc.GetRaw` result is discarded entirely) — see §5.

**`connect`/`disconnect`/`connect status`** — CLIENT-ONLY, all three; writes/reads
`~/.keyorix/cli.yaml`, calls only already-existing `/auth/login` and `/health`. Already hardened
(anti-SSRF redirect refusal, cleartext-endpoint refusal, credentials never on argv). Dead code found
while reading this package's config backing: `CLIConfig.Connections[]` and its 4 methods
(`AddConnection`/`RemoveConnection`/`GetConnection`/`GetDefaultConnection`) have zero callers
anywhere outside their own definitions and tests — **DROP**, a whole unused "saved connections"
schema.

A second, separate piece of dead code sits one level up from any command package:
`internal/cli/modes.go`'s `NewCLI()`/`CLI`/`CLIMode` (the `EmbeddedMode`/`ClientMode`
auto-detecting dispatcher, `initEmbeddedMode`/`initClientMode`) has **zero production callers** —
`rg -n "NewCLI\(\)"` across `internal/cli` matches only `main_test.go`/`modes_s23_test.go`/
`modes_s24_test.go`. Every real command instead uses the per-file `common.NewRemoteClient()`/
`common.InitializeCoreService()` pattern documented throughout §2. **DROP** — this whole
mode-dispatch abstraction was superseded by the per-command pattern and never wired into
`rootCmd`/`Execute()` (`internal/cli/main.go`) at all; removing it is a pure deletion, not a
migration.

**`config`** (`keyorix.yaml`, distinct from `connect`'s `~/.keyorix/cli.yaml`) — `status`/
`set-remote`/`use-local`/`test-connection`: **DROP the whole group.** `set-remote`/`use-local`
configure exactly the `storage.type` mechanism ADR-108 Decision A/C removes outright; `status`/
`test-connection` exist only to inspect/exercise that state and become vestigial once it's gone.

**`run`** — traced ADR-107's flagged "second idiom" (`common.ResolveRemote()` called directly
instead of `common.NewRemoteClient()`) fully: `NewRemoteClient()` is *implemented as*
`ResolveRemote()` + `newHardenedRemoteClient()`; `run` calls `ResolveRemote()` directly only to
override the token half for `--token`, then builds its client via
`NewRemoteClientWithCredentials`, which shares the identical hardened `http.Client`. **Not a
distinct bypass** — confirmed, not assumed. Remote path (4 existing routes: `/projects`,
`/projects/{id}/environments`, `/secrets`, `/secrets/{id}?include_value=true`) is **API**, already
correct. Embedded/local path is **DROP** — and dropping it is a security fix, not just cleanup: see
§8 Finding S18, the sharpest finding in this batch.

---

## 3. `/system` route caller census

`server/http/router.go:1126` registers the `/system` route group (`r.Route("/system", ...)`),
gated by `RequirePermission(permSystemWrite)` at `router.go:1127`, closing at `router.go:2078`
(verified by brace-depth matching, not assumed). **Current count: 151 route registrations**
(`rg -c '\.(Get|Post|Put|Patch|Delete)\('` restricted to lines 1126–2078, re-run during final
review — corrects an earlier draft of this section, which undercounted at 133; the resource-family
table below sums to the earlier 133 figure and has not been re-derived line-by-line against the
corrected count, so treat its per-family numbers as illustrative of the route mix, not as an
exhaustive partition of all 151). ADR-102's own snapshot ("148") remains a reasonable prior count;
the small drift from 148 to 151 is expected route churn since ADR-102 was written, not a
discrepancy worth chasing further. It is the server-to-server proxy tier originally built for the
ADR-049 downstream-node-relay topology and implements `storage.Storage` for `RemoteStorage`, the
CLI's client-mode Go type.

### Architectural finding: no non-CLI caller can reach `/system` today, and none ever could

Two independent facts, both verified directly (not assumed):

1. **No server process can construct a `RemoteStorage` client.** `internal/config/config.go`'s
   `validateRemoteStorageNotServer` unconditionally rejects `storage.type: remote` for any server
   process (ADR-083, Accepted) — no hub/spoke/replica/relay topology can exist that would give a
   *different Keyorix server* a reason to call `/system`.
2. **No other component calls `/system` over raw HTTP either.** `web/src/services/system.ts` calls
   `/api/v1/system/info`, `/system/metrics`, `/system/auth-config`, `/system/encryption-config` —
   all four are explicitly registered *outside* the `/system` proxy group (router.go:421-430,
   comment: "Deliberately NOT inside the `/system` route group below... these are human-facing
   reads"). Grep for `/system` across `web/src` found no other match. `cmd/keyorix-k8s-sync` and
   `operator/`: zero matches for `/api/v1/system` or `/system/`. `cmd/keyorix-mcp`: one match, an
   unrelated code comment, not a caller. No `sdk/`-named directory exists in the repo.

**Conclusion: every one of the 151 `/system` routes has exactly one possible caller category — the
CLI, in client mode, on the narrow fallback path where its `NewRemoteClient()`-first /
`InitializeCoreService()`-under-`RemoteStorage`-fallback pattern (ADR-107) actually falls through to
the fallback.** There is no "other caller: web UI / SDK / k8s-sync / mcp / operator" bucket for this
route group — confirmed empty by grep, not merely unclaimed.

### Within the CLI-only-reachable set: live vs. dead, per the existing reachability registry

`internal/storage/store/remote_reachability_registry_test.go` (the G80 158-method classification
pass, ADR-087) already carries an exhaustive per-method reachability verdict for every
*structurally-stub* `RemoteStorage` method — this report reuses that registry as the authoritative
caller-census evidence rather than re-deriving it by hand:

- **190 entries `reachabilityDead`** — the reaching core method is called only from `server/http`,
  `server/grpc`, or `server/main.go` (server-only, foreclosed by ADR-083), or has zero caller
  anywhere. Strongest Phase 6 deletion candidates.
- **16 entries `reachabilityLive`** — a real CLI command reaches this stub today, unguarded by the
  `NewRemoteClient`/`ResolveRemote`/`IsClientMode` idiom family: `AddPasswordHistory`,
  `CountSecretReadsBySecretIDs`, `CreateSecretAccessLog`, `GetBillingReport`,
  `GetProjectUsageStats`, `GetUserGroupRoleIDsAt`, `GetUserRoleIDsAt`, `ListAccessRequestsByIDs`,
  `ListAllUserRoleGrants`, `ListInactiveUsers`, `ListLiveSecretNamesByProject`, `ListSecretACLs`,
  `ListSecretAccessLogs`, `ListSessionTokenHashesForUser`, `RoleSetHasPermission`, `WithTransaction`.
  These are real, currently-broken (hard stub) features under `storage.type: remote` — exactly the
  set that must get a working human-facing REST equivalent before their CLI fallback can be
  deleted, per ADR-107's own Phase 2 framing. `GetUserRoleIDsAt`/`GetUserGroupRoleIDsAt`/
  `RoleSetHasPermission` are additionally covered by ADR-086's separate carve-out (the
  `core.Authorize` direct-entry-point path) — intentionally kept, not an oversight.
- **5 entries `reachabilityUnresolved`** — `AssignPermissionToRole`, `GetMachineRoleScopes`,
  `GetUserGroupPermissions`, `GetUserRoleIDsExact`, `GetUserRoleScopes`. Not independently
  re-verified to the same depth; Phase 0 of ADR-107's migration should resolve these first.
- **Working (non-stub) proxy files are outside this registry by design** — `remote_sod.go`,
  `remote_invitations.go`, `remote_memberships.go`, `remote_rotation_policies.go` etc. implement
  real HTTP proxying, so never entered `actualRemoteUnsupportedStubs`. Reachable only on the same
  narrow fallback edge case ADR-107 already characterized for `user update`/`group
  create/update/delete`/`invite revoke` — real, but rare, not a second caller category.

### Full route enumeration

The 133 routes group into these resource families (handler prefix, route count, resource area):

| Resource family | Route count | Representative handler(s) |
|---|---|---|
| Access requests / access-review campaigns | 12 | `CreateAccessRequestProxy`, `ListAccessReviewCampaignsProxy`, `GetLatestClosedAccessReviewCampaignProxy` |
| Machine identities / credentials / OIDC bindings | 24 | `CreateMachineIdentityProxy`, `TransitionMachineIdentityStateProxy`, `CreateMachineIdentityCredentialProxy`, `CreateOIDCBindingProxy` |
| RBAC (role/permission grants, group role assignments) | 9 | `AssignRoleWithExpiryProxy`, `RemoveGlobalAdminRoleGuardedProxy`, `ListProjectRoleAssignmentsProxy` |
| Setup tokens / login attempts / SSO state / WebAuthn / MFA | 20 | `CreateSetupTokenProxy`, `RecordLoginAttemptProxy`, `CreateSSOLoginStateProxy`, `ListWebAuthnCredentialsProxy`, `GetMFASecretProxy` |
| Groups / project memberships | 11 | `AddGroupMemberProxy`, `RestoreGroupProxy`, `CreateMembershipProxy`, `TransitionMembershipProxy` |
| Dynamic secrets (configs + leases) | 7 | `ListDynamicSecretConfigsProxy`, `ListDynamicSecretLeasesProxy` |
| Break-glass / legal hold / risk exceptions / SoD policies | 15 | `GetBreakGlassActivationProxy`, `UpdateLegalHoldProxy`, `ApproveRiskExceptionProxy`, `CreateSoDPolicyProxy` |
| Secrets (dependency graph, status transitions, including-deleted) | 5 | `CreateSecretDependencyExclusiveProxy`, `TransitionSecretStatusProxy`, `GetSecretIncludingDeletedProxy` |
| Users (active-state transitions, PAT/session bulk revoke, group lookup) | 6 | `UpdateUserIfActiveStateMatchesProxy`, `RevokeAllPersonalAccessTokensForUserProxy`, `DeleteSessionsForUserExceptProxy` |
| Retention sweeps / shares / notifications / audit ingest / access-activity | 24 | `DeleteExpiredRoleGrantsProxy`, `ListSharesByOwnerProxy`, `CreateNotificationProxy`, `IngestAuditEventProxy`, `LastUserSecretReadActivityProxy` |

(Full 133-row path+handler table available in the inventory working notes; grouped above by
resource family for readability — every route in every family above is CLI-only-reachable per the
architectural finding, none has a confirmed non-CLI caller.)

### What this means for Phase 6

Every route this report's per-command-group sections classify as **API** (has a working
human-facing REST equivalent already) is a Phase-6 deletion candidate the moment ADR-107 Phase 1
removes its CLI command's `InitializeCoreService()` fallback — no new REST work needed. Every route
this report flags as a **GAP** (the `reachabilityLive` list above, or a command whose only path is
the raw-proxy one with no REST sibling) is ADR-107 Phase 2 scope: a new/extended REST capability
must land *before* that command's fallback can be deleted.

---

## 4. CLI-side state today

**Three independent, overlapping remote-target/config mechanisms exist today, not one, with a fixed
but undocumented precedence order** (`common.ResolveRemote()`, `internal/cli/common/remote_client.go:57-108`):

1. **Env vars** `KEYORIX_SERVER`/`KEYORIX_TOKEN` — highest priority, no file involved.
2. **`~/.keyorix/cli.yaml`** (`$XDG_CONFIG_HOME/keyorix/cli.yaml`, falling back through
   `./keyorix-cli.yaml`) — written by `keyorix connect`, read by
   `internal/cli/config/cli_config.go`'s `CLIConfig` (`Mode: "embedded"|"client"`,
   `Client.Endpoint`, `Client.Auth.APIKey`, `ActiveProject`, plus a `Connections[]` list that has
   **zero callers anywhere in the CLI outside its own definition and tests** — confirmed dead code,
   see §2.7). Written via `securefiles.SecureWriteFile(..., 0600)`, `O_NOFOLLOW`-hardened.
3. **`./keyorix.yaml`** (CWD-relative, written by `keyorix config set-remote` or `keyorix auth
   login --server`) — the exact same config format the *server itself* reads. Explicitly flagged
   in-code (`#G73`/`#G74`, `remote_client.go:37-47`, `config.go:240-248`) as untrusted/
   attacker-plantable, since it resolves from the current working directory regardless of
   `KEYORIX_CONFIG_PATH` — both `auth login` and `ResolveRemote()` print an explicit warning when
   a security-relevant value is sourced from it.

**Token storage**: neither mechanism uses an OS keychain (Keychain/Credential Manager/Secret
Service) anywhere in the codebase. Both files store the API key/token in **plaintext YAML**, at file
mode **0600** with `O_NOFOLLOW` anti-symlink protection — real OS-level permission hardening, but
not keychain integration. This is a genuine open gap: today's plaintext-file model is a defensible
bar for a server-side root-owned config file, but a materially weaker one for a small,
widely-distributed client binary meant to run on individual operators' laptops.

**Auth per mode**:
- **Embedded/local mode**: no authentication layer at all. `common.InitializeCoreService()` opens
  storage directly; every mutation is audit-stamped with a *self-asserted*, unverified actor ID
  from `KEYORIX_CLI_ACTOR` (`common.ResolveActorID()`, defaults to `0` if unset) — the literal
  mechanism ADR-108 names as bypassing "the API's authorization, audit and rate limits."
- **Client mode (REST)**: a long-lived, non-expiring API key/PAT sent as `Authorization: Bearer
  <token>` on every request. `auth login` verifies the key against `GET /auth/profile`
  (self-service, unpermissioned) before persisting it — a bad/mistyped key/URL is caught at login
  time. **No refresh flow exists anywhere** — the PAT is the credential itself, not a short-lived
  session token with a refresh grant; revocation is `keyorix auth logout` (clears local config
  only — does **not** revoke the server-side PAT, see §8 Finding S12) or server-side
  `DELETE /auth/tokens/{id}`.
- **Client mode (raw proxy / `RemoteStorage`)**: same bearer-token transport, through the `/system`
  route group — the narrow fallback path §3 documents.

**Hardening already present** on the REST transport (`remote_client.go`): anti-SSRF redirect
refusal, split connect/idle timeouts, `HTTP_PROXY`/`HTTPS_PROXY`/`NO_PROXY` support, a 10MB
response-size cap, and an HTTPS/loopback-only warning for cleartext bearer-token transmission. This
is already close to what a thin, REST-only CLI module needs — it does not need to be rebuilt, only
relocated.

**What the thin CLI needs instead**: collapse to **one** credential-storage mechanism (the
`~/.keyorix/cli.yaml`-style, XDG-aware, 0600, symlink-hardened one should absorb what `auth
login`/`./keyorix.yaml` does today) — the CWD-planted-file attack surface disappears entirely once
the thin CLI has no reason to ever read the server's own `keyorix.yaml`. No embedded/local mode at
all (ADR-108 Decision A), so the `KEYORIX_CLI_ACTOR` self-assertion and its audit-attribution gap
disappear structurally. OS keychain integration and a token-refresh story are both explicitly
**not** decided by ADR-108 today — flag as product decisions needed before or during Phase 2, not
silently inherited.

---

## 5. Version skew: what exists today

**Nothing exists today.** Grepped `server/http/router.go`, `server/http/handlers/system.go`,
`internal/cli/common`, `internal/cli/status`, `internal/cli/system` for `api.?version`,
`x-api-version`, `minimum.?cli`, `min.?cli.?version`, `x-keyorix-version`, `ServerVersion`
(case-insensitive) — **zero matches, anywhere.**

The closest existing artefact: `GET /api/v1/system/info` (`system.read`-gated) returns a `Version`
field sourced from `internal/version`'s build-time value — but this is the server's **binary
release version** (e.g. `v0.92.1`), not a separate **API version** number, and carries no
minimum-CLI-version field. It also requires a prior successful login (`system.read`), which is
circular for the exact "is my CLI compatible with this server before I try to authenticate" check
ADR-108's tiered version-skew model needs.

The unauthenticated `GET /health` endpoint — the one route a thin CLI can always reach before any
credential exchange — **deliberately omits version/commit by explicit design**
(`server/http/handlers/health.go:18-20`: "disclosing the exact build aids CVE targeting... the
precise version is available on the `system.read`-gated `/api/v1/system/info` instead"). `keyorix
status`'s remote branch calls `GET /health` today and **discards the response body entirely** —
`rc.GetRaw(ctx, "/health")`'s result is checked only for a transport error, never parsed
(`internal/cli/status/status.go:189`).

**GAP**: ADR-108's tiered version-skew rule (same major = allowed with a warning if older, clear
"server too old" if the CLI is newer than a route the server has; different major or below the
server's stated minimum = refused) has no server-side field to read today, authenticated or not,
and no CLI code path that would read one even if it existed. Closing this needs: (a) a new,
deliberately narrow field on `/health` (or a new unauthenticated `/api/v1/version`-style endpoint)
carrying `api_version` + `minimum_cli_version` — a bare semantic version is much lower-signal than
the full build/commit `health.go` already declines to expose, so this is a distinct disclosure
decision, not a reversal of that one; and (b) new CLI code to compare it against the CLI's own
compiled-in version and warn/refuse per the tiered rule. Neither exists today. This is
infrastructure every future thin-CLI request should be able to check, so it belongs early in the
PR sequence (§7, PR 0) — before the bulk of command migration, not woven into any single command's
own PR.

---

## 6. Top 5 GAPs by user impact

1. **Secret-scoped access-request approval has no REST route at all.** `request secret-access`
   (approve access to read one `restricted`-classified secret's value) and the secret-scoped branch
   of `request review --action approve` are local-only by explicit, runtime-enforced design — the
   command itself refuses to run if a remote client is configured, rather than silently touching a
   stray local DB. `internal/core/classification_gate.go`'s `RequestSecretAccess`/
   `ApproveSecretAccessRequest` have zero HTTP handler anywhere in `server/http`. This is a
   compliance-relevant, classification-gate-driven feature with zero network path today — if the
   thin CLI ships REST-only with no local-DB fallback (which is the whole point of ADR-108), this
   capability disappears entirely unless a new route is built. Needs a product decision (build it,
   or explicitly drop the feature) before Phase 2's `request`/`accessreview` PR.
2. **B4 (offline, independent-of-the-running-server audit-chain verification) doesn't exist in any
   form.** `audit verify` is 100% REST and asks the live server to verify its own chain — the
   opposite of what regulated customers need this for. This is new `keyorix-server admin` work,
   not a reclassification.
3. **No version-skew infrastructure exists anywhere** (§5) — blocks every future CLI/server
   release from advertising compatibility safely. This blocks ADR-108's own stated tiered-skew
   decision from being enforceable on day one of the split, not just a nice-to-have.
4. **`compliance export`/`compliance verify` cannot round-trip successfully today for a genuinely
   untampered evidence pack** — `export` never signs or assigns the canonical filename `verify`
   needs, and `verify`'s own request never carries a `filename` field despite the server's
   AUD-009 filename-binding requiring one. A compliance operator running exactly the documented
   `export` → `verify` workflow gets a false "invalid" result today, with no code path to ever get
   `VALID`. Independent of the split, but the split's migration work is a natural forcing function
   to fix it (or decide the CLI needs a different route entirely) rather than porting the broken
   pair forward unchanged.
5. **GAP-F-BULK: `request bulk-approve`, `bulk-reject`, and `rejection-templates delete` silently
   hit the local embedded core instead of the connected remote server**, even though a matching
   REST route exists for all three and their sibling commands in the same file correctly check
   `NewRemoteClient()` first. Today, on `main`, an operator with `keyorix connect`-configured
   remote access who runs any of these three commands gets local/embedded behavior instead —
   inconsistent with every other command in the package, and it blocks a straight lift-to-thin-CLI
   since the thin CLI has no local-mode fallback to (accidentally) fall into. This is the highest
   user-impact GAP that is purely a bug fix, not new capability — recommend fixing before or as
   part of the `request` package's migration PR, independent of any ADR decision.

(Two more real gaps, lower individual user impact but both structural: OS-keychain-vs-plaintext
credential storage — §4 — and `share shared-secrets --user-id`'s missing arbitrary-target REST
route — §2.2.)

---

## 7. Phase 3 PR breakdown

Proposed order, smallest-safe-first, per ADR-108's own "Order of work" §2 ("Move commands group by
group: secrets, projects, users, then the rest" — adapted here to sequence by risk and by
dependency on gap-closing work, not strictly alphabetically).

**PR 0 — thin CLI module skeleton + version-skew infrastructure (prerequisite for everything else).**
New Go module, own `go.mod`, dependency-guard CI job that fails the build if the module imports
`internal/core`/`internal/storage`/`internal/config` server code or any cloud SDK. Add the
`api_version`/`minimum_cli_version` field(s) (§5) to `/health` or a new endpoint, plus CLI-side
comparison/warn/refuse logic. Depends on: a product decision on the OS-keychain-vs-plaintext
question (§4) landing in this PR's config-storage design, even if the decision is "keep plaintext
for now, revisit later." No command migration yet. Size: medium (new module scaffolding + CI +
one small new server endpoint). Tests: dependency-guard CI test (a forbidden import fails the
build); a version-skew unit test matrix (same-major-older/newer, different-major, below-minimum).

**Closed by PR split/pr0-cli-module (2026-09-23).** `cli/` (module
`github.com/keyorixhq/keyorix/cli`), excluded from the root `go.work` and gated by its own
`cli` CI job, matching `operator/`'s existing precedent. `cli/internal/depguard`'s test walks
the module's real dependency graph (`go list -deps`, not a source grep) and fails on any
`internal/core`/`internal/storage`/`internal/config`/`server/` or cloud-SDK import;
red/green-proven on this PR (a forbidden `internal/core` import pulled in the full AWS/Azure/
GCP SDK surface transitively — see the PR description for the exact failure output). The
server side adds `GET /api/v1/version` (`server/http/handlers/version.go`), unauthenticated
like `/health`, returning only `api_version` (`internal/version.APIVersion`, starts at 1) and
`minimum_cli_version` (new `Config.MinimumCLIVersion`, empty by default) — deliberately never
the build version/commit, matching `/health`'s own disclosure rationale; a handler test
asserts exactly those two fields and nothing else. `cli/internal/skew.Check` implements the
tiered rule (§ above this PR's own reasoning, in the package doc comment): `minimum_cli_version`
(when set) is a hard floor checked by both major-line and numeric comparison; independently,
the CLI's compiled `TargetAPIVersion` vs. the server's `api_version` produces a soft
same-major-older/newer warning, with the true "server too old for this command" case surfacing
per-request when a specific route actually 404s. Credential storage: single mechanism (§4's
"one mechanism only" decision), a 0600 plaintext file at `os.UserConfigDir()/keyorix/
credentials.yaml` (`cli/internal/credstore`) behind a `Store` interface that refuses to `Load`
on any permission wider than 0600 or through a symlink — an OS-keychain implementation is a
later option behind the same interface, not decided here. The HTTP client
(`cli/internal/apiclient`) is generated (`oapi-codegen`, `cli/Makefile`'s `client` target) from
a filtered copy of `server/http/handlers/openapi.yaml` (`cli/internal/apiclient/gen/
filterspec.go`'s `keptPaths`, extended by each future Phase 3 PR) rather than the full spec —
narrows the generated surface to what's actually wired (`/health`, `/api/v1/version`,
`/auth/login`, `/api/v1/auth/profile`) while still being real generation from the canonical
spec, not a hand-maintained subset. Commands: `keyorix-next version`, `login`, `status` — all
three exercised against a real running server (SQLite, no mocks) as part of this PR's manual
verification, not just unit tests. Follow-up needed outside this PR: add `cli` to the
repository's required-status-checks branch-protection list (a repo setting, not a file this PR
can change).

**PR 1 — `dynamic-secret`, `rotation`, `breakglass` (9+7+3 = 19 commands).** Zero GAPs, zero
security findings, already 100% REST with no fallback anywhere — the lowest-risk group, proves the
new module's plumbing end-to-end before anything harder. Size: small. Tests: golden-output
comparison against the current CLI's remote-mode output for every subcommand (should be byte-for-byte
identical, since the new module calls the same routes the same way).

**PR 2 — `pat`, `auth` (mfa/login/logout/status), `machine` identities (6+4+14 = 24 commands).**
Zero GAPs. `auth login/logout/status`/`connect`/`config` need the credential-storage consolidation
decided in PR 0 — land that here for real (collapse to one config mechanism, drop `config
set-remote`/`use-local`/`test-connection` per §2.7, drop `connect disconnect`'s embedded-mode
meaning). Size: medium. Tests: same golden-output comparison; a dedicated regression test for the
credential-file consolidation (old `~/.keyorix/cli.yaml` + `./keyorix.yaml` precedence collapses
correctly to the new single mechanism, no credential silently dropped).

**Closed by PR split/pr2-cli-pat-auth-machine (2026-09-24, stacked on split/pr0-cli-module —
#2019 had not yet merged when this PR opened).** All 24 commands ported into `cli/cmd/` against
the generated `apiclient`, REST-only, no new local mode. `login`/`status` were already PR 0's;
this PR added `logout`, `mfa stepup`, `pat` (6 leaf), and `machine` (14 leaf: create/list/
describe/suspend/reactivate/revoke, `binding` add/list/rm, `token` issue/list/revoke,
token-hygiene, audit) as flat top-level commands, matching PR 0's convention of not nesting under
an `auth` group. `machine`/`pat` have no "active project" concept yet (that lands with the
`project` command group in a later PR per this table) — every command takes `--project` or
`KEYORIX_PROJECT` directly, no fallback.

**OpenAPI spec gap found and closed, not just filtered:** 13 of the 24 commands' REST operations
either had no 2xx response schema in `server/http/handlers/openapi.yaml` (`createPAT`,
`listPATs`, `createMachineIdentity`, `listMachineIdentities`, `issueMachineToken`,
`listMachineTokens`, `listProjects`) or did not exist in the spec at all (`listExpiredPATs`,
`bulkRevokeExpiredPATs`, `patHygiene`, `machineTokenHygiene`, `getMachineAuditReport`,
`mfaStepUp`, and the three OIDC-binding operations) despite being real, working, `Zero-GAPs`
routes reachable in `router.go` — filterspec.go's `run()` would have failed outright the moment
any of these was added to `keptPaths` without a matching spec entry. Authored full operations
(request + response schemas, 8 new `components/schemas` entries: `PATToken`,
`PATHygieneRow`, `MachineIdentity`, `MachineToken`, `MachineTokenHygieneRow`, `OIDCBinding`,
`MachineAuditRow`, `MachineAuditReport`) rather than terse description-only stubs, per
CLAUDE.md's "generate it" preference — a schema-less operation cannot produce a typed generated
accessor, which would have forced the CLI code back onto raw `json.Unmarshal`, the exact pattern
ADR-106/108 are moving away from. This mechanically converted 13 operations from "pending" to
"enforced" in `contracttest`'s ADR-074 registry (`registry.go`'s `pendingRegistry` →
`exercisingTests`, `checks_test.go`'s `TestEnforcedSetMatchesADR074` pinned baseline) — closed
with new, self-contained happy-path tests in `server/http/handlers/openapi_contract_pr2_test.go`,
not by grafting onto an existing test whose fixture/path might not actually reach a 2xx.
`bulkRevokeExpiredPATs` was reclassified to its real status code (204, `outOfScopeRegistry`) after
tracing the handler; the two other net-new schema-less operations (`deleteOIDCBinding`,
`mfaStepUp`) were added to `pendingRegistry`, matching the existing `removeMachineRole`/
`revokeMachineToken` precedent of a 200-with-message response with no schema yet.

Two real bugs the schema-authoring step itself caught (server/http/handlers/openapi.yaml, not
CLI-side): an unquoted comma inside a YAML flow-mapping description silently produced a spurious
"extra sibling field" that `contracttest`'s spec-load validation rejected outright (caught before
merge, not after); and `PATToken.scopes`/`allowed_cidrs` needed `nullable: true` -- the real
handler serializes a nil `[]string` as JSON `null`, which a non-nullable array schema rejects
(`kx_pat_...`/scope round-trip, caught by `TestContractPR2_CreatePAT` failing against the real
handler, not by hand-inspection).

Credential/config: no consolidation work was actually needed beyond what PR 0 already decided —
`login`/`status`/`logout`/`mfa` all use PR 0's single `credstore` file
(`os.UserConfigDir()/keyorix/credentials.yaml`); the new CLI never had `config set-remote`/
`use-local`/`test-connection`/`connect` to begin with, so there is nothing to drop. `logout` was
the one real gap: the old CLI's `auth logout` never told the server (§8 Finding S12); this one
calls `POST /auth/logout` first (`TestRunLogout_RevokesServerSideThenDeletesLocalCredentials`
asserts the server actually received the call, not just that the local file is gone — asserting
the return value alone would have passed even with the revocation call deleted, see CLAUDE.md's
"assert the effect, not the return value"), then deletes the local credential file regardless of
whether the server call succeeded (`TestRunLogout_StillDeletesLocalCredentialsWhenServerUnreachable`).
Migration helper (`cli/internal/migrate`): `login` detects a server URL from either pre-ADR-108
config file (`./keyorix.yaml`, `~/.keyorix/cli.yaml`/XDG) and offers it as a confirmable default
-- never auto-imports, and structurally cannot read a credential (`Candidate` has no field for
one); `./keyorix.yaml` takes precedence over `cli.yaml` per `internal/migrate`'s own doc comment
(most-recent-explicit-login wins), confirmed by `TestDetectOldServerURL_CWDConfigTakesPrecedence`
independently re-discovering the lower-precedence candidate once the higher one is removed (not
lost, not merged).

New shared package `cli/internal/cliout` (named to avoid the repo root `.gitignore`'s generic
`output/` build-artifact rule): `Table` (tabwriter wrapper) and `SanitizeForTerminal`
(control-character stripping for attacker-controlled free text -- mirrors the old CLI's
`internal/cli/common.SanitizeForTerminal`), for reuse by later Phase 3 PRs.

Verified: `go build`/`go vet`/`go test ./...` clean for both `cli` (depguard green -- no
forbidden import pulled in by any of this PR's additions) and the main module's
`server/http/handlers` + `.../contracttest` packages; `gosec -severity medium` and
`golangci-lint` both clean on `cli/`.

**PR 3 — `rbac`, `group`, `invite` (11+8+4 = 23 commands).** Zero hard GAPs. Requires an explicit
decision on Finding S11 (D1: `rbac assign-role`/`remove-role`'s embedded-mode actor-0 attribution —
moot once local mode is gone, but decide explicitly rather than silently drop) and Finding S9
(`invite list`'s stricter-than-REST local check — also moot, same reasoning). Size: medium.

**PR 4 — `secret` core CRUD + metadata (create/get/update/delete/list/versions/diff/folder +
the ~30 already-CLIENT-ONLY commands, ~40 commands).** **Hard prerequisite**: fix Finding S1 (the
`PUT /api/v1/users/{id}` admin-rank ceiling gap) is a `user` package concern but should land
*before or alongside* this PR since it's the single highest-severity finding in the whole report —
sequencing note, not a blocker specific to `secret`. This PR itself has no REST gaps. Size: large
(highest command count, highest scrutiny given it's the product's core surface). Tests: full
behavioral-parity suite (today's dual-mode CLI vs. new thin-CLI's remote-only output) for every
command, explicit regression tests for the 4 documented audit-skip findings (S-secret-1 through
S-secret-4 in §8) being *closed by deletion* (once local mode is gone, there's no path left to
regress) rather than fixed in place.

**PR 5 — `secret` bulk/rotation/export/import/scan/hygiene (~22 commands).** **Hard prerequisite,
must land first and independently, NOT gated on this program**: fix Finding S2 (the broken
`?environment=<name>` filter in `rotate`/`render` — a live correctness/security bug on `main`
today). File and fix this as its own PR before this group's migration PR opens, so the migration
doesn't carry the bug into the new module under a "matches old behavior" banner. `bulk-delete` and
`score`'s embedded paths are DROP (Findings S5/S6). Size: large.

**PR 6 — `project`, `user` (14+11 = 25 commands).** **Hard prerequisite**: Finding S1 (admin-rank
ceiling gap on `PUT /api/v1/users/{id}`) must be fixed on the server route itself before this PR
deletes `user update`'s local fallback — today's fallback is, ironically, the better-guarded of the
two paths; deleting it first would narrow the CLI's own protection against the F5-class attack.
Also decide Finding S8 (`project env clone`'s misleading local-mode failure report — DROP recommended,
not a fix). Size: medium.

**PR 7 — `audit`, `anomalies`, `notification`, `accessreview`, `request` (37 commands).** **Hard
prerequisite**: fix GAP-F-BULK (Finding S15 / §6 GAP-5) — 3 of 6 `request bulk.go` commands need
rewiring to check `NewRemoteClient()` like their siblings, otherwise they silently break the moment
local mode is removed. **Needs a product decision**: `request secret-access`/secret-scoped `review
approve` (§6 GAP-1) — build a new route, or drop the feature with release-note documentation. Size:
medium-large, gated on the GAP-1 decision landing first (this PR's scope shrinks or grows
depending on which way that decision goes).

**PR 8 — `risk`, `sod`, `legalhold`, `compliance`, `hygiene`, `trust` (24 commands).** **Needs a
product/engineering decision**: the `compliance export`/`verify` round-trip bug (§6 GAP-4) — fix
independently first (recommended, since it's a live compliance-workflow bug, not split-specific),
or explicitly defer with a documented known-broken state. Every other command in this group is a
trivial move (already REST-only, no fallback anywhere). Size: small once GAP-4 is resolved
elsewhere.

**PR 9 — `share` (7 commands).** **Needs a product decision**: `shared-secrets --user-id`'s
missing arbitrary-target REST route (§6, secondary gap) — build new admin-scoped surface, or drop
the admin capability from the thin CLI. Size: small.

**PR 10 — `bundle`, `license`, `system info`/`role-expiry-check`/`token-expiry-check`, `status`
(remote branch only), `run` (remote branch only) — CLIENT-ONLY/API cleanup (~15 commands).** Drop
`status`'s and `run`'s local/embedded branches (Findings S18, §2.7) — dropping `run`'s is a
security fix, not just cleanup. Size: small.

**PR 11 (parallel track, `keyorix-server admin`) — B1 subcommands.** `system init` (local mode),
`system audit`, `system validate` port near-verbatim (`internal/startup.ValidateStartup`,
`securefiles.FixFilePerms`, `generateConfigFile`/`initializeEncryption`/`initializeDatabase` are
already core/storage-independent). Size: small — mostly relocation, not new logic. Tests: existing
CLI-level tests for these 3 commands should port unchanged onto the new `admin` subcommand
entrypoint.

**PR 12 (parallel track, `keyorix-server admin`) — B3 subcommands (`encryption` family, 15
commands).** All 15 port with the "testable core" pattern already in place (`rotateWithConfig`,
`migrateProviderWithConfig` etc. take no cobra/flag dependency). Fix Finding S13
(`auth-encryption rotate`'s missing lock call) as part of this port, not before — it's isolated to
this one command and the port is the natural place to normalize it against its 4 siblings in the
same file. Size: medium.

**PR 13 (parallel track, `keyorix-server admin`) — B4, new work.** Build offline audit-chain
verification from scratch: open the DB file directly (no running server, no HTTP), re-derive the
hash chain independent of `k.storage`. This is the least-defined PR in the whole program — no
existing code to port, ADR-108 §B.4 states the requirement but not a design. Size: large,
should not be scheduled until the design is scoped separately.

**PR 14 (final, ADR-108 §Decision C) — delete `/system` and `RemoteStorage`.** Gated on every prior
PR that removes an `InitializeCoreService()`/`NewRemoteClient()`-fallback pattern having landed
(PRs 1-10) and on the `reachabilityLive`/`reachabilityUnresolved` 21 methods (§3) either getting a
real REST route or being confirmed genuinely dead by that point. Delete the 151 route
registrations, their handlers, `internal/storage/store/remote_*.go`, the `~18`
`remote_storage_*_test.go` parity-fuzzer files, `validateRemoteStorageNotServer`'s enforcement
(carefully — per its own doc comment, this must go LAST, after the topology it forbids is already
gone, not alongside it). Size: large but mechanical (deletion, not new logic). Tests: the existing
`remoteUnsupportedAllowlist`/reachability-registry tests should go to zero real entries; a final
CI check that nothing in the repo imports `internal/storage/store/remote_*` outside test files.

---

## 8. Candidate security findings — consolidated

Ranked by severity/impact. All are report-only per this task's scope — none were fixed. "Local mode"
below means `common.InitializeCoreService()`/`InitializeStorage()`+`core.NewKeyorixCore` (direct-DB,
no HTTP layer) unless stated otherwise.

**S1 — HIGH. `PUT /api/v1/users/{id}` (the human-facing route ADR-107 wants as the CLI's SOLE path
for `user update`) is missing an authorization ceiling its own `/system` proxy sibling already had
to acquire.** `server/http/handlers/users_active_transition_proxy.go:169`
(`UpdateUserIfActiveStateMatchesProxy`) calls `RequireEqualOrGreaterAdminAuthority` (defined
`internal/core/users.go:829`) — an admin-rank ceiling that refuses a caller from rewriting a target
user's identity fields (email especially — the F5 finding this exists to close) when the target
holds, at any scope, a permission the caller does not also hold.
`server/http/handlers/users_crud.go:727-783` (`UserHandler.UpdateUser`, backing
`PUT /api/v1/users/{id}`) does **not** call this or any equivalent — only session presence plus the
blanket group-level `RequirePermission(permUsersWrite)`. Repo-wide grep confirms only 2 call sites
for `RequireEqualOrGreaterAdminAuthority` exist at all (`webauthn_proxy.go:289` and this one
`/system` proxy). **Practical effect**: a principal holding only `users.write` (not global admin)
can, via the route both the web UI and the CLI's primary path already use, rewrite a
HIGHER-privileged target's email/username with no admin-rank check, then pivot via
password-reset/setup-token completion exactly as the `/system` proxy's own fix comment describes for
the now-fixed path — via the sibling route that fix was never applied to. Not hypothetical scope
creep — this is the literal attack the existing fix names, unaddressed on the primary route.
Location: `internal/cli/user/update.go` cross-referenced against `server/http/router.go:878`,
`server/http/handlers/users_crud.go:727-783`, `internal/core/users.go:793-795,829`.

**S1b — MEDIUM, compounding S1. `user update`'s own local-mode path is inconsistent with its
package's own established mitigation pattern.** Every other account-lifecycle command in
`internal/cli/user/` (`suspend`, `reactivate`, `force-password-reset`, `revoke-sessions`, `delete`,
`resend-setup-link`, `create --setup-link/--one-time-password`) requires `--by` and calls
`resolveAdminID`+`requireUserAuthority` — the package's own hand-rolled simulation of the HTTP
layer's check. `update.go`'s local branch has no `--by` flag, no `resolveAdminID` call, no
`requireUserAuthority` call at all — combined with S1 (core itself checks nothing), local-mode
`user update --active=true` performs **zero** authorization of any kind, not even the weak,
spoofable `--by`-email check its siblings at least attempt. Migrating this command by simply
deleting the local fallback (ADR-107 Phase 1's usual move) would, ironically, remove the
*better-guarded* of the two existing paths for this specific operation unless S1 is fixed first.
Location: `internal/cli/user/update.go:58-73` vs. `internal/cli/user/lifecycle.go:179-185`,
`delete.go:53-59`, `setup_link.go:45-51`.

**S2 — HIGH, live bug on `main` today, independent of the CLI/server split. `secret rotate` and
`secret render` build a broken, silently-ignored `?environment=<name>` filter and name-match
unscoped across every secret the caller can read.** `GET /api/v1/secrets` only ever reads
`environment_id` (numeric) — `environment=<name>` matches zero code path anywhere in
`secrets_list.go` (grepped across all of `server/http/handlers/*.go`). `render.go`'s resolver
(page_size=1000) and `rotate.go`'s (default page_size=20, no explicit override) both silently get
an unscoped, cross-project/cross-environment page of the caller's readable secrets and take the
first case-(in)sensitive name match. A purpose-built, project-scoped server-side renderer
(`POST /projects/{id}/secrets/render`) already exists and is simply never called. **Concrete
failure modes**: `render` can silently substitute a same-named secret from a different
project/environment into rendered output headed for a live config file — no error, no warning.
`rotate` — the worse half, since it's a write — can silently `POST /secrets/{wrong-id}/rotate`,
overwriting an unrelated secret's value, with zero output indicating anything went wrong. Recommend
filing and fixing this **independently of, and before, the split program** — it is a real,
currently-exploitable-by-mistake defect on `main`, not a migration artifact. Location:
`internal/cli/secret/render.go:108-137`, `rotate.go:72-89`, cross-referenced against
`server/http/handlers/secrets_list.go:120`, `internal/core/secret_render.go:40`,
`server/http/router.go:552`.

**S3 — HIGH. `keyorix run`'s embedded/local-mode secret-value fetch has zero authorization check
and zero audit event, where the functionally identical remote path in the same file correctly hits
both controls.** `fetchSecretsEmbedded` (`internal/cli/run/run.go:227`) calls the bare
`svc.GetSecretValue(ctx, s.ID)` — always treated as `userID 0`, runs `enforceSecretReadGuards`
(expiry/suspension/classification-approval/schedule) but never `ValidateSecretAccess` (that only
happens inside `GetSecretValueWithPermissionCheck`, which this isn't). `internal/core/versions.go`
has zero audit-emitting calls anywhere in the file. The REST route `run`'s own remote path
correctly uses (`GET /secrets/{id}?include_value=true`) calls
`GetSecretValueWithPermissionCheck(ctx, id, userCtx.UserID)` AND explicitly emits
`LogSecretReadWithProject` for every read. **Net effect**: running `keyorix run` today in
embedded/local mode against a project with restricted-classification or otherwise access-controlled
secrets silently reads and injects EVERY secret in the project+environment into a child process's
environment with no RBAC check against the invoking OS user and no audit trail recording the read
happened at all. The sharpest concrete instance in this whole report of ADR-108's abstract "second
server that bypasses the API's authorization, audit and rate limits" framing. Location:
`internal/cli/run/run.go:170-239` vs. `internal/core/versions.go:148-238`,
`server/http/handlers/secrets_crud.go:274,296`.

**S4 — MEDIUM. `secret folder delete`'s embedded path has no type-guard the REST route has, and
can silently delete a SECRET instead of a folder.** `FolderHandler.DeleteFolder` explicitly
re-fetches the target node and 400s if `node.IsSecret` is true (with a dedicated test,
`TestDeleteFolder_IsSecret_Returns400`). The embedded CLI path calls
`service.DeleteSecret(ctx, folderDeleteID)` directly — the generic secret-delete method, which has
no such check. An embedded-mode operator who mistypes a secret's ID into `secret folder delete --id
<secretID>` silently deletes that secret (after a confirmation prompt that only asks about "folder
N", not what kind of node N actually is). Location: `internal/cli/secret/folder.go:245` vs.
`server/http/handlers/folders_handler.go:202-211`.

**S5 — MEDIUM. `secret bulk-delete`'s embedded path attributes every deletion to actor `0`/username
`"cli"` with empty ip/ua — a documented, not silent, attribution gap, still worth flagging as
concrete evidence for ADR-108's own B2 rationale.** `bulk_delete.go`'s own doc comment explicitly
names `actorID==0` as the embedded-CLI signal and states per-secret re-authorization is
deliberately skipped ("physical access to the local DB file is the authorization boundary"). The
audit event IS still written (not an audit-skip, unlike S3/S-secret-1..4) — just attributed to a
non-identity. Recommend DROP under ADR-108 Decision A, not a fix. Location:
`internal/cli/secret/bulk_delete.go:152-201` vs. `internal/core/bulk_delete.go:89-104`.

**S6 — MEDIUM, one point unresolved. `secret score`'s embedded path has NO authorization check
reachable at all (not even the actor-0 convention S5 has), and possibly no audit either.**
`ComputeSecretRiskScore(ctx, secretID)` takes no actor/permission argument whatsoever — genuinely
unlike `bulk-delete`'s documented pattern. Whether the REST route's handler (`GetSecretRisk`) itself
emits an audit event that the embedded path then simply lacks was **not fully determined** in this
pass (handler body not read) — flagged as the sharpest unresolved item in the whole `secret`
inventory; recommend a follow-up trace before assuming parity either way. Location:
`internal/cli/secret/score.go:142-180`.

**S7 — LOW, doc-only, not an authorization defect (the router is the real gate in all three cases).**
Three CLI help-text/doc-comment mismatches, all in the direction of UNDER-claiming the required
permission (so an operator is surprised by an unexpected 403, never granted more than intended):
`secret reassign-owner`'s help text says `secrets.write` + per-secret authorization; actual
enforcement is a single project-level `roles.assign` check gating the whole bulk operation.
`secret quota-report` and `secret name-conformance` (org-wide form) both say `secrets.read`/
`system.read` respectively; both routes actually require `audit.read`. Same class of mismatch
recurs across `risk list`, `sod violations`, `legalhold status`, and `hygiene`'s own printed
`--help` text (all say `system.read`, all actually gate on `audit.read`) — a calibration change
that landed in the router without a corresponding CLI doc-string update, repeated across 7
commands. Worth a single pass fixing all 7 help strings together when these commands migrate, not
7 separate fixes.

**S8 — MEDIUM, functional bug, not a security bypass (fails closed). `project env clone`'s
embedded path hardcodes actor `"cli"`/`0` instead of using the `ResolveActorID`/`ResolveActorLabel`
self-assertion helpers used elsewhere in the same package, and — because
`GetSecretValueWithPermissionCheck` proven-fails-closed on `actorID==0`
(`TestGetSecretValueWithPermissionCheck_ZeroUserID`) — this makes the command silently copy ZERO
secrets on every embedded-mode run while reporting a hardcoded, incorrect "already exist in
destination" reason and exiting 0 (success). The permission check is doing its job; the CLI is
lying about why nothing happened. Recommend DROP under ADR-108 Decision A rather than fixing the
actor-threading — this embedded path has, in effect, never worked, so removing it loses nothing a
user could have relied on. Location: `internal/cli/project/env_clone.go:88-130` vs.
`internal/core/env_clone.go:33,83-92`, `internal/core/secret_copy.go:53`.

**S9 — LOW, correctness/parity gap, fails closed (stricter, not weaker). `invite list`'s
embedded-mode authority check requires `roles.assign`, a materially HIGHER permission than the
route's actual `users.read` gate.** An embedded-mode `--by` actor holding only `users.read` (what
the REST route actually requires) would be refused locally for an operation the equivalent REST
call would allow them. Not exploitable — fails safe — but real local/remote parity divergence
worth correcting rather than silently carrying forward. Location: `internal/cli/invite/list.go:58-70`
vs. `server/http/router.go:494`.

**S10 — LOW/MEDIUM, already documented and accepted in-repo, reported per this task's instruction
to surface it, not a fresh discovery. `share list` and `share shared-secrets --user-id`'s
embedded paths can enumerate a secret's share graph / an arbitrary user's shared-secrets list with
no ownership/actor check at all**, where the REST routes enforce an owner-only or self-only
restriction respectively. Both are explicitly flagged in the CLI's own code comments
("cli-connect-007 (info, deliberate — not a bug)") as an accepted consequence of embedded mode
having no authenticated-user concept — the residual-risk condition (embedded mode pointed at a
genuinely multi-tenant backend) is exactly what ADR-108's removal of local mode closes structurally.
`share shared-secrets --user-id` additionally has no REST equivalent at all (§6, secondary gap) —
an admin-scoped "list user X's shared secrets" capability that would need new REST surface, not an
ADR-108 B1-B4 item, if kept. Location: `internal/cli/share/list.go:41-55`,
`internal/cli/share/shared_secrets.go:44-56`.

**S11 (= "D1" in the source inventory) — MEDIUM. `rbac assign-role`/`remove-role`'s embedded-mode
core methods are structurally incapable of carrying an actor, where the identical group-scoped
operation in the SAME package IS correctly actor-threaded — proving the fix is a core-layer
signature change, not a CLI oversight.** `internal/core/rbac.go:19,41`
(`AssignUserRoleScoped`/`RemoveUserRoleScoped`) take no actor parameter at all — line 28 hardcodes
`c.AssignUserRole(ctx, 0, ...)` inside `core`, not passed in by the caller; the method's own doc
comment states this outright ("actorID 0 = local CLI/system"). Contrast:
`internal/core/rbac_management.go:200,246` (`AssignRoleToGroup`/`RemoveRoleFromGroup`) — the
group-scoped equivalent, same package — DO take an explicit `actorID`, and
`internal/cli/rbac/group_role.go:109,175` correctly passes `common.ResolveActorID()`. Every
embedded-mode direct user-role grant/revocation (arguably the more common, more security-relevant
of the two operations) is audit-attributed to actor `0` regardless of `KEYORIX_CLI_ACTOR`, with no
way for the CLI to fix this without a core-layer signature change. Scope note: embedded-mode-only;
moot once ADR-108 Decision A removes local mode, but worth deciding explicitly (fix the signature,
or accept and document) rather than silently dropping, since the same core methods likely have
other embedded-mode callers repo-wide not traced in this pass.

**S12 — LOW, informational/UX gap, not a code defect. `auth logout` clears local config only — it
does not call `DELETE /api/v1/auth/tokens/{id}` to revoke the server-side PAT.** A copy of
`~/.keyorix/cli.yaml`/`keyorix.yaml` taken before `logout` still holds a live, usable credential
after the operator believes they've "logged out." Documented CLI behavior ("remove stored API key"),
not a bug, but worth a UX/docs fix (or an explicit revoke-on-logout default) when this migrates.
Location: `internal/cli/auth/auth.go:194-217`.

**S13 — LOW, unresolved (not confirmed either way). `encryption auth-encryption rotate` acquires no
key-directory lock at all, unlike all 4 of its siblings in the same file** (`status`/`enable`/
`migrate`/`validate` all explicitly call `AcquireSharedKeyLock`). Whether
`AuthEncryption.RotateAuthEncryption` takes a lock internally the way `Service.RewrapDEKWithProvider`
does for `migrate-provider` was not verified in this pass (the implementation file wasn't read) —
flagged as the single highest-priority follow-up read from the `encryption` cluster, and a natural
fix-point when this command ports to `keyorix-server admin` (PR 12, §7). Location:
`internal/cli/encryption/auth_encryption.go:173-198`.

**S14 — LOW, documented-by-design, positive framing for the split. Four local-mode `request`
commands (`access`, `withdraw`, `list --by`, `review --by`) resolve identity from a caller-supplied
email flag with no session to verify it against** — `access`/`withdraw` can file/withdraw "as" an
arbitrary resolvable user; `list`/`review`'s `--by` at least passes through a real `Authorize(...)`
check against the resolved actor, so only identity (not privilege) is unverified there. Every
instance carries an in-code comment acknowledging the tradeoff as inherent to embedded mode having
no session concept. This entire class of risk disappears by construction once ADR-108 Decision A
removes local mode — cited here as positive evidence for the split's security value, not a fix
request.

**S15 (= "GAP-F-BULK") — MEDIUM, confirmed implementation bug (not a design gap), independent of
the split. 3 of `request/bulk.go`'s 6 subcommands (`bulk-approve`, `bulk-reject`,
`rejection-templates delete`) never check `common.NewRemoteClient()` at all and go straight to the
local embedded core — even though a matching REST route exists for all three, and their siblings in
the same file (`rejection-templates list`/`add`) check correctly.** Today, on `main`, an operator
with a `keyorix connect`-configured remote server who runs any of these three commands silently
operates on the local embedded core instead of the connected server. See §6 GAP-5 for the
migration-blocking framing; listed here for its security angle: `BulkApproveAccessRequests`/
`BulkRejectAccessRequests` DO perform genuine per-item project-scoped authorization inside `core`
(`bulk_access_requests.go:89,150`) — so this bug is a "silently wrong target," not a privilege
escalation — but it means an operator's bulk decision may land in a local SQLite file nobody is
reading while believing it reached the hub, a trust/correctness defect ADR-108's thin-CLI (no local
DB mode at all, compiler-enforced) eliminates structurally once fixed and migrated. Location:
`internal/cli/request/bulk.go:47-52,105-110,294-299`.

**S16 — MEDIUM, functional gap not an authz/audit skip. `compliance export`/`compliance verify`
cannot round-trip to VALID for a genuinely untampered pack, see §6 GAP-4 for full detail.** Not an
authorization or audit-emission bug — `GenerateComplianceEvidence` (what `export` calls) and
`ExportComplianceEvidence` (the only function that ever produces a valid signed pack, called only
by the scheduled job in `server/main.go`) are two different functions for two different purposes,
never wired together the way the CLI's `export`→`verify` UX implies. No test would have caught this
(`TestVerify_ValidAndInvalid` stubs the HTTP response directly rather than exercising the real
signing/verification logic).

**S17 — MEDIUM. `usage show` and `billing report`'s embedded-mode paths call disclosure-sensitive,
deployment-wide report generators with literally no `userID`/caller-identity parameter on the core
method signature — there is nothing for a permission check to even be threaded through.** REST
gates both at `audit.read`; local mode has zero. Both reports are explicitly documented in their
own handler header comments as "disclosure-sensitive" (`admin_usage.go`, `admin_billing.go`), and
`admin_billing.go` additionally notes "no per-project ownership check anywhere in the call chain" —
meaning `audit.read` is the ONLY control on this data, and local mode has none of it. Location:
`internal/cli/usage/usage.go:53-65` vs. `internal/core/usage_report.go:13`;
`internal/cli/billing/billing.go:81-97` vs. `internal/core/billing.go:16`.

**S18 — HIGH (= S3 restated for emphasis as the report's own "sharpest finding" callout). See S3
above — `keyorix run`'s local-mode secret-value fetch is the single clearest concrete instance in
this entire inventory of ADR-108's abstract "local mode is a second server that bypasses
authorization, audit, and rate limits" framing, with disclosure-sensitive, file:line evidence on
both sides of the split.**

**Systemic pattern underlying most of the above (stated once, not re-derived per finding)**: per
ADR-108's own Context section, local/embedded mode "opens the SQLite DB itself, which makes it a
second server that bypasses the API's authorization, audit and rate limits." This report confirms
that pattern with concrete call-chain evidence across `secret`, `project`, `group`, `machine`,
`rbac`, `usage`, `billing`, and `run` — `internal/core.KeyorixCore` methods generally assume the
HTTP router already authorized the caller and do not re-check themselves; local-mode CLI commands
never construct a router, so they skip that check entirely. Three distinct sub-shapes were found
(not one uniform gap): (1) no check at all, ever; (2) a check exists but is explicitly bypassed for
actor `0` specifically (documented, deliberate, e.g. `requireGranterHoldsRolePermissions`); (3) a
check exists and fails closed for actor `0` (the safer minority shape, e.g.
`requireMachinePrivilegeCeiling`). Every instance of this pattern not individually numbered above
(the majority of "no behavior difference beyond the general pattern" rows in §2) becomes moot,
structurally, the moment ADR-108 Decision A removes local mode from the CLI — that removal is this
report's single strongest piece of evidence *for* the program, not against it.





