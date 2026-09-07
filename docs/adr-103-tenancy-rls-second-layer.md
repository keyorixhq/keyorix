# ADR-103: PostgreSQL Row-Level Security as a second, independent tenancy layer

## Status

**Proposed.** Not implemented; not ratified. `096092d6` marked this ADR
"Accepted" without human review — an autonomous background session (the
`e6aa08b0` adversarial-review daemon, working the same shared checkout)
extended the design and self-assigned Accepted status. The content is
retained as-is (it includes a real, measured correction to this ADR's
original §1c design — the original `WithTransaction`-only injection point
left 99.4% of read traffic unprotected) but Accepted is a human decision that
has not happened yet in the conversation that owns this document. Resetting
to Proposed pending actual ratification.

This ADR authorizes design only, including the §1c injection-point revision
(§1c for the measurement and the corrected mechanism), the mandatory `WITH
CHECK` on every policy (§1b/§1f Test 4), explicit trigger security context
(§1d), and the required latency measurement and context-propagation guard
(Consequences, §1f). It does **not** authorize migrations, policies, or code:
§1b's two open product/security sign-offs (`audit_events` NULL-scope
visibility, global `notifications` visibility) block implementation and must
be resolved before an implementation PR starts, not inside one — tracked in
`QUEUE.md`. See "Verification design" for what must exist and pass,
red-then-green, before any of this ships or before Status can move to
Accepted.

## Context

PR #1774 (cross-tenant usage disclosure) had exactly one control between any
authenticated user and every project's data: the route's permission check. A
single missed or buggy check at that one altitude was sufficient to leak
another tenant's data. The goal of this ADR is a second control that fails
**independently** of application-layer bugs — enforced by PostgreSQL itself,
below every handler, below the ORM, below `WithTransaction`.

This ADR intentionally does **not** touch the application authorization layer
(RBAC, permission checks, handler wiring). A second check at the same altitude
as the one that failed is not defence in depth; it is the same layer twice.

Prior investigation (this workstream, 2026-09-06/07) established:

- The schema is **not** the deep `namespace → zone → environment → secret_node`
  hierarchy originally assumed. Zones don't exist in the live GORM models.
  Every tenant-scoped table is at most one join away from a table that already
  carries `project_id` directly (`secret_nodes`, `machine_identities`, or
  `access_review_campaigns`).
- The PostgreSQL backend (`internal/storage/factory.go`, `createPostgresStorage`)
  is real, documented as the production/HA default (ADR-039), and shares the
  same `LocalStorage` GORM code path as SQLite.
- `WithTransaction` (`internal/storage/store/local_transaction.go:17-21`) pins
  one physical connection for a transaction's lifetime via `gorm.DB.Transaction`,
  giving a single choke point to inject per-transaction session state.
- Zero RLS exists anywhere in the codebase today (one aspirational doc mention
  only, no `CREATE POLICY`/`ENABLE ROW LEVEL SECURITY` anywhere).
- No client runs Postgres in production today. There is no live tenant data to
  migrate under downtime constraints — the schema change this ADR requires is
  currently free in a way it will not be once a customer is live on Postgres.
- ADR-097 (Accepted, 2026-09-02) already added a startup guard against an old
  binary silently running against a newer schema: a monotonic
  `currentSchemaEpoch` int, written to `system_metadata.schema_epoch` after
  `migrateDatabase` completes, checked before any migration step runs on the
  next boot. It explicitly rejected, as disproportionate to *that* problem, "a
  full versioned migration framework (numbered up/down files, a
  `schema_migrations` table tracking every individual step)". §1g below adds a
  narrower mechanism for a different problem (see there for why it doesn't
  reopen that rejection) and this ADR does not replace or duplicate ADR-097's
  epoch guard.

## Decision

### 1a. Role separation (the decision that makes or breaks this)

**Empirically verified against a real `postgres:16` instance** (not assumed):
a role that creates a table (as `AutoMigrate` does today) becomes its
**owner**, and PostgreSQL exempts a table's owner from its own RLS policies
unless `FORCE ROW LEVEL SECURITY` is set — even when RLS is `ENABLE`d, the
policy is correct, and the session variable is set correctly.

Reproduced directly:

| Scenario | Session var | Policy | `FORCE` set? | Rows returned (2 total, 1 per tenant) |
|---|---|---|---|---|
| Owner connection, RLS enabled only | `app.current_tenant = '1'` | `project_id = current_tenant` | No | **2** — RLS silently bypassed |
| Same owner connection, same session, same policy | `app.current_tenant = '1'` | `project_id = current_tenant` | Yes | **1** — correctly enforced |

Today, `factory.go` opens **one** `*gorm.DB` per process, using **one**
configured DSN/role for both `AutoMigrate` (schema creation → ownership) and
all runtime traffic (`LocalStorage`'s queries). That role is therefore
guaranteed to own every table it creates, which means: enable RLS with correct
policies and correct session-variable plumbing, and it still protects nothing,
silently, with every test that doesn't specifically check for this passing
green.

**Decision:**

1. Two distinct Postgres roles, not one:
   - `keyorix_migrator` — owns all objects, holds DDL privileges (`CREATE`,
     `ALTER`), used **only** for the `migrateDatabase` step (schema creation,
     `AutoMigrate`, the account-state backfill/constraint pattern, index
     creation). Never used for request-serving traffic.
   - `keyorix_app` — the runtime role every request-serving connection uses.
     Granted DML only (`SELECT`/`INSERT`/`UPDATE`/`DELETE`) via explicit
     `GRANT`, **not** ownership. Must **not** have `BYPASSRLS` and must not be
     a superuser — either would silently reproduce the same bypass as owner
     status.
2. `FORCE ROW LEVEL SECURITY` on every protected table (scope: §1d), **in
   addition to** role separation, not instead of it. Role separation alone
   would already be sufficient (non-owner, non-`BYPASSRLS` roles are subject
   to RLS regardless of `FORCE`), but `FORCE` is zero-cost for a correctly
   separated non-owner role and is the only thing that keeps enforcement
   correct if a future change (a Helm value regression, a manual `GRANT`, a
   local dev shortcut) accidentally reunifies the two roles. Belt and
   suspenders, cheap enough that there's no reason not to.

**The reverse ownership trap — symmetrical to the bug above, and just as
invisible.** `FORCE ROW LEVEL SECURITY`'s whole purpose is to apply policies
to the table owner too. Once it's on, `keyorix_migrator`'s own operations —
`AutoMigrate`, and critically, any cross-tenant backfill it runs (exactly
§1g's mechanism, and exactly #1723's pattern) — are subject to the same
policies as everyone else. A backfill issuing `UPDATE <table> SET project_id
= ...` with no `app.current_tenant` session variable set would silently
update **zero** rows and report success (`RowsAffected` correctly reflecting
"zero rows matched the policy," not an error) — the exact failure shape as
this section's original trap, just pointed the other way.

**Decision: `keyorix_migrator` carries the `BYPASSRLS` role attribute.**
Considered and rejected the alternative of sequencing ("create policies
strictly after the backfill completes"): it only covers the *first* backfill
on a fresh table. Every future named step in §1g's ledger that needs to touch
existing, already-RLS-protected tables (a later data fix, a schema evolution)
would hit the identical trap the moment it runs after that table's policies
already exist — sequencing doesn't generalize, a role attribute does.
`BYPASSRLS` is a strong privilege, but `keyorix_migrator` is already, by this
section's decision, never used for request-serving traffic and treated as a
break-glass-tier credential — extending that same role's privileges to
include `BYPASSRLS` is consistent with a decision already made, not a new
risk category.

Verified empirically against real `postgres:16` (same throwaway-container
method as the forward-trap reproduction above), on a table with `ENABLE` +
`FORCE ROW LEVEL SECURITY` and a tenant-equality policy already active:

| Connection | `app.current_tenant` set? | `UPDATE <table> SET ...` (no `WHERE`) | Rows affected (of 2, 1 per tenant) |
|---|---|---|---|
| `keyorix_migrator` (owner + `BYPASSRLS`) | No | Blanket update, both tenants | **2 — correctly bypasses, backfill works** |
| `keyorix_app` (non-owner, no `BYPASSRLS`) | Yes, tenant 1 | Same blanket update | **1 — correctly scoped, cannot cross tenants** |

This is the required, asymmetric behavior: the migration role must be able to
write across tenants unconditionally; the runtime role must never be able to,
even with a blanket statement and no `WHERE` clause. §1f's verification
design adds a test asserting exactly this pairing, not just the runtime
role's isolation alone.

**Implications for config/DSN, Helm, and operator docs** (specification for a
future implementation PR, not built here):

- `internal/config/config.go`'s `Storage.Database` needs **two** DSN-shaped
  fields — e.g. `migration_dsn` (or a `migration_user`/`migration_password`
  pair layered onto the existing host/port/name fields) and the existing `dsn`
  repurposed as strictly the runtime connection. `factory.CreateStorage` opens
  the migrator connection only for the duration of `migrateDatabase`, then
  closes it; the long-lived pooled `*gorm.DB` handed to `LocalStorage` is
  opened with the runtime DSN only.
- The Helm chart must provision both roles (an init container/job running as
  `keyorix_migrator`, the app `Deployment` running as `keyorix_app`), and
  `GRANT`s must be scripted, not manual, so they're reproducible and
  reviewable.
- Operator docs (self-hosted/air-gapped customers pointing their own Postgres
  at Keyorix, not using the Helm chart) must state the two-role requirement
  explicitly and warn that pointing both `dsn` and `migration_dsn` at the same
  role silently disables this entire ADR — this is exactly the failure mode
  reproduced above, and it is invisible without the verification tests in
  §1f.

### 1b. Null / zero tenancy semantics, per table

This is the third instance in this codebase of a blank/zero value carrying
implicit security meaning (cf. the blank-`AccountState` backfill, #1723/PR
`89a38f42`, which required a dedicated backfill + `CHECK` constraint after the
fact because "blank" had silently meant "unset" with no enforcement). Treated
accordingly: every ambiguous column gets an explicit, written decision below,
not "whatever the equality operator happens to do."

| Table | Sentinel | Meaning | RLS decision | Status |
|---|---|---|---|---|
| `notifications.project_id` | `NULL` | System/operational notice not tied to one project (e.g. "backup completed") | `project_id = current_tenant OR project_id IS NULL` — global notices visible to all tenants | **Needs product sign-off**: confirm no global notification ever carries cross-tenant-sensitive content before treating "global" as "visible to everyone." |
| `rotation_policies.project_id`/`environment_id` | `NULL` | Deployment-wide default policy | `SELECT`: `project_id = current_tenant OR project_id IS NULL` (informational, readable). `INSERT`/`UPDATE`/`DELETE` via `WITH CHECK`: `project_id = current_tenant` only — the `keyorix_app` role can never write a global policy through the request path; global defaults are seeded via `keyorix_migrator` or a dedicated admin path. | Decision made here; flag for review since it forecloses one Options in the future admin UI. |
| `audit_events.project_id` | `NULL` | Platform/global-scope event (admin login, global RBAC change) | **Do not** blanket-union via `OR project_id IS NULL`. Audit events are the closest analog to the PR #1774 exposure — a naive "global rows visible to everyone" rule here would recreate a cross-tenant disclosure through the RLS layer itself. Global-scope audit visibility must be gated on a distinct, explicitly-set session flag (e.g. `app.is_platform_admin`, set only for verified platform-admin sessions), not folded into the tenant policy: `project_id = current_tenant OR (project_id IS NULL AND current_setting('app.is_platform_admin', true) = 'true')`. | **Open decision — requires product/security sign-off before implementation.** This is a genuine design fork, not a detail; do not resolve it silently in a migration PR. |
| `user_roles`, `group_roles`, `user_groups`.`project_id` | `0` (not `NULL`) | Global role/group assignment | `project_id = current_tenant OR project_id = 0`. Unlike the audit-event case, global role/group *definitions* are not tenant secret data — the existing (out-of-scope) application authz logic already reads across both scopes in one query to compute effective permissions per project, and an RLS policy that excluded `0` would break that read pattern without touching a line of authz code. | Decision made here. Recommend a follow-on (separate from this ADR): replace the bare-`0` sentinel with an explicit `is_global boolean` column or a `CHECK` constraint documenting the convention, mirroring the pattern `guardAccountStateValid` already established for `AccountState` — not required for this ADR to land, but the same defect class recurring a third time is a signal worth acting on separately. |

**`WITH CHECK` is mandatory on every policy in this ADR's scope, not only
`rotation_policies`.** `USING` governs which rows a query can *read*; without
a matching `WITH CHECK`, Postgres lets the runtime role `INSERT`/`UPDATE` a
row carrying a `project_id` it cannot itself read back — a cross-tenant write
that Test 1 (§1f, a read-only assertion) would never catch, since the
attacking session never has to read the row it just planted. Every policy
created under §1d — for the twelve backfilled tables and for the tables that
already carry `project_id` directly — must pair its `USING` predicate with an
equivalent `WITH CHECK`. For the two rows above with an `OR`-widened `USING`
clause, the `WITH CHECK` must **not** inherit the same widening:
`rotation_policies` already establishes the correct asymmetric shape (read
side: `project_id = current_tenant OR project_id IS NULL`; write side:
`project_id = current_tenant` only, so `keyorix_app` can never write a global
row through the request path). `notifications` and `audit_events` need the
identical asymmetry once their open product-sign-off questions above are
resolved — whatever the eventual read-side rule, the write side stays
`project_id = current_tenant` only, with any global/NULL-scope row written
exclusively via `keyorix_migrator` or a dedicated admin path, never through
the runtime role's ordinary `WITH CHECK`.

**Session-variable default (unset case), decided once, applied everywhere:**
`current_setting('app.current_tenant', true)` returns `NULL` when unset (the
`true` = missing-ok flag). `project_id = NULL` evaluates to `UNKNOWN`, which
PostgreSQL treats as false in a `USING`/`WITH CHECK` clause — i.e., an
unset tenant context sees **zero** rows by default. This is the correct
fail-closed default and must never be "fixed" with an escape hatch like
`current_setting(...) IS NULL OR project_id = current_tenant` — that pattern
is a full RLS bypass disguised as a null-handling convenience and is
explicitly forbidden by this ADR.

Background/system code paths that legitimately need cross-tenant reads
(schedulers, rotation execution, audit chain checkpointing) must not be solved
by leaving `app.current_tenant` unset and hoping a permissive policy covers
them. They must either (a) run through `keyorix_migrator` for genuinely
system-wide maintenance operations (narrow, audited, not request-serving), or
(b) iterate per-tenant, setting `app.current_tenant` explicitly for each
project they touch. **Enumerating every such background call path is
implementation scope, not this ADR's scope** — flagged here so it isn't
discovered as a production outage after RLS ships.

### 1c. Injection point: `SET LOCAL`, never `SET SESSION`

`tx.Exec("SET LOCAL app.current_tenant = ?", tenantID)` as the first statement
inside `WithTransaction`'s callback (`local_transaction.go:17-21`), mirroring
the existing `pg_advisory_xact_lock` pattern in `local_audit_chain.go:167`.

**`SET LOCAL` is transaction-scoped and resets automatically at
`COMMIT`/`ROLLBACK`.** This codebase runs one shared, pooled `*gorm.DB`
process-wide (confirmed: `server/main.go`, `factory.CreateStorage` called
once at startup) — connections are returned to the pool after each
transaction and reused by unrelated requests, potentially for a different
tenant on the very next checkout. `SET SESSION` persists on the physical
connection past `COMMIT` and would leak one tenant's context onto whichever
request happens to draw that same pooled connection next — a cross-tenant
disclosure introduced by the fix itself. **This reasoning is recorded here so
that a future "simplification" to `SET SESSION` — e.g. to avoid re-issuing it
per transaction, or because it "tests the same either way" — is caught by
someone reading this ADR before it ships, not by an incident report after.**

Any code path that checks out a raw `*sql.Conn` outside `WithTransaction`
(`local_bootstrap_lock.go`, `local_audit_checkpoint_lock.go`,
`local_scheduler_lock.go` — currently advisory-lock bookkeeping only) must be
audited as part of implementation to confirm none of them touch
RLS-protected tables. If any do, they need their own `SET LOCAL` inside an
explicit transaction, or must be moved onto `WithTransaction`.

**Measured, not assumed: how much of the read path actually goes through
`WithTransaction`.** `LocalStorage` (`internal/storage/store/entry.go:178-198`)
holds one `db *gorm.DB` field; every storage method issues GORM calls
(`Find`/`First`/`Where`/`Count`/etc.) directly on it, and `WithTransaction`
(`local_transaction.go:17-27`) only rebinds that field to a transaction handle
for the duration of its own callback. A repo-wide count of read-style calls
made through `internal/core` (the sole consumer of `storage.Storage`) found
**666 call sites reading directly on the outer, non-transactional handle**
against **4** reading on a `tx` parameter inside an existing `WithTransaction`
closure — roughly **0.6%** of read traffic would receive the `SET LOCAL` this
section originally specified. The other **99.4%**, including every list/get
endpoint that serves a request (`ListProjects`, `GetProject`, `ListSecrets`,
`ListMachineIdentities`, `GetMachineIdentity`, `ListProjectMembers`, the
dashboard and project-stats aggregates), would run with `app.current_tenant`
unset. Per §1b's fail-closed default this is not merely "unprotected" — an
unset session variable makes every one of those reads return **zero rows**,
indistinguishable from an empty project, the instant `FORCE ROW LEVEL
SECURITY` goes on. As originally scoped, §1c doesn't leave a gap at the edges;
it breaks the read path wholesale on day one, application-wide, not just for
this ADR's twelve backfilled tables.

**Decision: a GORM callback plugin, not 666 hand-rewritten call sites.**
Register a `gorm.Plugin` (`db.Use(...)`) with `Before` callbacks on the
query/row/raw/create/update/delete callback points. When a call arrives on a
connection pool that is *not* already a transaction (i.e., not already inside
`WithTransaction`), the plugin transparently promotes that single statement
into its own short-lived explicit transaction — `BEGIN`, `SET LOCAL
app.current_tenant = ?` from the request context, the original statement,
`COMMIT` — with no change to any of the 666 call sites. This still uses `SET
LOCAL`, never `SET SESSION` — it does not weaken this section's pooling
argument above, it extends the same mechanism to the calls that don't already
have an enclosing transaction to attach it to.

**Detect an in-flight transaction and skip — never nest a savepoint per
statement.** GORM's default behavior for a `Transaction()` call issued while
already inside another transaction is to open a `SAVEPOINT`, not a new
top-level transaction. If the plugin calls `db.Transaction(...)` for every
statement without first checking whether it is already running inside
`WithTransaction`, it will silently nest a savepoint per statement inside
every existing explicit transaction — multiplying round trips inside the one
place (`WithTransaction`) that already has a working `SET LOCAL` from its own
start, for no benefit. The plugin must detect the in-flight-transaction case
(the connection pool the current `*gorm.DB` is bound to already implements
the driver's transaction interface, distinguishing a `tx`-bound `*gorm.DB`
from one bound to the raw pool) and, when true, do **nothing**: no additional
`SET LOCAL`, no savepoint, no wrapping. The enclosing `WithTransaction`'s own
`SET LOCAL`, issued once at its start, already covers every statement inside
it, nested calls included.

**The scoping heuristic's failure mode: not a leak, a silent outage — but
still not good enough to keep.** Determining "does this statement touch a
protected table" requires inspecting `Statement.Table`/`Statement.Schema` per
call. State the failure mode explicitly so it is diagnosed correctly the
first time it's hit: if the heuristic fails to recognize a statement as
touching a protected table, the plugin does not wrap it, `app.current_tenant`
stays unset on that connection, and §1b's fail-closed default applies — the
statement returns **zero rows**, never another tenant's rows. That is the
correct direction to fail in, and it must be documented here so the first
person who hits it treats an empty result as a wrapping bug to fix, not as
evidence a policy is "too strict" — the forbidden escape hatch exists
precisely to be reached for at this exact moment.

That said, a primary-table heuristic has specific, known blind spots, not
hypothetical ones:
- **`db.Raw(...)` has no parsed table.** GORM's raw-SQL path bypasses the
  statement builder that populates `Statement.Table`/`Statement.Schema` —
  there is nothing for a primary-table check to inspect. A heuristic keyed on
  the parsed table cannot classify a raw query at all and must pick a default
  for "unknown," which is itself a decision with a failure mode either way.
- **`.Joins(...)`/`.Preload(...)` can touch a protected table that isn't the
  query's primary table.** A query whose primary table sits in §1d's
  "deliberately global" set (e.g. `users`) can still join or preload a
  protected table (e.g. `machine_identity_roles`); a heuristic that only
  inspects the primary table misses this, the statement isn't wrapped, and
  the joined/preloaded protected rows come back empty while the primary
  table's own rows return fine — a partial, confusing result, not a clean
  all-or-nothing failure.

**Decision: wrap every non-transactional statement uniformly; drop the
per-table scoping heuristic entirely.** The heuristic's only possible saving
is on the "deliberately global" tables (§1d) — RLS with no matching policy
makes `SET LOCAL app.current_tenant` a harmless no-op there, so wrapping them
anyway costs a round trip but changes no query result. Against that bounded,
already-known saving, a table-detection heuristic would have to correctly
classify every call *shape* GORM supports (bare calls, joins, preloads, raw
SQL, subqueries) to avoid the silent-outage failure mode above — and this
codebase has already hit exactly this class of bug more than once: an
enumeration of call shapes that misses an idiom it doesn't know about (see
`docs/g80-remediation-notes.md`'s repeated "an enumeration is only as complete
as the idioms it knows about" finding), discovered each time only after it
silently misclassified something. Wrapping unconditionally removes the
classification problem instead of trying to make it exhaustive: no allowlist
to keep in sync as tables are added or queries change shape, and a new
protected table introduced later is covered automatically rather than
requiring someone to remember to register it.

**Name the cost.** Every one of the 666 currently single-round-trip
statements — now unconditionally, not only the ones matching a table
heuristic — becomes a four-statement round trip
(`BEGIN`/`SET LOCAL`/statement/`COMMIT`) and holds a pooled connection for the
duration of an explicit transaction instead of one implicit one. This is a
real latency and pool-pressure cost on every list/get endpoint in the
product, including the "deliberately global" auth/session/RBAC lookups that
don't need RLS at all, and must be benchmarked against realistic data volumes
and concurrency before this ships, not assumed negligible (see Consequences
for the required measurement).

**Hitting this during implementation is not grounds for the forbidden escape
hatch.** Neither "the plugin is hard to get right" nor "the latency cost is
too high" license falling back to `SET SESSION`, to the `current_setting(...)
IS NULL OR project_id = current_tenant` pattern §1b already forbids, to
quietly narrowing RLS enforcement to only the 4 call sites that happen to run
inside `WithTransaction` today, or to resurrecting the per-table scoping
heuristic this section just rejected in order to claw back some of the cost.
The plugin above is the sanctioned mechanism for the non-transactional
majority; a future implementer who finds it inconvenient must fix the plugin,
or bring a new ADR amendment with its own empirical measurement — not bypass
RLS at the query site.

### 1d. Scope

**Get `project_id` added (denormalized, ~12 tables, all one join from a
table that already has it):** `secret_versions`, `secret_access_logs`,
`secret_metadata_history`, `secret_tags`, `secret_acls`,
`secret_access_schedules`, `secret_version_comments`, `share_records`,
`anomaly_alerts`, `machine_identity_credentials`,
`machine_identity_oidc_bindings`, `access_review_items`.

Populated by a `BEFORE INSERT/UPDATE` trigger deriving the value from the
parent row (e.g. `secret_versions.project_id := (SELECT project_id FROM
secret_nodes WHERE id = NEW.secret_node_id)`), **not** trusted from
application-supplied input. This keeps the second layer trustworthy even if
application write-path code sets the wrong value — the database, not the
handler, is the source of truth for what `project_id` means once the column
exists.

**Trigger security context: `SECURITY INVOKER`, stated explicitly, not left
to the default.** `SECURITY INVOKER` is Postgres's own default when
unspecified, but this ADR requires it be written explicitly in the migration
rather than relied on implicitly — so a future reviewer sees the decision, not
just its absence. The risk being written down: if a future change declares
one of these triggers `SECURITY DEFINER` and, following the natural instinct
to own it the same way as the rest of the schema, the function ends up owned
by `keyorix_migrator`, it would execute with that role's privileges —
including `BYPASSRLS` (§1a) — on every row insert/update, for every caller,
forever. That silently reopens exactly the bypass §1a spent two empirical
reproductions closing, except triggered by ordinary application traffic
instead of a migration step, and with no error or log line marking the
moment it happened.

**A `NULL` derivation must `RAISE`, never insert `NULL`.** If a trigger's
parent-row lookup (e.g. `SELECT project_id FROM secret_nodes WHERE id =
NEW.secret_node_id`) finds no row or a `NULL` `project_id` — a dangling
foreign key, a parent deleted concurrently, or a parent that unexpectedly has
children despite being in §1d's "deliberately global" set — the trigger must
`RAISE EXCEPTION`, not silently write `NULL` into the new row's `project_id`.
A `NULL` `project_id` on an RLS-protected table is invisible under every
tenant's `USING` clause (§1b's fail-closed default: `NULL = current_tenant`
evaluates `UNKNOWN`) — including to the session that just inserted it. A row
that silently disappears from its own creator's view, with no error anywhere
in the chain, is a worse failure than blocking the write outright.

**Already have `project_id` directly, get RLS policies only:** `environments`,
`secret_nodes`, `secret_dependencies`, `notifications`, `audit_events`,
`user_roles`, `group_roles`, `user_groups`, `project_memberships`,
`project_invitations`, `access_requests`, `access_review_campaigns`,
`break_glass_activations`, `machine_identities`, `machine_identity_roles`,
`dynamic_secret_configs`, `dynamic_secret_leases`, `rotation_policies`,
`connector_project_bindings` — per the null/zero decisions in §1b where
applicable.

**Deliberately global, no RLS:** `projects` (is the tenant, not scoped to
one), `sod_policies`, `risk_exceptions`, `legal_holds`,
`rejection_reason_templates`, `alert_escalation_policies`,
`notification_channels`, `anomaly_config_records`, `users`, `sessions`,
`personal_access_tokens`, MFA/WebAuthn tables, `password_resets`, `settings`,
`roles`, `permissions`, `role_permissions`, `groups`.

### 1e. What this does not protect

- **SQLite has no RLS.** The dev/single-instance path (ADR-039: SQLite is
  supported only for single-instance/dev, not HA) keeps only the existing
  application-layer checks. This ADR does not weaken that path; it also
  doesn't strengthen it.
- **A `keyorix_migrator` (owner + `BYPASSRLS`, §1a) or superuser connection
  still sees and writes everything**, by design — someone has to be able to
  run schema migrations and §1g's backfill steps without RLS silently
  blocking them (the reverse trap). This makes the migrator role's credential
  handling an operational control, not a database one: it must not be
  embedded in the runtime app's secrets/config, must not be used by any
  request-serving process, and access to it should be as narrow and audited
  as any other break-glass credential.
- **RLS enforces "which tenant" once the session variable is set correctly;
  it does not enforce that the value in the session variable is correct.**
  If upstream authentication/session-to-tenant binding is itself broken, RLS
  faithfully enforces access to the wrong tenant. This is a second layer
  against a missing or buggy scoping check in the read/write path (the PR
  #1774 shape) — it is not a substitute for correct authentication.

### 1f. Verification design

Without this, the effort is unverifiable — enabled-but-bypassed RLS looks
identical to working RLS in every way except the one query that matters.

**Test 1 — tenant isolation, connected as the runtime role.** Setup (as
`keyorix_migrator`): insert rows for tenant A and tenant B. Test body:
connect as **whatever role the CI/test config's runtime DSN actually
specifies** (the test must not use a test-admin/superuser shortcut — it has
to exercise the same role production traffic uses, so a future DSN
misconfiguration fails this test, not just a manual audit). `SET LOCAL
app.current_tenant = 'A'`; run a plain, unqualified `SELECT * FROM <table>`
(no explicit tenant `WHERE` — this specifically reproduces the "handler
forgot the scoping clause" shape of PR #1774 at the database layer); assert
only tenant A's rows return, zero of tenant B's.

**Test 2 — RLS is actually forced, not just enabled.** For every table in
§1d's protected scope: query `pg_class.relforcerowsecurity` and assert true;
query `pg_tables.tableowner` and assert it is **not** the configured runtime
role. This directly encodes the empirical failure mode reproduced above —
a future config regression (DSN repointed at the owner role, a migration that
recreates a table without `FORCE`) fails CI immediately instead of silently
disabling protection.

**Test 3 — the migrator/runtime pairing, not just runtime isolation alone.**
On the same table as Test 1/2: as `keyorix_migrator`, with **no**
`app.current_tenant` set, run a blanket `UPDATE <table> SET ...` with no
`WHERE` clause and assert it affects **all** seeded tenants' rows (proves
`BYPASSRLS` genuinely lets backfills work — §1a's reverse trap). In the same
test, as `keyorix_app` with tenant A's context set, run the identical blanket
`UPDATE` and assert it affects **only** tenant A's rows. Asserting both
directions in one test is deliberate: a change that fixes one side and
silently breaks the other (e.g. someone removes `BYPASSRLS` "to be safe" and
breaks every future backfill, or someone grants it to the runtime role "to
fix a backfill bug" and reopens the original hole) is exactly the failure
mode a test that only checks one side would miss.

**Test 4 — `WITH CHECK` blocks cross-tenant writes.** For every table in
§1d's protected scope: connect as the runtime role, `SET LOCAL
app.current_tenant = 'A'`; attempt an `INSERT` and, separately, an `UPDATE`,
each supplying tenant B's `project_id` explicitly; assert both are **rejected**
with a policy-violation error — not silently accepted, and not a silent
zero-row no-op (a `WITH CHECK` failure on `INSERT` errors; it does not skip
the row). This is the write-side counterpart to Test 1 and exists because
Test 1 cannot detect a missing `WITH CHECK` at all — it never attempts a
write.

**Guard — every GORM entry point carries a tenant-bearing context, not just
the call sites these four tests happen to exercise.** §1c's plugin can only
set `app.current_tenant` if the `context.Context` reaching that call actually
carries the tenant, propagated from the authenticated request. A dropped
context — `context.Background()`/`context.TODO()` substituted at any call
site between the HTTP handler and the storage call, whether by a future
refactor, a background goroutine spun off without threading `ctx` through, or
a helper that swallows and replaces it — is invisible on SQLite (no RLS,
nothing to enforce) and invisible to a superficial code read (the call still
compiles and still runs). On the Postgres path, in production, it silently
degrades to §1c's own fail-closed default: `app.current_tenant` unset, zero
rows, at exactly the one call site that dropped it. This is an availability
defect, not a security one — RLS still fails closed — but severe enough for
this product (a customer's dashboard or secret list silently going empty)
to qualify under this repo's own guard criterion. Required: a structural
check enumerating every exported `LocalStorage`/`storage.Storage` method and
asserting its first parameter is a real, threaded `context.Context` — not a
single reproduction test for one call site, since the failure this guards
against is "a call site nobody thought to check," and a guard aimed at one
known case instead of the general shape would be exactly the kind of
conclusion-only guard this repo's own engineering notes already warn against.
Red-then-green: deliberately substitute `context.Background()` at one call
site, confirm the check fails; restore it, confirm green.

**Red-then-green, required before any of these four tests is considered
load-bearing:** when first written, temporarily remove `FORCE` (or point the
test at the migrator role) and confirm Test 1/Test 2 go red; temporarily
strip `BYPASSRLS` from the migrator role and confirm Test 3's migrator-side
assertion goes red; temporarily drop a table's `WITH CHECK` clause (leaving
`USING` untouched) and confirm Test 4 goes red for that table; restore each
and confirm green. This is the same practice already standing in this
repository (verify a repaired test by breaking its subject) — it applies here
with extra force because the whole point of this ADR is a control that fails
silently when misconfigured, in either direction.

**Standing CI gate, not a one-time check:** Tests 2, 3, and 4, and the
context-propagation guard above, should run on every PR that touches
migrations, the §1g step registry, or the Postgres role/Helm provisioning,
using the existing `KEYORIX_TEST_PG_DSN`-gated real-Postgres CI
infrastructure (`.github/workflows/ci.yml`) already used by the
`*_postgres_test.go` HA-lock contention suite — not just once at merge time.
The context guard specifically should run on every PR regardless of whether
it touches migrations, since it's a static check over Go source, not a
Postgres-dependent test — gating it only on migration-touching PRs would
miss the exact case it exists for (a refactor in `internal/core` that drops a
context, nowhere near a migration file).

### 1g. Minimal schema ledger for named schema/backfill steps

**The problem this section exists to avoid:** §1d requires backfilling
`project_id` onto ~12 existing tables. Following #1723's pattern literally —
a hand-written Go function, wired into `migrateDatabase`, fatal on error,
re-run in full on every boot — verbatim, twelve more times, is where that
pattern stops being proportionate. Each of those twelve steps would re-scan
its table on every single server start forever, and there is still no
artifact a DBA can point to and ask "did the `access_review_items` backfill
run, and when" (the gap filed as part of this workstream's investigation:
`AutoMigrate` plus ad hoc fatal Go steps is auditable only by reading source,
not by querying anything).

**Decision: a `schema_steps` ledger table plus a runner that skips completed
steps, layered on top of #1723's pattern — not a replacement for it.**

- `schema_steps(name TEXT PRIMARY KEY, completed_at TIMESTAMPTZ NOT NULL)`,
  written only by `keyorix_migrator`.
- Each backfill (the twelve in §1d, and #1723's account-state backfill if
  ported to this mechanism) is registered as a named step: a Go function plus
  a stable string name.
- The runner, called from `migrateDatabase` after `AutoMigrate`: for each
  registered step, if `name` is present in `schema_steps`, skip it; otherwise
  run the step function, and on success (no error), insert the `schema_steps`
  row in the **same transaction** as the step's own writes — so a crash
  between "step ran" and "ledger recorded" is impossible; either both happen
  or neither does, and a missing ledger row after a crash means the step
  genuinely didn't complete and will correctly re-run next boot.
- Failure remains fatal, exactly as #1723: an error from any step aborts
  `migrateDatabase`, which aborts server boot. This is unchanged, not
  softened.

**Stated explicitly, so this isn't "optimised" away later: the ledger is for
skipping redundant cost and for auditability, NOT for correctness.** The
boot-time re-run guarantee — every step runs, fatally-on-error, until it
provably succeeds — is a strictly stronger correctness property than "trust
the ledger row." Each step function must remain independently idempotent and
safe to re-run even if its `schema_steps` row is missing, wrong, or the table
doesn't exist yet (fresh install) — the same discipline `backfillBlankAccountState`
already has (it re-scans for blank rows and no-ops if none exist, regardless
of any ledger). The ledger is a fast-path cache in front of that guarantee,
never a substitute for it. A future change that makes the ledger the *only*
thing gating whether a step's underlying data-safety check runs would
silently reintroduce exactly the failure mode #1723 was written to close.

**Interaction with §1a's reverse-ownership decision:** a step's completion
must only ever be recorded when it actually ran as `keyorix_migrator`
(`BYPASSRLS`). If a future step were accidentally invoked under the runtime
role after RLS is active, it would update zero rows (§1a's reverse trap) —
and if the ledger were written unconditionally on "no error," it would
record a false completion for a backfill that touched nothing. The runner
must check `current_user`/role identity before recording success, not just
absence of an error.

**Why this doesn't reopen ADR-097's rejected alternative:** ADR-097
considered and rejected "a full versioned migration framework (numbered
up/down files, a `schema_migrations` table tracking every individual step)"
as disproportionate to the narrow downgrade-detection problem it was solving.
`schema_steps` is not that: no up/down files, no rollback, no ordering
semantics beyond "registered order," forward-only, one small table, and it
reuses — rather than replaces — the fatal/idempotent wiring ADR-097 itself
called out approvingly ("`migrateDatabase`'s existing idempotent-additive
design already handles forward migration correctly"). It solves a different
problem (skip-cost and per-step auditability for named data-mutating steps)
than ADR-097 solves (an old binary refusing to run against a newer schema).
The two coexist: ADR-097's `schema_epoch` still gates whether `migrateDatabase`
runs at all; `schema_steps` gates which named steps *within* it actually do
work versus no-op.

## Consequences

- A real code change is required before this can be enabled: two DSNs/roles
  in config (one with `BYPASSRLS`), a migration-time-only connection, a
  schema migration for the ~12 tables in §1d, policies, triggers for derived
  `project_id`, the `schema_steps` ledger and runner (§1g), and the three
  verification tests (§1f). None of that is built by this ADR.
- Two decisions in §1b (`audit_events` NULL-scope visibility, and whether
  "global" `notifications` can safely be blanket-visible) are explicitly left
  open pending product/security sign-off and must not be resolved silently
  inside an implementation PR.
- Both the forward trap (owner exempt from RLS without `FORCE`) and the
  reverse trap (`FORCE` blocking the migrator's own backfills without
  `BYPASSRLS`) were reproduced empirically against real `postgres:16`, not
  assumed from documentation — see §1a. The asymmetric role design (migrator:
  owner + `BYPASSRLS`; runtime: neither) is what makes both traps closed
  simultaneously; changing either role's privileges without re-running Test 3
  (§1f) risks silently reopening one of them.
- The `project_id = 0` sentinel convention (§1b) is flagged as worth
  hardening (explicit column or `CHECK` constraint) as a **separate**
  follow-on, not blocking this ADR.
- No production Postgres deployment exists today, so the schema change this
  ADR requires has no downtime/backfill risk right now. That will not remain
  true once a customer goes live on Postgres — this is the reason to do this
  now rather than "when we have time."
- **Index implications.** Every query in §1d's scope now filters on
  `project_id` (directly, or via the derived column on the twelve backfilled
  tables) once RLS folds the tenant predicate into every `WHERE` clause.
  Composite indexes prefixed by `project_id` will likely be needed on
  hot tables (`secret_versions`, `secret_access_logs`, `audit_events`,
  `machine_identity_credentials`) or query plans degrade under real data
  volumes — this must be measured, not assumed free, as part of
  implementation. "Postgres is slower than SQLite" is a bad look for a
  product whose HA story (ADR-039) depends on Postgres being the credible
  choice.
- **Required before/after latency measurement, not assumed.** §1c's plugin
  turns every currently single-round-trip, non-transactional statement into a
  four-statement round trip (`BEGIN`/`SET LOCAL`/statement/`COMMIT`); 666 read
  call sites go through this path today, and the decision to wrap
  unconditionally (§1c) means every write and every "deliberately global"
  table lookup pays it too. Before implementation ships, produce an actual
  before/after comparison using `scripts/memory-measurement/` (does not exist
  in this repo yet — create it as part of implementation, scoped to this
  comparison, not built as a general-purpose benchmarking framework), run
  against realistic data volumes and concurrency, not a synthetic
  single-connection loop. These sizing numbers are also a go-to-market asset —
  "what does the second tenancy layer cost" is a conversation this product
  will have with customers evaluating Postgres/HA, so the measurement needs to
  be defensible externally, not just reassuring internally. If the measured
  cost is material, the sanctioned mitigation is pipelining `BEGIN` + `SET
  LOCAL` + the original statement as a single multi-statement `Exec` (one
  network round trip instead of three; `COMMIT` remains separate) — but that
  optimization is justified by the measurement, not built preemptively on the
  assumption it will be needed.
- **Dialect divergence in test coverage.** RLS is Postgres-only (§1e); the
  bulk of this repo's test suite runs against SQLite. Once this ships, the
  two dialects diverge in actual query behavior on identical inputs — a
  SQLite-run test can pass while the same code path silently returns zero
  rows (§1c) or slips a missing `WITH CHECK` (§1f Test 4) on Postgres, and
  nothing in the SQLite-run suite would ever observe it. §1f's four
  RLS-specific tests, gated only on PRs that touch migrations/roles, are
  necessary but not sufficient exposure. A meaningful subset of the broader
  suite — not just the RLS-specific tests — should run against real Postgres
  in CI regularly, mirroring the existing `KEYORIX_TEST_PG_DSN`-gated HA-lock
  contention suite, so a Postgres-only regression elsewhere in the codebase
  doesn't have to wait for someone to touch migrations directly before it's
  caught.
