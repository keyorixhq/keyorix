# Role-permission generation trigger: integrity beyond "present and ENABLE ALWAYS"

Status: decided, implemented as option B (TRIGGER-ROWDIGEST-1). Backlog item TRIGGER-ROWDIGEST,
narrowed on 2026-10-16 to attackers who are superuser or can run DDL.

## What exists today

- `internal/storage/store/role_permission_generation_trigger.go` installs two statement-level
  triggers (`trg_role_permissions_generation` on `role_permissions`, `trg_permissions_generation`
  on `permissions`). Both call one PL/pgSQL function, `keyorix_bump_role_permissions_generation()`,
  which increments `system_metadata.role_permissions_generation`. The migration runs the installer
  on every boot. It issues `CREATE OR REPLACE FUNCTION` and converges each trigger to
  `ENABLE ALWAYS`.
- The role->permission cache (`role_permission_cache.go`), the one-statement principal resolutions
  (`local_principal_permission.go`), the read-path prefetch (`local_readpath_prefetch.go`) and the
  folded credential (`local_folded_credential.go`) all read the generation through
  `rolePermGenerationExpr`. That expression proves, in the same statement, that both triggers exist
  on this connection's tables with `tgenabled = 'A'`, on a session in `origin` replication role.
  If the proof fails, the generation reads as NULL and the live join answers.
- The application's own writes also call `bumpRolePermissionsGenerationTx`. The generation
  therefore moves on every in-app write whatever the database triggers do.

The proof looks at `pg_trigger` only. It does not look at the function the trigger calls, and it
cannot see a change that is undone before it next looks.

## Attacker model

Who can defeat the triggers without them reading as missing?

| Actor | Can do | Already covered by today's proof? |
|---|---|---|
| Writer with DML only on the tables (an operator's role, a script) | write rows; set its own `session_replication_role` only if superuser | yes: `ENABLE ALWAYS` plus the origin check |
| Accidental operator states (restore without triggers, `pg_restore --disable-triggers`, `ALTER TABLE ... ENABLE TRIGGER`) | leave the trigger missing, disabled, ordinary or replica-only | yes: fails closed until the next migration |
| **Owner of the function and tables** (the Keyorix database role itself) | `CREATE OR REPLACE` the function with a body that does nothing; `ALTER FUNCTION ... SET search_path`; drop and re-create a trigger that points at another function; `DISABLE TRIGGER; write; ENABLE ALWAYS TRIGGER` inside one transaction | **no**: every one of these leaves `tgenabled = 'A'` |
| Superuser | all of the above, plus catalog `UPDATE`s, native code, writes to the data directory | no; part of this cannot be covered at all |

On PostgreSQL the owner is not a superuser. Any process that holds the server's own database
credentials can replace the function. TRIGGER-ROWDIGEST-1 checked this against an ordinary
`kpg` role: the replacement succeeds and today's proof still trusts the generation.

**What such an attacker gains.** That attacker can already write `role_permissions` directly and
grant themselves anything. A stale cache adds nothing on the grant side, because a stale cache
holds the old answer. It also adds nothing for the attacker's own writes, because the old answer
favours the principals that already held the permission. The only gain is persistence against the
defender. Suppose the body is replaced and a defender later revokes a permission with direct SQL.
Every warm replica keeps authorizing from its cache. This lasts until the next in-app
role-permission write (which bumps the generation explicitly) or until a restart (which re-installs
the function). Revocations made through the API or CLI are not affected, because they bump the
generation themselves.

A variant also covers its tracks: replace the body, wait for the defender's direct-SQL revocation,
then restore the original body. The catalog then reads as clean, and nothing in today's design
would ever notice.

**What a check can and cannot buy.** Against the owner, the catalog is trustworthy: a role that is
not superuser cannot forge `pg_proc.prosrc` or a row's `xmin`. Against a superuser, a check is
detection only. It holds against a non-adaptive attacker or a tooling accident, and stops nothing
that native code or a data-directory edit can do.

## Options

### A. Per-statement function-body proof

Extend `rolePermGenerationTriggersPresentExpr` with a join from `pg_trigger.tgfoid` to `pg_proc`,
requiring `prosrc` to equal the compiled-in body (or a sha256 of it), `proconfig IS NULL` and
`NOT prosecdef`.

- Window: zero for a persistent replacement or a re-pointed trigger. Fails closed exactly like a
  missing trigger: the live join answers.
- Misses: the in-transaction disable/write/enable sandwich and tamper-then-restore. The catalog is
  clean by the time any statement reads it, and the stale entries stay stale.
- Cost: every statement that carries the proof gains a `pg_proc` lookup and a body comparison. That
  includes the read-path prefetch on every machine read. Measured on PostgreSQL with
  `BenchmarkRoleSetHasPermission_CacheHit`'s body (the statement is the proof plus one lookup), run
  interleaved against today's proof with `EXPLAIN ANALYZE` execution time: a clear, repeatable
  increase in server execution time. A sha256 comparison costs more than a plain text comparison.
  The figures are in the session report, not here. PERF-DESIGN-9 measured today's proof as within
  bench noise; this option would no longer be.
- Repairs nothing: each replica bypasses its own cache until restart.

### B. Periodic integrity check that repairs what it finds (recommended)

A background job on each PostgreSQL server reads one catalog statement every interval:

1. **Body check.** Each trigger's `tgfoid` must name a function whose `prosrc` equals the
   compiled-in body, written in plpgsql, with `proconfig` exactly
   `{search_path=pg_catalog, pg_temp}` and `NOT prosecdef`. Both
   triggers must point at that one function with `tgenabled = 'A'`.
2. **Row-version fingerprint.** Record the `xmin` of both `pg_trigger` rows and of the `pg_proc`
   row, plus each `tgfoid`. No SQL statement can set a row's `xmin` back. A sandwich, a drop and
   re-create, or a replace-then-restore therefore leaves a new `xmin` even though the definition
   reads as before. `internal/solewriter` (`fingerprintSQL`) uses the same idea.

On a failed body check, the job logs at error level, increments
`keyorix_role_permission_generation_tamper_total`, bumps the generation in a transaction of its
own, then re-runs `EnsureRolePermissionsGenerationTriggers` (which restores the body) under
`SET LOCAL lock_timeout` and bumps again in the repair's transaction. On a changed fingerprint
with a good body, it logs, increments the counter and bumps the generation. Bumping the
generation invalidates every replica's cache, so any staleness from the tampered period is
flushed fleet-wide, not just hidden on one replica. A false positive (an unforeseen catalog
rewrite such as a `pg_upgrade`) costs one cache refill and changes no decision.

The first bump never waits on the repair. The repair's `DROP TRIGGER` needs an ACCESS EXCLUSIVE
lock on the table, which any open transaction on it (an idle session, a long `pg_dump`) blocks,
and a superuser can make the repair fail outright. In one transaction, that failure also rolled
back the bump, and with no deadline a queued `DROP TRIGGER` stopped every later tick and stalled
every reader of the table queued behind it. Now the lock wait is capped
(`rolePermGenerationRepairLockTimeout`) and each tick has a deadline
(`rolePermGenerationIntegrityTickTimeout`). If the repair or the re-read fails, the job keeps the
previous baseline and stays pending: every later tick bumps again and retries the repair, until
a repair commits and the re-read is clean. It never adopts the catalog it reads after a failed
attempt as a new baseline, because the body may have been restored in between and nothing would
be left to see.

To keep the fingerprint stable across ordinary boots, the installer stops rewriting a function
that is already correct. It replaces the body only when the body check fails, and logs a warning
when it replaces a body that differed (an upgrade from an older release, or tampering). Without
this, every replica boot would rewrite the `pg_proc` row and flush every cache once.

- Window: at most one interval (`rolePermGenerationIntegrityInterval`, plus one tick timeout)
  between the tamper and the flush, also while a repair keeps failing (every pending tick bumps).
  It applies only to deliberate DDL by the owner or a superuser. Accidental states keep the
  zero-window per-statement proof.
- Rolling upgrade to the release that added the check (#3631): a replica still on an older
  release runs `CREATE OR REPLACE FUNCTION` without the `SET search_path` clause on every boot.
  Each such boot therefore reads as tampering on the new replicas: a `SECURITY:` log line, a
  `keyorix_role_permission_generation_tamper_total` increment, a repair that re-pins the function
  and a fleet-wide cache flush. No decision is wrong. Expect these alarms until every replica runs
  that release, and treat them as tampering only after that.
- Rolling upgrade between two releases that both run the check (#3717). Before version markers,
  any release that changed a definition ping-ponged with the previous one for the whole
  mixed-version window: every 30 s tick, each side read the other's definition as tampering and
  re-installed its own, with a `SECURITY:` line and a tamper increment per tick on both sides,
  fleet-wide flushes, repeated `DROP`/`CREATE TRIGGER` under ACCESS EXCLUSIVE when the trigger
  shape differed, and the older replicas undoing a security fix (such as the `search_path` pin)
  part of the time. See "Definition versions" below for how this is closed. The release that adds
  the markers keeps both function bodies byte-identical and writes the marker as a function
  `COMMENT`, which the check of the releases before it does not read, so its own rollout raises
  nothing either.
- Catches: body replacement, `ALTER FUNCTION ... SET`, `SECURITY DEFINER`, re-pointed triggers,
  the in-transaction sandwich, and tamper-then-restore between two ticks.
- Cost: zero on the request path. One small catalog statement per replica per interval.
- Startup: at boot the installer already converges, and that is the startup check. The first tick
  records the baseline right after the installer has run.
- Misses (residual): a superuser below SQL (native code, data files, a modified plpgsql handler,
  or a redefined `pg_catalog` function the body calls); a change during the window; SQLite (an
  embedded single-process file, where an attacker who can write the file controls everything).

#### Definition versions (#3717)

Each trigger function carries a version marker as its `COMMENT` (`pg_description`):
`keyorix-trigger-def <function> v<N> sha256:<digest>`. The digest is SHA-256 over a canonical text
of the definition that version names: the function's language, `proconfig`, `prosecdef` and body,
and each checked trigger's table, name, `tgtype`, argument count, `UPDATE OF` column count, WHEN
clause and constraint flag (`triggerDefDigest`). The marker is a comment, not part of the body,
so that the releases before it, which compare `prosrc` exactly, do not read it as tampering.
`pgTriggerDef.version` moves with every change to the body, the settings or the trigger shape.

The rule, as each checker and installer applies it (`pgTriggerDef.newerThan`):

1. Exactly this release's definition (the body, settings and shape comparisons above) plus
   exactly this release's marker string is the good state.
2. A marker one version ahead (`triggerDefMaxNewerSkew`), naming this function in this schema,
   whose digest matches what the catalog holds now, with every checked trigger present and on one
   function, is a newer release's definition. The checker logs a distinct, non-`SECURITY` line,
   increments the tamper counter under `reason="newer_definition"`, invalidates every replica's
   cache once (it cannot verify that body), takes the reading as its baseline and repeats the
   warning hourly. Neither the check nor the installer re-installs over it; the installer only
   turns a non-`ENABLE ALWAYS` trigger back to `ENABLE ALWAYS`.
3. Anything else is tampering, as before (`reason="tamper"`, restored, flushed): no marker, a
   malformed marker, an equal or older version that is not exactly this release's definition, a
   version more than one ahead, or a digest that does not match the catalog (a newer body edited
   in place, `ALTER FUNCTION ... SET`, `SECURITY DEFINER`, a trigger re-created on other events).

So during an upgrade from N to N+1, the first N+1 replica's migration installs v(N+1); the N
replicas each log and flush once and leave it; N+1 replicas read their own definition. A genuine
tamper of v(N+1) is restored by the N+1 replicas to their own definition. An N replica that reads
it first restores v(N), which the N+1 replicas then upgrade again: one alarm on each side, not a
loop.

Residual, stated: the digest is not a signature. The owner who can replace the function can also
write a self-consistent marker one version ahead over a body of their choice. Replicas at N leave
it in place (warning hourly, the `newer_definition` series moving) until a release at N+1, which
compares exactly, restores its own. The skew bound keeps a forged marker from outranking every
future release, and the warning says to treat it as tampering outside an upgrade. Alert on
`increase(keyorix_role_permission_generation_tamper_total{reason="newer_definition"}[1h]) > 0`
outside a deploy window. Two operational rules follow: a rolling upgrade must not skip a
definition version (one that does behaves as before markers, a ping-pong for the window), and a
release may change the body, the settings and the shape of the existing triggers but not the set
of trigger names a target checks (that needs a new function name).

#### The table the triggers write (#3713)

The generation triggers, the in-app bump and the check's own invalidation all `UPDATE`
`system_metadata`. The check compares the triggers and the function, so the owner could still make
every bump a no-op on that table: a `BEFORE UPDATE` trigger that keeps `OLD.value` for the
generation key, a rule, or forced row-level security with an `UPDATE` policy that hides the row
from the server's role. The same catalog statement now also reads `system_metadata`
(`systemMetadataWriteTargetSQL`) and requires a plain table without inheritance children, no
non-internal trigger except the retention-anchor trigger exactly as its installer creates it
(BEFORE UPDATE FOR EACH ROW, its function, and its `WHEN (key = 'audit_retention_anchor')`
clause, which keeps that function off the generation row whatever its body says), no rule, and
`relrowsecurity` and `relforcerowsecurity` false. The `xmin` of the table's `pg_class` row and of
each trigger and rule row joins the fingerprint, so an object added and removed between two ticks
still shows. On a violation the repair drops the foreign triggers and rules (re-creating the
anchor trigger if it was the one dropped) and turns row-level security off in the repair
transaction, then bumps. A rule makes PostgreSQL refuse the `INSERT ... ON CONFLICT` every bump
starts with, so the check's first invalidation fails there; the check then still repairs, and
the repair's own bump is the one that counts. A table that is not a plain table is reported every
tick and left to an operator. A future release that needs its own trigger, rule or policy on
`system_metadata` must first ship a release whose check allows it.

### C. Periodic content digest of `role_permissions` and `permissions`

Every interval, hash the two tables' rows together with the generation in one statement. If the
digest changed but the generation did not, a write bypassed the triggers: bump the generation.

- Catches every SQL-level bypass, whatever the catalog shows, including writes that leave no
  catalog trace.
- Cost: a full scan of both tables per replica per interval, which grows with the number of roles
  and permissions. It needs a per-process baseline that is correct across concurrent in-app writes
  (digest and generation must be read in one snapshot).
- Adds little over B for the owner attacker, who cannot write rows without either a trigger firing
  or a catalog change B sees. Against a superuser below SQL, it can still be defeated by whoever
  controls what the scan reads.

### D. Do nothing and document the residual risk

The exposure is narrow, as set out above. Single-writer mode (`internal/solewriter`) already
detects this class: its fence fingerprints the triggers on the fenced tables by `xmin`, and its
epoch trigger, not the generation, invalidates there. Doing nothing leaves an indefinite, silent
window in the default multi-replica mode against an attacker who holds the server's database
credentials.

## Recommendation

**B.** It covers every owner-level shape that A covers, plus the two A cannot see (the sandwich
and tamper-then-restore). It repairs instead of only bypassing, and it adds nothing to the read
path. A would add measurable cost to every machine read to close a P3 window that B bounds to one
interval. C costs a table scan for little gain over B. D leaves a silent, unbounded window.

## Findings recorded while doing this

- Fixed in this PR: `keyorix_bump_role_permissions_generation()` and the `secret_nodes`
  cache-epoch function now pin `search_path = pg_catalog, pg_temp`, as the `internal/solewriter`
  functions do. Before, a session with `search_path = <schema>, pg_catalog` and a `bigint +
  integer` operator in that schema made its direct writes move neither the generation nor
  `cache_epoch`. This is not limited to the writer's own session: a role that owns the database
  or another role can set that `search_path` for every session (`ALTER DATABASE/ROLE ... SET`),
  including a defender's, and no trigger or function row changes for the check to see. The check
  now expects exactly the pinned `proconfig`, and the installers re-create an older unpinned
  function on the next boot.
- The `secret_nodes` cache-epoch trigger (`secret_node_cache_epoch.go`) has the same owner-level
  exposure as this trigger. Closed by STARTUP-GUARD-TAILS-1: the job checks it as a second target
  (`secretNodeCacheEpochIntegrityTarget`) and invalidates by moving `cache_epoch` on every live row
  after the repair (INV-STORE-secret-node-cache-epoch-trigger-integrity-checked). Both targets
  also reject a reading taken on a session that is not in `session_replication_role = origin`.
- The check covered the triggers and their function, not the row they write. The owner could make
  the bump a no-op on `system_metadata` itself (a `BEFORE UPDATE` trigger on the generation key
  that keeps `OLD.value`, a rule, or forced row-level security that hides the row from the
  server's role), and the job's own bump goes through the same table. Closed by
  TRIGGER-INTEGRITY-1 (#3713): see "The table the triggers write" above
  (INV-STORE-system-metadata-write-target-checked). The cache-epoch target has no such write
  target (its function assigns `NEW.cache_epoch`); a second `BEFORE UPDATE` trigger on
  `secret_nodes` remains the residual INV-STORE-secret-node-cache-epoch-trigger-integrity-checked
  states.
