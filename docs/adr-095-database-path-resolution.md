# ADR-095: `storage.database.path` resolved against process cwd, not the config file — fixed at load time

## Status

**Accepted (2026-08-31).** #1636 (re-scoped from a migration-lock report to its
actual root cause). Fix landed; the in-database migration-lock hardening and
the create-vs-refuse behavior change are recommended, not built, in this pass.

## What this is

#1636 was originally filed as a migration-lock bug: `secrets.db.migration.lock`
turned up untracked in several directories. The two-process reproduction that
investigation ran found something larger — two servers started from different
working directories didn't share a database at all. Each silently created its
own, both succeeded, neither warned. The lock was a symptom.

`internal/storage/factory.go:185-187` defaulted `database.path` to the
relative `"./secrets.db"`, and the operator-facing template
(`configs/keyorix.yaml.tpl:97`, formerly line 73 pre-#1637) ships `"keyorix.db"`
— equally relative. Neither was ever resolved to an absolute path before being
handed to `gorm.Open`. Reachable without anyone doing anything wrong: systemd
with `WorkingDirectory=/`, a container with `WORKDIR /app`, or an operator
running the binary from a different directory across two restarts.

## Task 1 — does this reach bootstrap? No. Data-integrity, not escalation.

Traced before anything else, since it decides the severity class:

- Opening a missing SQLite path silently creates an empty schema (via
  `gorm.Open` + `migrateDatabase`'s `AutoMigrate`) — no distinct gate on that
  step. This is the actual "silent creation" finding.
- Populating that empty schema with an admin identity, RBAC roles, or any
  privileged material is a **separate, explicit, token-gated step**
  (`BootstrapSystem`, reached only via `POST /system/init`). Nothing calls it
  automatically at boot.
- The token itself is generated fresh and logged **masked** (first 8 + last 4
  characters only — `server/main.go:346`) whenever it wasn't operator-set via
  `KEYORIX_BOOTSTRAP_TOKEN`; the comment is explicit that the full value is
  otherwise unrecoverable by anyone, including the legitimate operator,
  without rebooting with the env var pre-set. `BootstrapSystem` fails closed
  outright on an empty token (`auth_bootstrap.go:250-251`).
- The CLI's own remote-bootstrap path (`keyorix system init --server`) goes
  through the identical HTTP-gated endpoint with the identical token
  requirement — no local-access bypass. There is no gRPC bootstrap RPC.
- A freshly-created, uninitialized instance IS externally indistinguishable
  from a healthy one: both `/health` (`server/http/handlers/health.go`) and
  `/readyz` (`readiness.go`, a bare `SELECT 1` reachability ping) report
  healthy/ready regardless of bootstrap state.

**Verdict: data-integrity, not privilege-escalation.** An actor able to
influence the process's working directory gets a running-but-empty Keyorix
that looks healthy — not one that bootstraps into their control. Claiming it
still requires the actual bootstrap token, which the cwd bug itself does not
grant. Per the investigation's own guardrail, this cleared the pass to fix
rather than stop-and-report.

## Task 2 — the class, not the instance

Every filesystem path the process resolves at runtime, verdicted:

| Path | Resolution | Consequence if cwd-relative |
|---|---|---|
| `storage.database.path` | Was cwd-relative | **Silent — a fresh, healthy-looking empty database.** Fixed here. |
| SQLite migration lock (`*.migration.lock`) | Derived from `database.path` (same defect, same cause) | Silent — symptom of the above. Not independently fixed (see Task 4). |
| `storage.encryption.dek_path` / `salt_path` | Cwd-relative (`server/main.go:252-254`'s own `baseDir = "."` fallback) | **Loud** — encryption init fails closed at boot if the key material can't be found; server refuses to start rather than serve plaintext. |
| `key_provider.file_path` (file-type KMS) | Cwd-relative, no baseDir at all (`internal/crypto/raw_providers.go`) | Loud — `os.Stat` failure surfaces as an encryption-init error, same fail-closed boot refusal. |
| `key_provider.wrapped_key_path` (TPM/KMS types) | Cwd-relative, but baseDir-aware like DEK/salt | Loud, same as above. |
| `server.http.tls.cert_file` / `key_file` | Cwd-relative (`tls.LoadX509KeyPair`, `server/main.go:2043`) | Loud — missing file fails `ListenAndServeTLS` at boot. |
| `tls.cert_cache_dir` (autocert/ACME cache) | Cwd-relative, defaults to `"certs"` (`server/main.go:2097-2099`) | Degraded, not silent-data-loss — a lost cache re-requests a cert from Let's Encrypt, risking their rate limit on repeated cwd drift. Opt-in feature (`auto_cert`), not in the default template. |
| `audit_forwarding.siem.spool_dir` | Cwd-relative (`internal/audit/siem/spool.go`) | Low — opt-in, off by default; a misplaced backlog file, not data loss. |
| `evidence_delivery.output_dir` | Cwd-relative (`server/main.go:1510`) | Low — opt-in, self-reporting (the resolved dir is logged on every scheduler tick). |
| `notary.ca_cert_path` (audit-checkpoint RFC 3161 anchor) | Cwd-relative | Low — failure is logged and the feature best-effort-degrades; anchoring continues to fail loud in logs, not silent. |
| `license.path` | Cwd-relative | Low — logged `WARNING`, degrades to community baseline. Not security-relevant. |
| **Config file's own path** (`KEYORIX_CONFIG_PATH` / `keyorix.yaml`) | **Already correct** — `Load()`'s `baseDir`/`filepath.IsAbs` handling (`config.go:1767-1770`) roots an absolute path at its own directory. This IS the anchor the fix below reuses. | — |
| Postgres client connection / migration lock | **Not applicable** — DSN/host/port fields, no filesystem path; `pg_advisory_lock` is a live-connection primitive with zero cwd dependency (`factory.go:73-80`, confirmed by reading the code, not assumed). | — |
| Unix socket paths | **Not applicable** — no such feature exists in this codebase. | — |
| Plugin/extension directories | **Not applicable** — no such feature exists in this codebase. | — |

Only `database.path` (and its lock symptom) produces *silent* divergence.
Every other cwd-relative path fails loud or degrades a specific, generally
opt-in feature — annoying, not dangerous, and explicitly reported as such
rather than left unstated.

## Task 3 — absolute is not sufficient (recommended, not built)

Resolving to absolute stops two processes from silently diverging onto two
different files. It does not stop a single mistyped absolute path from
producing a fresh, empty, healthy-looking store on its own.

**The rule worth adopting:** opening a database expected to exist and finding
nothing should refuse, not create. The codebase already has the exact marker
this needs, without inventing a fourth mechanism: `keyorix system init
--database` (`internal/cli/system/init.go:162-181`) already creates the
database file as an **explicit, deliberate step** (`O_CREATE|O_EXCL`, atomic,
no TOCTOU) — this is already the intended "yes, a fresh install belongs here"
signal. `createLocalStorage` (the server's boot path) currently doesn't check
for the file's prior existence at all before letting `gorm.Open` silently
vivify it.

**Recommended, not built this pass:** `createLocalStorage` should `os.Stat`
the resolved path before `gorm.Open` and refuse (`"no database found at %s —
run 'keyorix system init' to create one, or verify database.path/working
directory"`) unless the file already exists. Cost: one stat call, one new
error path; the compatibility risk is real (an existing fresh-install flow
that never explicitly runs `system init --database` first would start
failing) and is exactly the kind of behavior change that deserves a
deliberate sign-off rather than landing inside a same-day investigation.

## Task 4 — the fix, in the order that mattered

Two independent pieces were on the table. What actually landed:

1. **Built — `database.path` resolved to absolute at `Load()`, anchored to
   the config file's own directory, not process cwd.**
   `internal/config/config.go`: `resolveConfigRelativePath(baseDir, path)`,
   called from `Load()` using the *same* `baseDir` the config file's own path
   was already resolved against. An in-memory DSN (`:memory:`,
   `mode=memory`) and any existing `?query` suffix are left untouched,
   mirroring `acquireSQLiteMigrationLock`'s own detection of the same two
   shapes. Lands first — it's the actual reported defect.

   **Caught and fixed a regression this introduced before it shipped:**
   `filepath.Abs`/`Join` silently collapses a `"../escapes.db"` traversal
   attempt into a clean absolute path with no `".."` substring left to
   detect — which would have defeated `internal/cli/system/init.go`'s own
   `initializeDatabase` traversal guard (a check that, on inspection, only
   ever ran on the CLI's `init --database` step in the first place, never on
   the server's own boot path). Centralized the rejection into
   `resolveConfigRelativePath` itself instead: a `database.path` containing
   `".."` now fails `Load()` outright, covering both callers rather than
   just the one that happened to remember to check.

2. **Built — the startup log line, unconditionally, regardless of what else
   landed.** `internal/storage/factory.go`'s `createLocalStorage` now logs,
   before `gorm.Open`, whether it's opening an existing database or about to
   create a new empty one, at the resolved absolute path. Pure diagnostics —
   `dbPath` itself is untouched by this log line, no behavior change. This
   directly answers "which database am I actually using," previously
   unanswerable from the logs.

3. **Recommended, not built — move the SQLite migration lock inside the
   database**, matching Postgres's `pg_advisory_lock` and the scheduler
   lease's `ON CONFLICT DO NOTHING`. On inspection, the scheduler-lease
   pattern specifically does **not** transfer cleanly here: it requires a
   pre-existing table, and the migration lock's whole purpose is guarding
   the very first migration that creates that table — a chicken-and-egg
   problem `pg_advisory_lock` (a server-level primitive, no schema
   dependency) doesn't have. The correct SQLite analog is a `BEGIN
   EXCLUSIVE` file-level lock, schema-independent and auto-released by the
   OS on crash the same way `flock` already is — but wiring it correctly
   through GORM's connection pooling (a dedicated `*sql.Conn`, careful
   `busy_timeout` handling to preserve the current fail-fast-not-blocking
   semantics) is real, correctness-sensitive plumbing. Left recommended
   rather than risking a rushed, under-verified rewrite of a mechanism that
   protects real migration integrity. Independent of (1) and (2) — this
   piece is a hardening of the lock mechanism itself, valuable once the path
   problem is fixed but not required to fix it.

## Incidental finding, filed separately

`configs/keyorix.yaml.tpl` sets `storage.type: sqlite`; `CreateStorage`'s
switch and `Config.Validate()` only recognize `"local"`, `"postgres"`,
`"postgresql"`, or `"remote"` — copying the shipped template verbatim and
booting fails outright. Unrelated to path resolution; filed as its own issue
rather than folded in here.

## Verification

- `TestLoad_DatabasePathResolvedAbsoluteRegardlessOfCwd`: the same config,
  loaded via the same absolute path from two different process working
  directories, resolves to the identical absolute `database.path` both
  times. Red before the fix (asserted `keyorix.db`, unresolved), green after.
- `TestResolveConfigRelativePath_*`: already-absolute passthrough, in-memory
  DSN untouched, query-suffix preserved, empty passthrough, `".."` rejected
  — each pinned individually.
- `TestLoad_DatabasePathTraversal_Rejected` / updated
  `TestRunInit_DatabasePathTraversal_RejectedAtConfigLoad`
  (`internal/cli/system/system_s26_test.go`, renamed from
  `TestRunInit_InitializeDatabaseErrorPropagates`): the traversal now fails
  at `Load()`, verified through both the direct helper and the real CLI
  entrypoint. `initializeDatabase`'s own defense-in-depth check remains
  independently covered by `TestInitializeDatabase_InvalidPath`
  (`system_s2_test.go`), which constructs its `*config.Config` by hand
  rather than through `Load()`.
- Two-process end-to-end re-demonstration, same absolute `KEYORIX_CONFIG_PATH`,
  different working directories, through the real `config.Load()` →
  `CreateStorage()` pipeline: process A logs "no database found... a NEW,
  EMPTY database will be created here" and succeeds; process B logs "opening
  existing SQLite database at [the same path]" and succeeds, genuinely
  contending on the same file via the (now correctly co-located) migration
  lock. Both processes' own working directories remain completely empty
  afterward; only the config-anchored directory gains `secrets.db` +
  `secrets.db-shm` + `secrets.db-wal` + `secrets.db.migration.lock`.
- Postgres unaffected: confirmed by reading `withMigrationLock`'s Postgres
  branch, which never reads `dbPath` at all, and by `database.path` legitimately
  being empty for a Postgres deployment (the DSN/host/port fields are used
  instead), which `resolveConfigRelativePath` passes through unchanged.
- Full suites: `internal/storage`, `internal/config`, `internal/cli`,
  `server/http` green.
