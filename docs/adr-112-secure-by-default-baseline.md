# ADR-112: Secure-by-default baseline, and loud, audited opt-outs

## Status

**Accepted** (2026-10-17). Accepted by Andrei 2026-10-17. Amendments 1, 3 and 4
are shipped on main (`audit_durability`, `insecure_audit_skip_reads`;
`docs/UPGRADING.md` §6c to §6e); Amendment 5 (#2923) records the end of the
`require_mfa` upgrade grace period. Proposed 2026-10-02; the decisions taken
since are under "Decisions recorded", and the questions still open are listed
at the end.

Amended 2026-10-05 (decision by Andrei, "Amendment 1" below): the
audit-before-disclosure and `synchronous` baseline items gain one named
`insecure_` opt-out, `storage.database.insecure_audit_skip_durable_sync`,
**PostgreSQL only**. The defaults are unchanged, and SQLite's
`synchronous=FULL` becomes unconditional rather than merely default. Full spec
(Accepted): `docs/specs/fast-audit-mode.md`.

Amendment 3 (2026-10-15, **accepted by Andrei**): the audit durability opt-out
becomes `storage.database.audit_durability = strict | standard`, two baseline
levels rather than an `insecure_` opt-out, with `standard` the PostgreSQL
default and SQLite `strict` only. `insecure_audit_skip_durable_sync` becomes a
deprecated alias for one minor release. See "Amendment 3" below.

Amendment 4 (2026-10-15, **accepted by Andrei**): a new `insecure_` opt-out,
`storage.database.insecure_audit_skip_reads`, default false. When set,
successful secret-value reads write no audit row; everything else stays
audited. See "Amendment 4" below.

Amendment 6 (2026-10-18, BREAKGLASS-OWED-1, from Andrei's decision of
2026-10-16 "break-glass must work during an audit-subsystem incident without ever
being unrecorded"): when the audit log refuses an activation's rows, the
activation commits degraded, together with owed-audit records of those rows, with
a short lifetime, a loud alert and a mandatory review. See "Amendment 6" below.

Amendment 7 (2026-10-18, **decided by Andrei**, R1.8 / PERF-LOWCONC-1 option c):
on SQLite, `audit_durability: standard` becomes valid. Secret mutations and the
audit rows of mutations keep `synchronous=FULL`; only batches made up entirely
of successful secret-value read audits may commit on one dedicated connection
opened with `synchronous=NORMAL`. `strict` stays the SQLite default. See
"Amendment 7" below; it replaces the "SQLite" rejection in Amendment 1 and the
SQLite row of Amendment 3's table.

Amendment 8 (2026-11-25, **proposed, pending Andrei's OK**): a bounded sync
window for `standard` on SQLite, and an authenticated power-state signal that
switches audit to `strict` while a UPS reports battery. It adds no speed beyond
`standard`; it closes `standard`'s loss window on a signalled power failure. See
"Amendment 8" below.

Amendment 2 (2026-10-10, **proposed, pending Andrei's OK**, #2908): the
`enable_file_permission_check` upgrade grace period is a reported state:
a start-up warning, a settings-diff value and a posture deviation.

Related: ADR-111 (signed connector host, host connector allowlist), ADR-098 (process memory hardening), ADR-064 (air-gap update bundles), ADR-109 (air-gapped build profile).

A read-only gap check of `main` @ 219160b2 against this baseline (2026-10-02) found 9 of 22 items in place, 5 partial and 8 missing; see "Gap check results".

## Context

Keyorix's promise is "easy to operate, secure by default, with opinionated settings from experienced security people". Today that is true in many places (fail-closed startup, no default passwords, hash-chained audit, signed releases), but it isn't written down as one baseline, so:
- nobody can check a deployment against it in one step;
- a new feature can ship with a weaker default without anyone noticing;
- an operator can weaken a setting without the change being visible to auditors.

Regulated buyers (DORA, NIS2, ENS, CRA) ask for exactly this: what the secure configuration is, and how deviations are detected.

## Decision

### 1. The opt-out rule

Every setting that weakens security below the baseline:
- is named with an `insecure_` prefix (for example `insecure_allow_plain_http`), so it can't be enabled by accident or misread in review;
- logs a warning at **every** start, naming the setting;
- is audited when it changes: config has no hot reload, so at every start the server compares the security-relevant settings with those recorded at the previous start and writes an audit event with the old and new values for any difference;
- appears in the posture report (below) as a deviation.

No setting may weaken security silently. A new feature's defaults must meet the baseline; a PR that adds a weaker default must use an `insecure_` setting instead.

### 2. The posture report

`keyorix-server admin posture` (or an extension of `admin validate`) prints every deviation from the baseline: `insecure_*` settings in effect, file permissions, TLS configuration, admin MFA coverage, key rotation age, connector allowlist contents. It exits non-zero when any deviation exists, so it can run in CI or monitoring. The same data is available read-only over the API for dashboards.

### 3. The baseline

Each item is a default that holds unless an `insecure_` setting says otherwise.

**Process and host**
- Refuse to start if config, database or key files are readable by group or others (as `ssh` does with keys). The server already sets umask 0077 for files it creates (#1647).
- Core dumps disabled and the process marked non-dumpable, so a crash can't write keys or secrets to disk.
- Runs as non-root. The shipped systemd unit and container image are hardened: read-only root filesystem, no new privileges, no extra capabilities, minimal base image.
- Key material is wiped from memory after use where Go allows it (byte slices, not strings).

**Network**
- TLS 1.3 preferred; TLS 1.2 allowed by default but only with forward-secret AEAD cipher suites. TLS 1.0/1.1 are never accepted. A single setting (`tls_mode: strict`) switches to TLS 1.3 only, and the posture report shows which mode is in effect. Rationale: NIST SP 800-52 Rev. 2 requires servers to support both 1.2 and 1.3, BSI TR-02102-2 prefers 1.3 while planning 1.2's phase-out, and OT and legacy clients still need 1.2; TLS 1.2 with modern ciphers is therefore compliant, not an `insecure_` opt-out.
- No plaintext listener except a localhost health endpoint.
- Optional mutual TLS for machine identities.
- Administrative endpoints on a separate listener bound to localhost by default.

**Identity and access**
- No default credentials; first access uses the one-time bootstrap token.
- MFA required for admin accounts by default.
- Short default session lifetime; short-lived machine tokens; revocation takes effect immediately (#G18).
- Break-glass stays single-person, so it works in a real emergency, but it always produces an immediate alert and an audit event, and every activation must be reviewed afterwards: an open activation without a recorded review shows as a posture deviation. This matches the market (Infisical's "bypass approvals" works the same way) and DORA, which requires emergency access on a need-to-use basis and segregation of duties but not multiple approvers (RTS 2024/1774 Art. 21).
- Approval workflows ("dual control": a second person must approve before a secret is read, for selected policies) are a separate, later feature, not part of this baseline. Vault (control groups) and Infisical (access requests) both sell this as an enterprise feature; whether Keyorix includes it in the AGPL core or gates it is an open licensing decision (see open questions). Key-management dual control (PCI DSS 3.6/3.7) is already covered by the Shamir recovery split.
- Authorization is deny by default; any error while resolving permissions denies (fail closed). The fault-injection fuzzer's oracle (c) enforces this; #2412 is a current violation.

**Secrets and audit**
- A secret value is never returned before its audit record is committed (audit-before-disclosure, group commit). If the audit write fails, the read fails. `storage.database.audit_durability` chooses whether that commit also waits for the disk sync: `strict` waits, `standard` (the PostgreSQL default) skips only the *wait for the disk sync*, not the write and not the fail-closed behaviour — see Amendments 1 and 3.
- Secret values never appear in logs, error messages, URLs or metrics. Enforced by a test oracle over all operations, not by review alone.
- The audit log is hash-chained with signed checkpoints and offline verification (exists).
- SQLite runs `synchronous=FULL` for every mutation and for every audit row of a mutation, **unconditionally — no setting relaxes it**; Postgres runs with `fsync`, `synchronous_commit` and `full_page_writes` on (#2403). `storage.database.audit_durability: standard` is the only setting that relaxes any of this. On PostgreSQL (its default there) it relaxes only `synchronous_commit`, only on the audit transaction (Amendments 1 and 3). On SQLite (opt-in; the default stays `strict`) it lets batches made up entirely of successful secret-value read audits commit on one dedicated `synchronous=NORMAL` connection, and nothing else (Amendment 7).

**Keys**
- Scheduled KEK rotation on by default, with a configurable interval.
- HSM/KMS key protection available as an option (exists: `server/admin/encryption.go`).
- The recovery key can be split among several people (Shamir), so no single person can recover alone (exists: `internal/crypto/shamir_provider.go`).

**Supply chain and updates**
- Every binary is signed (Ed25519/cosign), with SBOM and SLSA provenance (exists).
- The connector host is signature- and version-verified before it runs, and only allowed connector types and destinations are reachable (ADR-111).
- Update bundles, including air-gapped ones, are signed and **cannot downgrade**: an older bundle is refused even with a valid signature, so an attacker can't "update" a server to a known-vulnerable version (exists, with tests).

### 4. Enforcement in CI

- A test per baseline item that fails if the default changes.
- A test that every config key weakening security uses the `insecure_` prefix, the start-up warning and the audit event.
- The posture command run against the default configuration must report zero deviations.

## Gap check results (2026-10-02)

9 of 22 items exist, 5 are partial and 8 are missing.

**Exists:** bootstrap-token-only admin creation (no default credentials); hash-chained, signed audit log with offline verification; key-material memory wiping; HSM/KMS key protection; Shamir recovery-key split; signed binaries with SBOM and SLSA provenance; signed update bundles with tested downgrade protection; deny-by-default authorization; a posture-report foundation (`admin validate`, `keyorix compliance report`).

**Inverted defaults (fix first):** `enable_file_permission_check` and `require_mfa` are off unless enabled, so the weak state is the default. Flip both; existing deployments get a grace period with a start-up warning and a posture deviation until they comply.

**Missing or partial, in priority order:**
1. Audit-before-disclosure: secret values are returned before a fire-and-forget audit write (`secrets_crud.go`). In progress (group commit, alongside the read-throughput work).
2. Fail-closed authorization on the MFA path: #2412. In progress.
3. The opt-out rule: only 4 of 32 security-weakening settings use the `insecure_` prefix; none warns consistently or is audited on change. Work: rename with deprecation aliases, start-up warnings, start-to-start settings diff audited, plus the structural CI test.
4. Posture report: `admin validate --posture` with a non-zero exit on deviations.
5. TLS: keep 1.2 as the floor, restrict it to forward-secret AEAD suites, add the TLS 1.3-only strict mode, and show the mode in the posture report.
6. Separate admin listener bound to localhost.
7. Scheduled KEK rotation (manual only today).
8. Break-glass: keep single-actor (decided 2026-10-02); add the mandatory post-activation review and its posture deviation.
9. Optional mutual TLS for machine identities.
10. CI enforcement: one test per baseline item and the zero-deviation posture gate.

## Amendment 1 (2026-10-05): fast audit mode, an `insecure_` opt-out for guaranteed-power deployments

Decision by Andrei, 2026-10-05. Spec: `docs/specs/fast-audit-mode.md`.

### Why an opt-out is warranted here specifically

PERF-2 measured Keyorix at ~10x Vault's single-client read latency on pve01
(8.36ms vs 1.30ms p50) **with Vault's own file audit device enabled**, and
confirmed that at c=1 essentially the entire 8.36ms is one durable Postgres
commit (the independently measured `fdatasync` floor on that disk is 9.33ms). A
source-verified read of each competitor's audit write path
(Vault, OpenBao, Conjur, Infisical) found that **none of them fsync audit before
answering**: Vault and OpenBao do one `write()` to an `O_APPEND` file with no
`fsync` anywhere, Conjur fires into syslog, Infisical queues to Redis and
swallows request-path errors. Their speed is not a technique Keyorix is missing;
it is the durability Keyorix declines to skip.

That makes audit-before-disclosure a genuine differentiator worth keeping as the
default — and it also makes "I have a UPS and a battery-backed write cache, give
me Vault's number" a legitimate operator request that the baseline should answer
with a named, loud, audited setting rather than with a fork or a patch.

### The opt-out

`storage.database.insecure_audit_skip_durable_sync`, boolean, default **false**,
settable from the config file only. **PostgreSQL only** (decided 2026-10-05):
the audit-commit transaction, and only that transaction, issues `SET LOCAL
synchronous_commit = off`. `SET LOCAL` is transaction-scoped, so a concurrent
secret write still commits durably and the relaxation cannot follow the pooled
connection into the next transaction.

| `storage.type` | Behaviour |
|---|---|
| `postgres` / `postgresql` | supported; in effect when true |
| `local` / `sqlite` | **refuses to start** with a named error |
| `remote` | not applicable — a server cannot run with remote storage (ADR-083) |

It carries the full §1 opt-out treatment: a `WARNING:` line at **every** start, an
`admin.audit_durable_sync_skipped_at_startup` audit event at every start (so the
tamper-evident chain itself records the window the install ran weakened), an entry
in the `insecure_` registry, a line in `admin validate`'s posture output, and a
boolean in `GET /system/info` so a buyer's auditor can see it without host access.

### What the mode does and does not change

Unchanged, and tested to stay unchanged:

- The audit row is still INSERTed and COMMITted in the same transaction/batch,
  before the secret value is returned. No background writer, no queue.
- If the audit row cannot be written, the request still fails. Only the *wait for
  the disk sync* is skipped.
- The hash chain can lose a **tail** of entries to an OS crash or power loss. It
  can never gap or fork: WAL (Postgres) and `-wal` frames (SQLite) are totally
  ordered and recovery accepts only a valid prefix, so a surviving row's
  `prev_hash` always points at a row that also survived. `verify-audit` must pass
  after a `kill -9` under load, on both backends, and there is a test for it.

Changed, and stated plainly rather than minimised:

- Up to ~600ms (3 × `wal_writer_delay`) of audit entries can be lost to an OS or
  database-server crash. Measured effect of accepting that: a single-client read
  goes from 16.6ms to 3.7ms p50 on pve01, i.e. from 11.8x to 2.7x slower than
  Vault with its own audit device on (both sides re-measured in the same
  session).

Rejected, with the reasons recorded so the decision does not have to be
re-litigated:

- **SQLite** (superseded by Amendment 7 for read audits only; both reasons
  below still hold for everything else, and Amendment 7 is built around them:
  a dedicated connection rather than the shared pool, and a pragma fixed in
  that connection's DSN rather than flipped per transaction). `PRAGMA synchronous` is per-connection and the pool is shared, so
  the relaxation would be database-wide, not audit-only — a power loss could
  undo a just-committed secret rotation or revocation. And it was not a clean
  latency win: p99 got worse at 10 and 50 clients. The narrower alternative
  (flip the pragma per transaction, restore afterwards) was rejected separately
  for failing open — a skipped restore leaves a pooled connection permanently
  weakened with nothing reporting it.

This is Vault's guarantee, not a safe one, and the hardening guide says so in
those words.

## Amendment 2 (2026-10-10, PROPOSED — needs Andrei's OK): the grace period is a reported state, not a clean one

#2908, decided by Andrei 2026-10-10 to fix after #2454 and #2478. The gap check
above says existing deployments get "a grace period with a start-up warning and
a posture deviation until they comply". For `enable_file_permission_check` only
the start-up warning existed: its `insecure_skip_startup_validation` registry
entry was the boolean `!enable_file_permission_check`, which is false all through
the grace period, so a deployment whose failed startup checks only **warn** was
reported as clean by the §1 start-up warning, the §1 settings-diff audit and the
§2 posture report.

The setting now has four states, the registry entry's settings-diff value:

| State | When | Deviation |
|---|---|---|
| `off` | `enable_file_permission_check: false` written | yes (explicit) |
| `grace-warn-only` | key absent, upgraded deployment (users exist) with no `adr112.file_permission_check.enforced` marker: a failed check only warns | **yes** (shipped default) |
| `enforcing-implicit` | key absent, fresh install or already ratcheted past the grace period | no |
| `enforcing-explicit` | `enable_file_permission_check: true` written | no |

Choices made where neither #2908 nor this ADR was explicit, each the stricter option:

- **Four states, not three.** #2908 names three (off / enforcing implicitly /
  explicitly enabled). The implicit default covers two different behaviours
  since the grace decision moved into the database (fresh installs enforce,
  upgrades warn), so "implicit" is split. Every pair has its own value, so every
  transition (entering or leaving the grace period, writing the key down) is an
  audited settings-diff change. `enforcing-implicit` is not a deviation because
  §4 and the definition of done require zero deviations for the default
  configuration, which is that state.
- **The posture report decides the grace period from the database**, using
  the same facts as the boot. If the database cannot be read, an
  implicit-default deployment is counted as a deviation (cannot be shown to be
  enforcing), not reported as enforcing.
- **The registry warning moves after the grace decision at boot**, and names
  the state (`... is in effect (grace-warn-only)`).
- **Derived fields are swept.** The grace state lives in fields the config file
  cannot set (`yaml:"-"`), which the config-surface sweep skipped. Every such
  field must now be read by a registry entry (`DerivedInputs`) or exempted with a
  reason. `require_mfa`'s two are exempted for now: it has no registry entry at
  all (#2986).

Upgrade note: the settings-diff value of `security.insecure_skip_startup_validation`
changes from `true`/`false` to the state names, so the first boot after upgrade
writes one audit event for it.

## Amendment 3 (2026-10-15): audit durability levels, `standard` by default on PostgreSQL

Accepted by Andrei, 2026-10-15. Supersedes the opt-out shape of Amendment 1
(the mechanism, its scope and its crash argument are unchanged); Amendment 1's
rejection of SQLite stands. Spec: `docs/specs/fast-audit-mode.md`.

### The decision

One setting, `storage.database.audit_durability`, config file only:

| Level | Meaning |
|---|---|
| `strict` | The audit commit waits for the disk sync (the pre-Amendment-3 default). No audit entry is lost to any crash or power loss. |
| `standard` | The audit row is still INSERTed and COMMITted before the secret is returned (audit-before-disclosure unchanged; a failed audit write still fails the request). Only the wait for the disk sync is skipped: `SET LOCAL synchronous_commit = off` on the audit transaction only, exactly Amendment 1's mechanism. A Keyorix process crash loses nothing; an OS crash, power loss or PostgreSQL crash can lose up to ~600 ms (3 × `wal_writer_delay`) of audit entries as a TAIL, never a gap or fork (the WAL-prefix argument in the spec, §5, and `TestFastAuditMode_PostgresCrashLosesOnlyATail`). |

Non-audit writes (secret writes, revocations, rotations) always commit durably
at both levels.

| `storage.type` | Default | Allowed |
|---|---|---|
| `postgres` / `postgresql` | `standard` | `standard`, `strict` |
| `local` / `sqlite` | `strict` | `strict`, `standard` (Amendment 7: read-audit batches only; until Amendment 7, `standard` refused to start) |

### Reporting

`standard` is the PostgreSQL baseline, **not** a posture deviation, and neither
is `strict`. The setting is therefore not an `insecure_` registry entry (§1's
rule applies to settings that weaken security below the baseline; both levels
are the baseline). Instead:

- every start logs one `INFO` line (not `WARNING`) with the effective level and
  its meaning, e.g. `audit durability: standard (PostgreSQL default; committed
  before every disclosure; up to ~600 ms of entries can be lost to an OS crash
  or power loss; set audit_durability: strict to wait for the disk sync)`;
- a level change between two starts is audited by §1's start-to-start settings
  diff (old and new value). The diff records the EFFECTIVE level, so a default
  changing on upgrade is recorded too, not only an edit of the config file;
- `GET /system/info` (`security.audit_durability`) and `admin validate` report
  the effective level; `admin validate --posture` shows it as an informational
  line, so a default PostgreSQL install still reports zero deviations (§4).

Removed with the registry entry: Amendment 1's per-start `WARNING`, its
per-start `admin.audit_durable_sync_skipped_at_startup` audit event (the
settings-diff event replaces both), and the `audit_durable_sync_skipped` /
`audit_durable_sync_skip_not_in_effect_reason` fields of `GET /system/info`.

### Migration

`storage.database.insecure_audit_skip_durable_sync` is a deprecated alias for
one minor release: `true` → `standard`, explicit `false` → `strict`. Both keys
set with conflicting levels refuses to start; the old key logs a deprecation
line at start-up. Existing PostgreSQL installs that set neither key move to
`standard` on upgrade (there are no production customers yet). The release
notes, `docs/UPGRADING.md` and the start-up line say so, with how to stay on
`strict` (`audit_durability: strict`).

### Comparison

Vault's and OpenBao's file audit device writes each entry with one `write()` to
an append-only file and never calls `fsync`: a process crash loses nothing (the
entry is in the OS page cache), but an OS crash or power loss can lose
everything not yet written back, up to ~30 s on Linux's default dirty-page
writeback. `standard`'s window is ~600 ms and `strict`'s is zero; at both
levels the hash chain can lose only a tail.

### Enforcement

Default per backend, SQLite refusal, alias mapping and conflict refusal
(`internal/config/audit_durability_test.go`); config-file-only reachability
(`audit_durability_reachability_test.go`); non-audit writes durable at
`standard` (`TestAuditDurabilityStandard_NonAuditWritesStayDurable`, pg-gated);
the crash test at both levels (`TestFastAuditMode_PostgresCrashLosesOnlyATail`,
`TestAuditDurabilityStrict_PostgresCrashLosesNothing`, manual); the settings-diff
event (`TestSecurityPostureSnapshot_AuditsAuditDurabilityLevelChange`); zero
posture deviations on a default PostgreSQL install
(`TestCollectAuditDurabilityPosture_DefaultPostgresIsNotADeviation`); the INFO
line (`TestLogAuditDurability_StartupInfoLine`); the real binary on PostgreSQL
(`TestAuditDurability_PostgresEndToEnd`) and SQLite
(`TestAuditDurability_SQLiteDefaultBootIsStrict`; the SQLite refusal test was
replaced by `TestAuditDurability_SQLiteStandardBootsEndToEnd` with Amendment 7).

## Amendment 4 (2026-10-15): `insecure_audit_skip_reads`, successful secret reads unaudited

Accepted by Andrei, 2026-10-15. Independent of Amendment 3.

### The decision

1. `storage.database.insecure_audit_skip_reads`, boolean, default **false**,
   config file only. When true, a SUCCESSFUL secret-value read does not write an
   audit row. This covers every path that discloses a value: REST, gRPC,
   connectors/sync/injection, and the CLI through the API. Everything else stays
   audited: secret create/update/delete and version changes;
   permission/role/share/policy changes; authentication events and failures;
   DENIED reads; admin and break-glass actions; configuration and key
   operations.
2. Loud, per §1: the `insecure_` prefix and a registry entry; a `WARNING` at
   every start ("secret reads are NOT audited"); an
   `admin.audit_reads_skipped_at_startup` audit event at every start; a
   start-to-start settings-diff event when the value changes; a posture
   deviation in `admin validate`; a flag in `GET /system/info`; a persistent
   web UI banner.
3. Refusal hook: a compliance profile setting refuses this setting, if one
   exists or whenever one is added. Denied reads are always audited.
4. Independent of `audit_durability`: that level governs every row that is
   still written.

### How it is implemented

- **Where the skip happens.** It is in `internal/core/audit_skip_reads.go`, at
  the three audit-emit choke points every core audit write passes through
  (`emitAudit`, `emitAuditOn` and `emitAuditWithAccessLog`;
  `TestDirectLogAuditEventCallersAreSafe` keeps it that way). The check runs
  before any storage call, so a skipped read opens no database transaction and
  takes no audit-chain lock. That also holds under `single_writer`: a skipped
  read never reaches the write path.
- **What it skips.** Exactly two event types, and only with `Success=true`:
  - `secret.read`: every native value read through
    `LogSecretReadWithProject`. That is REST `GET /secrets/{id}?include_value=true`
    and `/secrets/value`, gRPC `GetSecretValue`, render, and the source read of
    a copy, environment copy or environment clone. The CLI, k8s sync, MCP and
    the operator all read through these routes.
  - `connect.secret_read`: a federated read through a connector.

  The atomic `secret_access_logs` row written with `secret.read` is skipped
  too. Writing it would need a transaction, and it is part of the same read
  record.
- **What it does not skip:**
  - `secret.metadata_read` and `secret.versions_listed`: no value is disclosed.
  - `dynamic_lease.issued`: this mints a credential, so it is a create.
  - `share_access_elevated`: it records that access came through a share.
  - `secret.certificate_inspected`: it covers public metadata only.
  - Every event with `Success=false`.
  - Every event written outside core: `server/admin`, `internal/encryption`,
    and the start-up events in `server/main.go`.
- **Denied reads stay audited, so probing still leaves a trace** (#3273). At
  both settings, every refused value read writes an audit row with
  `Success=false`:
  - Federated reads: the six `connect.secret_read` deny paths.
  - Native reads: a `secret.read` row with a `reason=` class and
    `outcome=denied`. This covers REST `GET /secrets/{id}?include_value=true`
    and `/secrets/value`, render, copy, environment copy and clone, and gRPC
    `GetSecretValue`. The reason classes are `forbidden`, `not_found`,
    `outside_schedule`, `expired`, `suspended`, `max_reads_exhausted`,
    `classification_gate` and `mfa_required`. A read that breaks
    (`internal_error`) is recorded with `outcome=failed`.

  How it works (`internal/core/secret_read_denial.go`):
  - **Who records it.** Each value route carries
    `middleware.AuditSecretValueReadDenials` as its outermost middleware. The
    gRPC method opens a `SecretReadDenialNote`. Whatever refuses the read (the
    route gate, the gRPC authorization helper, or a core value-read entry
    point) notes the reason, and the transport records one row. Render and copy
    run inside core, so they record their own refusals.
  - **No existence oracle.** The caller gets the same response for "does not
    exist" and "exists but forbidden". A `forbidden` or `not_found` row has no
    `SecretNodeID` and no `ProjectID`, and its description names only what the
    caller supplied. So a caller's own dashboard activity and a
    project-filtered view cannot tell the two apart. The internal truth is in
    the `reason=` token and in `Diff` (resolved secret and project), which only
    `audit.read` holders see. A refusal after authorization (expired,
    suspended, ...) names the secret, because the response already does.
  - **Flood protection.** Rows are aggregated per (principal, reason, path,
    target). The first refusal of a key is written immediately. Later ones in
    the next 60 s are only counted, and one summary row with the count is
    written when the window closes. So a key costs at most two rows per
    window. A principal has at most 50 live keys; further targets fold into one
    overflow key per reason. The aggregator holds at most 10,000 keys. Counts
    of windows still open are lost on a restart; first rows are never lost.
  - **Fail-closed semantics unchanged.** The row is best-effort. A failed write
    is logged (`SECURITY: refused secret read NOT recorded ...`) and the
    refusal stands. It runs only on the denial path: a successful read pays one
    context value and a status capture, and touches no lock and no storage.
  - **Consumers.** Read counts that must mean disclosures (dashboard reads,
    top readers, billing machine reads, access-review activity) now count only
    `success = true` (or legacy NULL) rows. Usage and billing reads already did.

  Max reads is enforced by a counter on the secret, not by audit rows, so it is
  unaffected.
- **What operators lose.** Read history, read counts, `total_reads`, usage and
  billing read counts, the access-log export and anomaly detection all key on
  `secret.read` and access-log `read` rows. None of them see reads while the
  setting is on. The WARNING and the hardening guide say so.
- **Compliance profile.** No compliance profile setting exists yet.
  `config.complianceProfileGates` is the hook: `Validate` refuses
  `insecure_audit_skip_reads` while any registered profile is active.
  `TestInsecureAuditSkipReads_ComplianceProfileKeyIsGated` fails if a
  compliance-profile-looking key is added to Config without registering it
  there.

### Enforcement

| Claim | Test |
|---|---|
| default false | `TestInsecureAuditSkipReads_DefaultFalse` |
| registry entry | `TestInsecureAuditSkipReads_RegistryEntry`, plus the registry sweep |
| config file only | `TestInsecureAuditSkipReads_NoWriteAssignment`, `_NotSettableFromTheEnvironment`, `_ReferencesAreAllowlisted` |
| compliance profile refusal | `TestInsecureAuditSkipReads_RefusedByAnActiveComplianceProfile`, `_ComplianceProfileKeyIsGated` |
| a successful read writes nothing and opens no transaction | `TestInsecureAuditSkipReads_SuccessfulReadWritesNothingAndOpensNoTransaction` |
| a denied read is still audited | `TestInsecureAuditSkipReads_DeniedReadIsStillAudited` |
| every refused native value read is audited, per path and reason class, at both settings | `TestSecretValueReadDenials_StateRefusalsAuditedOnEveryRoute`, `TestSecretValueReadDenials_ForbiddenAndNotFoundAuditedWithoutAnOracle`, `TestSecretValueReadDenials_MFARequiredAudited`, `TestSecretReadDenial_RenderRefusalsAudited`, `TestSecretReadDenial_WrittenAtBothSkipReadsSettings` |
| every value route and RPC carries the denial audit hook | `TestValueReadRoutes_AuditTheirRefusals` |
| a refusal burst is aggregated: first row immediate, rows bounded, count correct | `TestSecretReadDenial_BurstIsAggregatedFirstImmediateCountCorrect`, `_WindowTimerWritesSummary`, `_DistinctTargetFloodIsBoundedPerPrincipal`, `_GlobalKeyCap` |
| no existence oracle in the row | `TestSecretReadDenial_ForbiddenAndNotFoundRowsAreNotAnOracle` |
| an audit-write failure keeps the refusal | `TestSecretReadDenial_AuditWriteFailureKeepsTheRefusal` |
| one subtest per still-audited event class | `TestInsecureAuditSkipReads_EveryOtherEventClassStillAudited` |
| the skip set is exactly the two value-read types | `TestInsecureAuditSkipReads_SkipSetIsExactlyTheSuccessfulValueReads` |
| REST, through the real router, at both settings | `TestInsecureAuditSkipReads_RESTValueReadsUnauditedWritesAudited` |
| gRPC | `TestSecretService_GetSecretValue_InsecureAuditSkipReads` |
| `/system/info` | `TestMakeSystemInfoHandler_ReportsAuditReadsSkipped` |
| `admin validate` | `TestAppendAuditSkipReadsPosture` |
| the real binary | `TestInsecureAuditSkipReads_EndToEnd`: every-start WARNING and event over two starts, the settings diff, `validate` and `validate --posture`, a chain that verifies, and the default install showing none of it |

With the setting off, behaviour is unchanged. The existing
audit-before-disclosure tests are untouched and still pass.

## Amendment 5 (2026-10-17): when the `require_mfa` upgrade grace period ends

#2923, decided by Andrei 2026-10-17. The gap check gave upgraded deployments
"a grace period with a start-up warning and a posture deviation until they
comply" but named no compliance condition, so a deployment that never set
`security.require_mfa` stayed unenforced forever.

### The decision

1. **The grace period ends at the first administrator MFA enrolment, with a
   hard stop 30 days after the upgrade that introduced it, whichever comes
   first.** "Administrator" is a global admin-tier holder (an admin-bypass
   role, directly or through a group); a TOTP factor or a passkey counts. An
   administrator who already had a second factor before the upgrade ends it at
   the first check.
2. **During the grace period** users without a second factor sign in normally.
   Every page of the web UI shows a persistent banner with the days left
   (login and profile responses carry `mfa_grace {ends_at, days_left}`),
   `keyorix login` prints the same on stderr, and the server logs a WARN line
   with the days left at boot, once a day and at each such sign-in.
3. **After it** they are sent to MFA enrolment when they sign in, exactly as on
   a fresh install: confined to the enrolment endpoints, never locked out.
   PAT and machine credentials are unaffected. Break-glass rules are
   unchanged. The end needs no restart: every MFA gate (session issuance, the
   HTTP setup gate, gRPC) reads the requirement per request.
4. **The start is stored durably, never derived from the clock alone.** The
   first boot on the version that introduced the bound writes
   `adr112.require_mfa.grace_started` to `system_metadata`; later boots keep
   it. The grace clock's high-water mark (`adr112.require_mfa.grace_clock`) is
   written at boot and every minute while the period runs, and the clock never
   reads earlier than it, nor than boot time plus the monotonic time since
   boot. **A clock set back does not extend the grace period**; a clock set
   forward only ends it sooner.
5. **Fail closed.** A start or clock value that cannot be written or parsed
   means no grace period (MFA enforced). A check that cannot read the
   administrator set or the marker enforces MFA until the next check. Once
   ended, the `adr112.require_mfa.enforced` marker is written and the grace
   period never returns.
6. **Posture.** `admin validate --posture` keeps reporting the grace period as
   a shipped-default deviation, now with its end date and days left, until it
   ends.

Enforced by `internal/core/mfa_upgrade_grace_test.go`
(`TestMFAUpgradeGrace_*`, SQLite and PostgreSQL), `server/adr112_mfa_grace_test.go`
(`TestADR112MFAGrace_*`, SQLite and PostgreSQL), `server/http/account_setup_mfa_grace_test.go`,
`server/grpc/interceptors/auth_mfa_grace_test.go` and the real-backend journey
`web/e2e/real/mfa-upgrade-grace.spec.ts`.

## Consequences

- The baseline becomes part of the product's documentation and sales material: "here is the secure configuration, and here is how you prove you're running it."
- Some existing settings may need renaming to the `insecure_` form, with a migration note and a deprecation period for the old names.
- Every new feature carries a small extra cost: its defaults must meet the baseline, and any weaker option needs the opt-out plumbing.
- Some items (non-dumpable process, memory wiping) are best-effort in Go and are documented as such, not overclaimed.

## Open questions

1. Posture report: a new `admin posture` command, or extend `admin validate`? Proposal: extend `validate` with a `--posture` mode (the gap check found `admin validate` and `keyorix compliance report` already provide most of the foundation).
2. ~~TLS 1.2 default~~ Decided 2026-10-02: TLS 1.2 stays allowed by default with modern ciphers only; TLS 1.3-only is a strict-mode setting.
3. ~~Admin MFA by default on fresh installs: also enforced on upgrades of existing deployments, with a grace period?~~ Decided 2026-10-17 (#2923, Amendment 5): yes; the grace period ends at the first administrator MFA enrolment or 30 days after the upgrade, whichever comes first.
4. Shamir split of the recovery key: default or optional? Proposal: optional, recommended in the hardening guide.
5. Approval workflows (dual control on secret reads): include in the AGPL core as a differentiator, or make it a third gated feature? Today exactly two features are gated (`airgap_updates`, billing); either choice changes the licensing story. Decide before the feature is built.

## Decisions recorded (2026-10-02)

- Break-glass remains single-person, with mandatory alert, audit event and post-activation review. Two-person break-glass is rejected: an emergency path that needs a second person fails exactly when it's needed.
- TLS 1.2 remains allowed with forward-secret AEAD suites; TLS 1.3-only is available as strict mode.
- Approval workflows are deferred to a separate feature; licensing is open question 5.

## Decisions recorded (2026-10-05)

- Audit-before-disclosure stays the default. One named `insecure_` opt-out
  (`storage.database.insecure_audit_skip_durable_sync`) is added for deployments
  with guaranteed power, giving Vault-equivalent semantics and Vault-equivalent
  speed. See Amendment 1.
- **The opt-out is PostgreSQL only.** A SQLite backend that sets it refuses to
  start, with a named error — not a silent ignore. SQLite was rejected because
  `PRAGMA synchronous` is per-connection and the pool is shared, so the
  relaxation would cover every table (a power loss could undo a just-committed
  secret rotation, not merely lose audit entries), and because the measured p99
  got *worse* under concurrency anyway (328.8→518.0 ms at 10 clients,
  703.7→919.0 ms at 50).
- **A configured setting that cannot take effect is reported as off, with the
  reason, as a structured field** — not as a weakening, and not only in log
  text. One start-up warning still prints, worded as "ignored".

## Amendment 6 (2026-10-18): break-glass during an audit-subsystem incident

Decision (Andrei, 2026-10-16): break-glass must work during an audit-subsystem
incident without ever being unrecorded. #3367 (AUDIT-TX-2) had made an activation
fail closed when its audit rows could not be written: correct for "never
unrecorded", wrong for "works in a real emergency", which §3 above also requires
("Break-glass stays single-person, so it works in a real emergency"). An incident
can be the audit subsystem itself, or someone making it refuse writes on purpose.

What changes, and only for break-glass activation (every other grant stays fail
closed, and revocations stay never-blocked):

- **Normal path unchanged.** The grant and its `role.assigned` and
  `break_glass.activated` rows commit in one transaction.
- **Degraded path.** When that transaction fails ONLY because the audit append
  failed (an error, a panic, or the chain lock not coming within the write path's
  10 s bound), a second transaction commits the activation, the grant and a
  `pending_audit_events` record of each of those rows (#3345's owed-audit table),
  built by the same writers. Never one without the other. If that transaction fails
  too, the activation is refused (`BreakGlassUnrecordable`, HTTP 503 / gRPC
  Unavailable) with a pointer to the offline `recover-admin` procedure: the
  database itself is broken, and the rule "never unrecorded" wins over availability
  at that point.
- **Short, loud, reviewed.** A degraded activation expires after
  `break_glass.degraded_ttl` (default 15 min, never longer than the same request's
  normal lifetime). It is logged at ERROR, counted
  (`keyorix_breakglass_degraded_activations_total`), notified to the project's
  admins, shown to system.write callers (system info and a web banner), and listed
  for review at once: its post-activation review is mandatory with no grace window.
  Like every review requirement here it reports, it does not lock anyone out.
- **Backfill.** #3345's backfill writes the owed rows into the hash chain in the
  order they were owed with their ORIGINAL event times (the chain is ordered by id,
  not time; the verifier accepts non-monotonic times), exactly once, and marks the
  activation settled (`audit_settled_at`) in the same transaction as its last row.
  `verify-audit` reports unsettled degraded activations and is INDETERMINATE while
  any exist. Retention never purges an unsettled one.

Why not keep fail-closed: an emergency path that an audit outage disables fails
exactly when it is needed, the same reasoning that keeps break-glass
single-person. Why not commit best-effort and audit later (the revocation shape):
the elevation would then exist with no durable record if the process died before
the late write. The owed record in the same transaction closes that gap.

Machine-checked by `internal/core/break_glass_degraded_test.go` (the append-error,
effect-then-error, panic, chain-lock and crash matrix plus an attacker-shaped test,
SQLite and PostgreSQL), `break_glass_lock_guard_test.go` (both paths stay inside
the revoke lock, the degraded path is reachable only from there) and
`internal/auditverify/owed_break_glass_test.go`. Operators:
`docs/operator/break-glass-runbook.md`.

## Amendment 7 (2026-10-18): SQLite `standard`, read audits on a dedicated `synchronous=NORMAL` connection

Decided by Andrei, 2026-10-18 (R1.8, PERF-LOWCONC-1 option c). Narrows
Amendment 1's rejection of SQLite and replaces Amendment 3's SQLite row.
Option (a), a single-writer SQLite mode, is not the default and is not part of
this amendment.

### The rule

On SQLite, `storage.database.audit_durability` accepts `standard`. The default
stays `strict`: an install that does not set the key runs exactly as before,
with no second connection opened.

At `standard` the server opens **one dedicated connection** to the same
database file, with `_synchronous=NORMAL` in its DSN. It is a separate
connection pool of size one, never the shared pool, and its pragma is fixed when
it opens; it is never flipped per transaction. The audit flusher commits a batch
on it **only when every row in the batch is a successful secret-value read
audit**: `Success=true` and an event type in the set Amendment 4 skips
(`secret.read`, `connect.secret_read`). Every other transaction stays on the
shared `synchronous=FULL` pool:

- every secret mutation, revocation, rotation, role, share or policy change,
  and every other non-audit write;
- every audit row of a mutation, including the audit-before-disclosure row of a
  mutation that returns a value;
- denied and failed reads (`Success=false`), metadata reads, version listings;
- a batch that mixes read audits with any other row: the whole batch commits
  on FULL. Rows are never reordered or split out to reach the NORMAL
  connection, because chain order is batch order;
- audit rows written inside a caller's transaction (the direct path), signed
  checkpoints, retention purges and re-anchors, the encoding migration.

Audit-before-disclosure is unchanged for reads too: the read's audit row is
INSERTed and COMMITted, and the commit has returned, before the value is
returned; a failed audit write still fails the read. Only the wait for the
disk sync is skipped, as on PostgreSQL.

### Why the chain stays contiguous: one WAL, one write lock

The argument is the WAL-prefix argument Amendment 1 uses for PostgreSQL,
applied to SQLite's WAL:

1. **One writer, one order.** Every audit append reads the chain head
   (`id DESC`) and inserts its rows inside one `BEGIN IMMEDIATE` transaction
   (`commitBatchAttemptTx`, `logAuditEventDirect`). SQLite has one write lock
   per database, not per connection, so at most one of the two connections can
   be inside a write transaction at a time, and a write transaction in WAL mode
   always reads the latest committed state. Both connections also pass the same
   in-process FIFO write gate. So the head a batch reads is the last row
   committed by either connection, and chain order equals commit order. SQLite
   has no client-side head cache (the one-flight cache is PostgreSQL-only).
2. **One log, appended in commit order.** Both connections write to the same
   `-wal` file. A commit appends its frames after those of every earlier
   commit, whichever connection made it. NORMAL writes the frames and returns
   without an fsync; FULL fsyncs the WAL file before returning. An fsync acts on
   the file, so a FULL commit makes every byte before its own frames durable,
   including the frames of every NORMAL batch committed before it. A checkpoint
   also syncs the WAL first.
3. **Recovery accepts only a prefix.** WAL frames carry cumulative checksums
   and the header's salt. After a crash, recovery replays frames up to the last
   valid commit frame and discards everything after it, so the recovered
   database is the state after some prefix of the commits. SQLite documents that
   WAL with `synchronous=NORMAL` stays consistent across a power loss and only
   loses recent commits.

From 1 to 3: a surviving row's `prev_hash` always points at a row that also
survived, because that row was committed earlier, so its frames come earlier
in the same log.

**The failing cases this rule prevents**, each of which would break
`verify-audit`:

- *Gap (the inversion).* NORMAL batch N commits read rows r1..r3 and a FULL
  batch M then commits m1 with `prev_hash = r3`. If r3 could be lost while m1
  survives, m1's link would name a missing row. It cannot happen: m1's fsync
  covers r3's frames, which come earlier in the same `-wal` file. It would
  happen if read audits went to a different file (a second database or an
  attached one) with its own log. That is why the dedicated connection opens
  the same file, and why a separate audit database is not an alternative.
- *Fork.* N and M both read head h and both insert a row with
  `prev_hash = h`. That needs a head read outside the write lock: a head
  cached across connections, or read in a DEFERRED transaction that upgrades
  later. Neither exists on SQLite: the head read is the first statement after
  `BEGIN IMMEDIATE` on whichever connection commits.
- *A lost mutation.* A revocation committed on a NORMAL connection could be
  undone by a power loss (Amendment 1's first reason). The classifier sends
  only batches of successful read audits to that connection, the shared pool
  stays FULL, and a test checks `PRAGMA synchronous` per connection for both.
- *A weakened pooled connection.* Amendment 1's second reason (a per-transaction
  pragma flip whose restore is skipped). There is no flip: each connection's
  pragma is fixed in its DSN for its whole life.

### What a crash can lose

| Event | `strict` | SQLite `standard` |
|---|---|---|
| Keyorix process crash (`kill -9`, panic, OOM kill) | nothing | **nothing**: a NORMAL commit has written its frames into the OS page cache before it returns, and the next open recovers them from the WAL |
| OS crash or power loss | nothing | a **tail** of read-audit rows (and their `secret_access_logs` rows) committed on the NORMAL connection after the last WAL sync; never a gap or a fork in the chain, never a committed mutation, never a mutation's audit row |

The last WAL sync is the most recent FULL commit on the database (any write,
any non-read audit batch) or checkpoint. Unlike PostgreSQL's WAL writer
(Amendment 3's ~600 ms), **SQLite has no background flush, so no timer bounds
the window**. On a read-only workload it lasts until the next write or
checkpoint, or until the OS writes the dirty pages back on its own, which has
no timing guarantee. The start-up INFO line and `admin validate` state this for
SQLite rather than repeating PostgreSQL's figure.

An external monitor that recorded a head from `verify-audit` inside a lost tail
sees the recovered chain end before that head. That is tail truncation, and it
is reported as such: the loss is visible, not silent. A signed checkpoint is
committed on FULL, so it can only certify rows that its own fsync made durable.

**Proof status.** The process-crash row and the chain argument are machine
checked (below). The OS-crash and power-loss rows rest on the WAL-prefix
argument above and SQLite's documented guarantee. They are **pending e2e VM
(dm-flakey)**: no test on this repository's development host can cut power
under the database, and nothing here claims more than that argument supports.

### Reporting

The same as Amendment 3 for PostgreSQL: `standard` is a baseline level, not a
posture deviation, and not an `insecure_` registry entry. A level change is
audited by the settings diff. The start-up INFO line, `admin validate` and
`GET /system/info` report the effective level, with the SQLite meaning when the
backend is SQLite.

### Enforcement

- `TestSQLiteReadAuditConn_PragmaPerConnection`: the shared pool reports
  `PRAGMA synchronous` = 2 (FULL) on every connection and the dedicated
  connection 1 (NORMAL); at `strict` no dedicated connection exists.
- `TestSQLiteReadAuditConn_OnlyReadBatchesUseNormal`: a mutation, a mutation's
  audit row, a denied read and a mixed batch commit on FULL; a batch of
  successful read audits commits on NORMAL.
- `TestSQLiteReadAuditConn_InterleavedChainVerifies`: concurrent read audits
  (NORMAL) and mutations with their audit rows (FULL) interleave and the chain
  verifies.
- The kill -9 drill (`scripts/drills`, native, SQLite, `standard`): nothing
  acknowledged is lost and `verify-audit` is VALID.
- Config: SQLite accepts `standard`, the default stays `strict`
  (`internal/config/audit_durability_test.go`).
- Invariant: `internal/storage/INVARIANTS.d/INV-STORAGE-sqlite-normal-conn-read-audit-only.md`.

## Amendment 8 (2026-11-25): bounded sync window for `standard`, and a UPS-assisted switch to `strict`

**Proposed, pending Andrei's OK.** Design only; nothing is implemented. Builds on
Amendment 3 (`audit_durability`) and Amendment 7 (SQLite `standard`). It does not
change the default of either backend and does not relax `strict`.

### Origin

Andrei's idea, 2026-11-25: where a site or datacentre has a UPS that holds for a
few minutes, audit could be written to disk in series instead of one event at a
time, and throughput would rise. The idea was checked against this ADR:

- `standard` already skips the wait for the disk sync, so the speed gain is already
  taken (PostgreSQL single client 4.11 ms to 1.84 ms, Amendment 3). A longer batch
  delay would not help a lone request: it has nobody to batch with and would only
  wait.
- What a UPS can add is **safety for `standard`**, not speed: a signal that power
  is about to fail lets the server close the loss window that `standard` leaves
  open. That is what this amendment specifies.

Evidence level: one idea from Andrei, plus an evaluator's remark that power loss
is a minor matter in a datacentre (datacentres go down in batches). No customer has
asked for it. It is cheap, and it removes the main objection to running `standard`.

### The problem it addresses

At `standard`, an OS crash or power loss can lose a tail of read-audit rows. On
PostgreSQL that tail is bounded (about 600 ms, Amendment 3). On SQLite it is not:
Amendment 7 states that SQLite has no background flush, so on a read-only
workload the window lasts until the next write, a checkpoint, or an OS writeback
with no timing guarantee.

### Decision 1: a bounded sync window on SQLite `standard`

At `standard` on SQLite, a background task makes pending `synchronous=NORMAL`
commits durable at most every `audit_sync_interval` (proposed default 500 ms, in
line with PostgreSQL's window). It acts only when there are commits not yet
synced, so an idle database does no work. Because an fsync acts on the file,
syncing the `-wal` file makes every earlier frame durable in commit order; it
cannot reorder rows or create a gap or a fork (the WAL-prefix argument of
Amendment 7). The exact mechanism (fsync of the `-wal` file, or a passive
checkpoint) is an implementation choice, constrained by that argument.

This is useful with or without a UPS, and it gives SQLite `standard` a stated
loss window like PostgreSQL's.

### Decision 2: a power-state signal that switches audit to `strict` temporarily

A new admin operation (name to settle; sketched here as `audit-power`) accepts two
states:

- **on-battery:** the server (a) makes all pending audit rows durable now, then
  (b) runs every audit commit at `strict` until the next state change, on both
  backends. On PostgreSQL that means audit commits stop using
  `synchronous_commit = off`; on SQLite the dedicated NORMAL connection is not
  used.
- **on-mains:** the server returns to the configured level. It can never go below
  the configured level, so this signal cannot weaken anything.

Rules:

1. **Only meaningful at `standard`.** At `strict` the operation reports that there
   is nothing to change.
2. **Fail-safe direction.** `on-battery` moves toward stricter; a restart returns
   to the configured level. A missing `on-mains` leaves the server at `strict`,
   which costs speed only.
3. **Authenticated and local.** The operation needs an admin credential and is
   reachable on the local interface used by host scripts; it is not an anonymous
   endpoint. A caller who can send `on-battery` can only slow the server down.
4. **Audited.** Each transition writes an `admin.audit_power_state_changed` event
   with old and new state, so the chain records when the server ran in which mode.
5. **Reported.** `GET /system/info` and `admin validate` show the configured level
   and, while active, the current override.
6. **No UPS logic in Keyorix.** Monitoring the UPS is the host's job (NUT or
   `apcupsd`). Keyorix provides the hook and the documentation gives an example
   script for the UPS daemon's on-battery and on-mains events.

### What this does not cover

State this plainly in the documentation, because it is the difference between
`strict` and `standard` plus a UPS:

- A kernel panic, an OS crash, a hard reset, or a UPS that fails or never sends
  the signal.
- A battery that runs out before the flush completes.
- An attacker with physical access who cuts power at the UPS or removes it. At
  unattended remote sites where this threat matters (Amendment 3, point 4),
  `strict` stays the right level and this amendment is not a reason to relax it.
- A process crash is not a new risk: rows are committed to the WAL before every
  disclosure, as today.

The guarantee is therefore stated as "`standard` with a bounded loss window,
and no loss on a signalled power failure with a working UPS", never as
"equivalent to `strict`". The posture report does not call it hardened.

### Alternatives considered

- **Buffer audit in process memory beyond the WAL, flush when power fails.**
  Rejected: a process crash would lose records of secrets already disclosed, which
  breaks audit-before-disclosure.
- **A longer group-commit delay.** Rejected: no gain for a lone request, extra
  latency for every request.
- **Trust the UPS implicitly, no signal.** Rejected: nothing would tell the server
  when to flush.
- **Make this a new durability level.** Rejected for now: it is a temporary
  override of `standard`, not a third baseline level, so the posture model stays
  with two levels.

### Enforcement (to write with the implementation)

- A test that on SQLite `standard` pending NORMAL commits are made durable within
  `audit_sync_interval`, and that an idle database does no sync work.
- A test that `on-battery` makes pending rows durable and moves all audit commits
  to `strict` on both backends, and that `on-mains` restores the configured level
  but never goes below it.
- A test that the operation is refused without an admin credential and reports
  "nothing to change" at `strict`.
- The `verify-audit` chain test after `kill -9` under load at `standard`, with
  and without the sync task, stays VALID.
- Power-loss behaviour stays "pending e2e VM (dm-flakey)", as in Amendment 7: no
  claim beyond the WAL-prefix argument is made without that test.

### Open questions

1. Name and surface of the operation (CLI command, admin API, local socket), and
   how a containerised server receives the host's signal.
2. Default `audit_sync_interval`, and whether it is configurable.
3. What happens to requests in flight at the moment of the switch to `strict`.
4. Whether a UPS-assisted site may advertise a stronger posture line than plain
   `standard`, and in what words.

## Decisions recorded (2026-10-15)

- Audit durability is two baseline levels, `storage.database.audit_durability:
  strict | standard`, not an `insecure_` opt-out. `standard` is the PostgreSQL
  default; SQLite runs `strict` only. Neither level is a posture deviation; a
  level change is audited by the settings diff. See Amendment 3.
- `storage.database.insecure_audit_skip_reads` (Amendment 4): a boolean
  `insecure_` opt-out, default false. It stops audit rows for successful
  secret-value reads only; denied reads and every other event stay audited. A
  compliance profile refuses it. It is independent of `audit_durability`.
- Refused native value reads are audited at both settings (#3273): a
  `secret.read` with `Success=false` and a reason class, aggregated per
  principal, reason, path and target (first row immediate, then one summary
  per 60 s window), and best-effort (a refusal stays a refusal if its row
  cannot be written).

## Decisions recorded (2026-10-17)

- ADR-112 is Accepted (Andrei, 2026-10-17).
- The `require_mfa` upgrade grace period ends at the first administrator MFA
  enrolment or 30 days after the upgrade, whichever comes first; its start is
  stored durably and a backward clock step cannot extend it. See Amendment 5.

## Decisions recorded (2026-10-18)

- SQLite `standard` (Amendment 7, option c of R1.8 / PERF-LOWCONC-1): one
  dedicated `synchronous=NORMAL` connection, used only for batches of
  successful secret-value read audits. Mutations and mutation audits stay
  FULL. `strict` stays the SQLite default. A single-writer SQLite mode
  (option a) is not the default.

## Definition of done

- The gap check is recorded, and every baseline item is either present with a test or scheduled.
- `insecure_` naming, start-up warnings and audit events are enforced by a test over all config keys.
- The posture report exists and reports zero deviations on a default install.
- The hardening guide in `docs/` lists the baseline, the posture command and every `insecure_` setting.
