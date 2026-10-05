# Spec: opt-in fast audit mode (`database.insecure_audit_skip_durable_sync`)

Status: **Proposed** (2026-10-05). Needs Andrei's decision on the two items marked
**NEEDS ANDREI** below before the implementation PR is merged.

Amends: ADR-112 (secure-by-default baseline) — two baseline bullets, see
`docs/adr-112-secure-by-default-baseline.md` §3 "Secrets and audit".
Related: ADR-029 (audit hash chain), ADR-115 (local append-only audit journal —
a **different** mechanism, not this one), #2403/#2420 (audit group commit).

## 1. Why

PERF-2 measured Keyorix at ~10x Vault's latency for a single-client secret read
on pve01 (keyorix-pg W1 c=1: 71.8 rps / 8.36ms p50, vs vault-on with its own file
audit device enabled: 715.9 rps / 1.30ms p50). PERF-2's H1 is confirmed: at c=1
there is nothing for the group-commit flusher to batch, so essentially the whole
8.36ms *is* one durable Postgres commit, and the independently measured
`fdatasync` floor on that disk is 9.326ms. The read path cannot go faster than
one disk sync as long as it waits for one.

A source-verified survey of how competitors get their numbers
(`~/proj/prompts/reports/2026-10-05-competitor-audit-write-paths.md`) found that
**none of them fsync audit before answering**:

| Product | Audit write path | Durable before the response? |
|---|---|---|
| HashiCorp Vault | one `write()` per entry to an `O_APPEND` file, no `fsync` anywhere | No — OS page cache only |
| OpenBao | same design (fork) | No |
| CyberArk Conjur | Ruby `Logger` over a UNIX socket to syslog | No (fire-and-forget) |
| Infisical | Redis `XADD`, background batch insert, request-path errors swallowed | No, and may drop events |
| Keyorix today | audit row committed durably before the secret is returned | **Yes** |

Keyorix's default is strictly stronger than every one of them, and that stays the
default. This spec adds an explicit, loud, audited opt-out so an operator whose
power is genuinely guaranteed (UPS, battery-backed RAID write cache, replicated
cloud block storage) can choose Vault's guarantee and Vault's speed.

## 2. User journey

1. An operator reads the hardening guide's "Fast audit mode" section, which states
   plainly what is given up.
2. They add `insecure_audit_skip_durable_sync: true` under `storage.database` in
   the server's config file and restart. There is no API, CLI flag, or environment
   variable that can turn it on.
3. Every subsequent start prints a `WARNING:` line naming the setting and what it
   weakens, and writes an audit event into the hash chain itself.
4. `keyorix-server admin validate` lists it as a posture deviation.
5. `GET /system/info` reports `security.audit_durable_sync_skipped: true`, so a
   buyer's auditor can see the deviation over the API without host access.
6. To turn it off they remove the line and restart. The next start's audit event
   is absent and the warning stops; the chain carries the dated record of the
   window during which the mode was on.

## 3. The setting

| | |
|---|---|
| Canonical name | `storage.database.insecure_audit_skip_durable_sync` |
| YAML path | `storage` → `database` → `insecure_audit_skip_durable_sync` |
| Go field | `config.DatabaseConfig.InsecureAuditSkipDurableSync bool` |
| Type / default | `bool`, **`false`** |
| Settable from | the config file only |
| NOT settable from | any HTTP handler, any gRPC RPC, any environment variable, any CLI flag |
| ADR-112 registry entry | `storage.database.insecure_audit_skip_durable_sync`, `DeprecatedAlias: ""` (ships compliant) |

Name: the leaf key carries the `insecure_` prefix, which is ADR-112 §1's rule as
the registry implements it (`InsecureSetting.Name` is a dotted path whose leaf is
prefixed — e.g. `security.recover_admin.insecure_keyless_admin_recovery`). It
lives under `storage.database` and not under `audit` because the thing it changes
is the *commit durability of the database transaction* the audit chain is written
in, which is also why its blast radius differs per backend (§6).

## 4. Required semantics

These are the acceptance criteria for the implementation. Each one names the test
that holds it.

**S1 — Still fails closed on a write failure.** If the audit row cannot be
WRITTEN, the request fails exactly as it does today. The only thing removed is
the wait for the disk sync. Concretely: `logAuditEvent` and every caller keep
returning the commit's error unchanged; nothing is swallowed, nothing becomes
best-effort.
*Test:* `TestFastAuditMode_StillFailsClosedOnWriteFailure` — a storage whose
audit insert is forced to fail must still make `GetSecret` fail with the mode on.

**S2 — Same order, same code path.** The audit row is INSERTed and its
transaction COMMITted, in the same transaction/batch as today, before the secret
value is returned. No queue, no background writer, no deferred write is
introduced. A Keyorix **process** crash therefore loses nothing on SQLite (the
frames are already in the OS page cache) — see §6 for the Postgres nuance.
*Test:* `TestFastAuditMode_DoesNotChangeWriteOrdering` — the audit row is
readable from a second connection before the handler's response is written, with
the mode on.

**S3 — The hash chain is never corrupted or forked.** Losing a tail of entries is
permitted in this mode. A broken chain, a gap in the middle, or two rows claiming
the same `prev_hash` is not. `verify-audit` must pass after a simulated crash.
*Test:* `TestFastAuditMode_ChainVerifiesAfterKill9` (SQLite and Postgres) — load
traffic, `kill -9` the server, restart, `VerifyAuditChain` reports valid.
See §5 for why this holds rather than being hoped for.

**S4 — Default off, and not remotely flippable.** With no setting present the
sync wait still happens: the SQLite DSN still says `_synchronous=FULL` and the
Postgres audit transaction issues no `SET LOCAL synchronous_commit`.
*Tests:* `TestSQLitePragmas_EnabledOnFreshConnection` (unchanged: asserts
`PRAGMA synchronous` = 2 on the default config),
`TestFastAuditMode_DefaultIsDurableSync`,
`TestInsecureAuditSkipDurableSync_NotReachableFromAnyTransport` (the grep-based
reachability guard, modelled on `keyless_mode_reachability_test.go`).

**S5 — Loud and audited.** Every start with the mode on prints a `WARNING:` line
naming the setting, and writes one `admin.audit_durable_sync_skipped_at_startup`
audit event with `ActorType = system`. Both repeat on every boot, not just the
first — the same treatment `keyless_mode` gets, and for the same reason: an
auditor reading the chain should not have to trust a point-in-time config dump.
*Test:* `TestFastAuditMode_WarnsAndAuditsAtEveryStartup`.

**S6 — Visible in the posture surface and over the API.**
`keyorix-server admin validate` lists it among its warnings;
`GET /system/info` reports it as a boolean in `security`.
*Tests:* `TestValidateStartup_WarnsOnAuditDurableSyncSkipped`,
`TestSystemInfo_ReportsAuditDurableSyncSkipped`.

### Error and concurrency cases

- **The audit insert fails mid-batch.** Unchanged. `commitAuditBatch`'s bisection
  still isolates a poisoned item; every surviving item still gets full chain
  linkage, and the failing item's caller still gets a non-nil error. The
  durability setting is orthogonal to this path.
- **A second request lands between the audit commit and the HTTP response.** It
  reads the chain head from the table. Async commit on Postgres and
  `synchronous=NORMAL` on SQLite both make a committed row **immediately
  visible**; only its *durability* lags. So the second request links onto the
  first, exactly as today.
- **Two server replicas appending concurrently (Postgres).** Unchanged: both still
  take `pg_advisory_xact_lock(auditAdvisoryLockKey)` inside the audit
  transaction, so the read-head-then-insert critical section is still atomic
  across processes. Async commit does not weaken an advisory lock.
- **A crash between a secret *mutation*'s durable commit and the audit row's
  async commit.** The mutation survives, the audit entry does not. This is a real
  consequence of the mode and is called out in §6 — it is the write path's
  version of the same tail loss the read path accepts.
- **Config present but the backend is `remote`.** `storage.type: remote` has no
  local database; the setting is inert there. The startup warning still fires if
  it is set (it is a posture deviation regardless), and the registry entry's
  `InEffect` stays true, because an operator who wrote the line into their config
  intended the weaker mode and should see it reported.
  **NEEDS ANDREI (1):** alternative is to treat it as not-in-effect on `remote`.
  Recommendation: keep it reported — a setting that silently reports "not in
  effect" while present in the file is exactly the silent weakening ADR-112 §1
  exists to prevent.

## 5. Why the chain cannot fork or gap — per backend

This is the part of the mode that must be argued, not asserted, because "lost tail
is fine, broken chain is not" is the whole safety claim.

### Postgres (`SET LOCAL synchronous_commit = off`)

The mechanism is one statement issued inside the audit transaction only:
`SET LOCAL synchronous_commit = off`. `SET LOCAL` is transaction-scoped — it
reverts at COMMIT/ROLLBACK and never leaks to the next transaction that borrows
the same pooled connection. `synchronous_commit` is evaluated at commit time, so
setting it inside the transaction is what takes effect for that transaction's
commit.

Why no gap is possible:

1. WAL is a single, totally ordered byte stream per cluster. Every transaction's
   commit record occupies one position (LSN) in it.
2. Crash recovery replays a **prefix** of that stream: it stops at the first
   record that is absent or fails its checksum. There is no mechanism by which a
   later record survives while an earlier one does not.
3. Therefore the set of surviving audit rows is always a prefix of the committed
   sequence — i.e. the chain loses a suffix, never a hole.
4. Mixing durability settings cannot invert this. A *synchronous* commit flushes
   WAL up to its own LSN, which necessarily makes every earlier async commit
   durable too. So a sync-committed secret mutation can survive while a *later*
   async-committed audit row is lost, but never the reverse — and never with an
   intervening audit row lost while a still-later one survives.
5. The chain head is read from the table inside the same transaction that inserts.
   After a restart, the head is whatever row actually survived, and the next
   append links onto it. Two rows can never claim the same `prev_hash`, because
   the only writer that could have produced the second one was rolled back by
   recovery, not merely made invisible.

Loss window: Postgres's WAL writer flushes every `wal_writer_delay` (default
200ms), and the documented worst case for async commit is three times that, so
**≤ ~600ms** of audit entries on a default-tuned cluster.

### SQLite (`_synchronous=NORMAL`, WAL mode)

WAL mode is already on (`internal/storage/factory.go`'s `sqliteDSN`). SQLite's own
documentation for `PRAGMA synchronous` states both halves of exactly the trade we
want: *"WAL mode is safe from corruption with synchronous=NORMAL"* and *"A
transaction committed in WAL mode with synchronous=NORMAL might roll back
following a power loss or system crash."* The same reasoning as Postgres applies
structurally: `-wal` frames are appended in order and individually checksummed, so
recovery accepts the longest valid prefix of commit frames and discards the rest.
Checkpointing stays safe because SQLite still syncs the WAL before copying frames
into the main database file and syncs the database file before resetting the WAL,
even at `NORMAL`.

`factory.go`'s existing `_synchronous=FULL` comment already describes NORMAL's
exact cost in this codebase's own words — "a transaction can report success to the
audit-chain writer while its WAL frame is still only in the OS page cache,
surviving an application crash but NOT an OS crash or power loss before the next
checkpoint." That sentence is the specification of this mode on SQLite. The
implementation keeps FULL as the default and that comment as the explanation of
why; it adds NORMAL only under the opt-out.

## 6. What you actually give up — and it is not the same on both backends

| | Postgres | SQLite |
|---|---|---|
| Keyorix process crash (`kill -9`, OOM, panic) | loses nothing | loses nothing |
| Database **server** process crash | loses ≤ ~600ms of audit entries | n/a (in-process) |
| OS crash / power loss | loses ≤ ~600ms of audit entries | loses audit entries not yet checkpointed |
| Chain integrity after any of the above | intact (prefix only) | intact (prefix only) |
| **Scope of the relaxation** | **the audit transaction only** | **the entire database** |

The last row is the one that must not be buried. On Postgres, `SET LOCAL` confines
the change to the audit transaction, so a secret write still commits durably. On
SQLite, `PRAGMA synchronous` is a **per-connection** property, and the connection
pool is shared by every query — so enabling the mode on a SQLite deployment
relaxes commit durability for *every* table, not just `audit_events`. A power loss
can then lose the last fraction of a second of secret writes as well as audit
entries.

This was a deliberate choice over the alternative (flipping the pragma per
transaction and restoring it afterwards), because that alternative fails *open*:
if the restore is skipped — an early return, a panic, a connection handed back to
the pool mid-sequence — the connection stays permanently weakened with nothing
reporting it. A statically weaker, loudly announced, posture-reported
database-wide setting is preferable to a nominally narrower one that can silently
become database-wide. The name keeps `audit` in it because that is the setting's
purpose and the reason anyone would turn it on; the SQLite scope is stated in the
field's doc comment, in the startup warning text itself, in the posture output,
and in the hardening guide.

**NEEDS ANDREI (2):** accept the SQLite database-wide scope, or restrict the
setting to Postgres only (refuse to start if it is set with a SQLite backend)?
Recommendation: accept it, with the wording above. SQLite deployments are the
small/edge ones where the latency win matters most (PERF-2: keyorix-sqlite W1 c=1
is 31.1 rps / 25.24ms p50, worse than Postgres), and an operator who has already
accepted "my power is guaranteed" has accepted it for the whole host, not for one
table.

## 7. Non-goals

- Not a background/async audit writer. The row is still written and committed
  before the response. ADR-115's local append-only journal is a different
  mechanism with a different trade; this spec does not touch it.
- Not a change to any default. Every default in ADR-112 §3's "Secrets and audit"
  block stays exactly as it is.
- Not a change to the hash-chain algorithm, the signed checkpoints, or
  `verify-audit`'s verification logic.
- Not reachable from any API. A compromised admin API must not be able to weaken
  an install's durability posture remotely, for the same reason `keyless_mode`
  is not reachable.

## 8. Measurement plan

pve01 VM 250 with the PERF-2 kit (`~/proj/bench-footprint`), W1 (hot secret read)
at c=1/10/50, on `keyorix-pg` and `keyorix-sqlite`, default vs fast mode, reported
beside PERF-2's `vault-on` / `openbao-on` numbers with the "x slower than Vault"
ratio at each concurrency. Results land in this session's report
(`~/proj/prompts/reports/SESSION-FASTAUDIT-1.md`), not in this spec.
