# ADR-094: time handling — UTC internally, civil time only where the product needs it, clock authority on the hub

## Status

**Accepted (2026-08-30).** This ADR states the rule the codebase already
follows almost everywhere, names the places it doesn't, and recommends (but
does not implement) a stronger normalization boundary. Nothing is fixed in
this pass except one filed issue (Task 3's systemic finding) — the
normalization-boundary migration this ADR recommends touches every
persisted model and is a separate decision, not a task.

## Task 1 — what the code does today (machine-derived)

### Table 1: every persisted time column

Derived via a Go AST script (`go/parser`) over `internal/storage/models/*.go`,
filtered to the 77 models actually reachable from `internal/storage/factory.go`'s
`migrateDatabase` (production schema) and `models.AllTestModels()` (test
schema) — every struct name in that union corresponds to a real `type X
struct` definition; conversely 10 struct definitions in the package (e.g.
`SecretListFilter`, `ShareSummary`) are transient DTOs never migrated, and
are correctly excluded.

**Result: 141 fields of type `time.Time` or `*time.Time`, across 65 models.
Zero fields encode time as `int64` or `string`.** Confirmed by a second pass
matching every non-`time.Time` field whose name ends in
`At|Since|Until|Expiry|Expires|Date|Time` (case-insensitive) — the only
matches were 7 `gorm.DeletedAt` fields (GORM's own soft-delete wrapper, a
distinct, already-normalized type) and two false positives (`ValidationModeAtInvite`
— an enum string, not a timestamp; `IP`'s gorm index name, which happens to
contain "time"). No hidden encoding-type outlier exists.

Full per-model, per-field list (model, field, Go type, file:line):
`.scratch/timeaudit/model_time_fields2.txt` in this branch's working tree —
not reproduced row-by-row here (141 rows); the finding that matters is the
uniformity (100% `time.Time`/`*time.Time`), not the individual field names.
Representative shape: every model has `CreatedAt time.Time`; most mutable
models also have `UpdatedAt time.Time`; every expiring/lease/token model has
one or more `*time.Time` (nullable) or `time.Time` (non-nullable, e.g.
`RiskException.ExpiresAt`, `DynamicSecretLease.ExpiresAt`,
`MFAStepUpGrant.ExpiresAt`, `SchedulerLockLease.ExpiresAt`,
`WebAuthnSession.ExpiresAt`, `SSOLoginState.ExpiresAt`, `SetupToken.ExpiresAt`
— non-nullable because these rows only exist to expire) `ExpiresAt`/`RevokedAt`/
similar field.

### Table 2: where normalization happens

23 models have a `BeforeSave` GORM hook (`internal/storage/models/models.go`).
**Every one of the 23 hooks normalizes exactly ONE field to UTC via `.UTC()`
— never more than one, even on a model with several time fields.**
Cross-referencing hook coverage against Table 1's full field list: of 141
time fields, 23 are covered by a hook; 118 are not (`.scratch/timeaudit/gap_analysis.tsv`).
Of those 118, 42 are on a model that HAS a hook — covering a different
field — and 76 are on a model with no hook at all.

This is not 118 open questions; it splits into three concrete, verified cases:

1. **GORM's own auto-populated `CreatedAt`/`UpdatedAt`, never explicitly
   assigned in Go.** Already investigated and documented in this codebase,
   independent of this ADR: `StatsSnapshot`'s own doc comment
   (`internal/storage/models/models.go:1471-1488`) states, empirically
   verified (G81 bug-class sweep), that `BeforeSave` fires BEFORE GORM's
   auto-timestamp callback — a hook here would normalize a zero value that
   GORM's own `NowFunc` (default `time.Now`, local) then silently overwrites.
   Classified there as "latent, not live" because the one read site
   comparing it is also local, so nothing observably breaks today. This
   applies to every model whose only unhooked time fields are genuinely
   never Go-assigned.
2. **Explicitly Go-assigned, via the injectable clock, uncovered by any
   hook — confirmed, not hypothesized.** `internal/core/service.go:579` sets
   `now: time.Now` as the default clock for every `KeyorixCore` — **local
   time, not UTC, at the single point every constructor in `internal/core`
   is supposed to get "the current time" from.** Traced one concretely:
   `CreateUser` (`internal/core/users.go:114,121-130`) does `now :=
   c.now()` then `CreatedAt: now, UpdatedAt: now` — `User.BeforeSave` only
   normalizes `CreatedAt` (`models.go:464-466`). **`User.UpdatedAt` is
   written with a local-offset value on every real user creation in
   production, today** — not a fixture artifact, not hypothetical. The
   other 41 hook-partial-coverage fields (`SecretNode.UpdatedAt`,
   `Session.CreatedAt`, `MachineIdentity.UpdatedAt`,
   `ProjectMembership.UpdatedAt`, `ShareRecord.CreatedAt`/`UpdatedAt`, and
   siblings) follow the identical shape by construction — same clock, same
   one-field-hook pattern — not independently traced to the same depth, but
   structurally the same finding.
3. **Currently latent, not live, by the same test the codebase already
   applied to `StatsSnapshot`**: no raw-SQL range query
   (`WHERE updated_at < ?`/`> ?`) exists anywhere on any of these fields
   today (checked directly — zero hits). The live exposure is therefore
   API/wire serialization (a local-offset `UpdatedAt` in a JSON response or
   export) and any FUTURE range query someone adds without knowing the
   column can carry mixed offsets — exactly the ShareRecord bug class
   (#1619) this ADR's normalization-boundary recommendation exists to make
   structurally impossible rather than depend on remembering.

This is the direct evidence for Task 5's "where normalization happens" — a
per-field, late (BeforeSave-time), single-field hook is the dominant
mechanism, backstopped by nothing for the majority of fields, and the shared
clock those hooks are papering over is itself unnormalized at the source.

### Table 3: `time.Now()` call sites, bucketed

163 non-test call sites (AST-confirmed via `go/parser`, `internal/` +
`server/`), each traced to its enclosing function and classified:

- **instant** (recorded for persistence — `CreatedAt: time.Now()`,
  `ExpiresAt: now.Add(ttl)`): the majority. Not independently
  security-relevant; Table 1/2 already cover what happens to these values at
  write time.
- **duration, in-process** (both operands are `time.Now()`-derived within the
  same call — timing an operation, computing an operation's own elapsed
  time): monotonic-safe by construction; found in `internal/cli/status/status.go`
  (ping round-trip timing) and similar instrumentation. No wall-clock
  exposure — Go's `Sub` uses the monotonic reading when both sides carry
  one, and neither side here ever round-trips through storage.
- **duration/comparison against a stored value**: the security-relevant
  bucket — see Task 3 below.

## Task 2 — instants vs. civil time

**Two genuine civil-time cases exist, and both are already correctly
modeled** — this ADR is stating a rule the product already follows in the
one place it currently matters, not correcting a violation:

1. **`SecretAccessSchedule`** (`internal/storage/models/models.go:970-980`):
   `AllowedDays` (ISO weekday list), `StartHour`/`EndHour` (0–23), `Timezone`
   (IANA name) — three separate fields, no derived instant stored.
   Evaluated at `internal/core/secret_schedule.go:40-75`
   (`enforceSchedule`): `now.In(loc)` computes the local civil time AT
   EVALUATION TIME from the current instant; nothing is ever stored back.
   Deliberate fail-open on an unparseable timezone name (documented at the
   file's own package comment) — an operator's misconfiguration degrades to
   "no restriction" rather than a permanent lockout, a considered choice, not
   an oversight.
2. **`AnomalyConfigRecord`**'s off-hours rule
   (`internal/storage/models/models.go:1709-1712`): `OffHoursTimezone` (IANA),
   `OffHoursStart`/`OffHoursEnd` (0–23) — same shape. Evaluated at
   `internal/core/anomaly.go:174-184` (`isOffHours`): `t.In(loc).Hour()`
   against a STORED instant (`SecretAccessLog.AccessTime`, itself correctly
   UTC-hooked — see Table 2), computed at evaluation time, band may wrap
   midnight, extensively validated at the config-write boundary
   (`SetBusinessHours`, `anomaly.go:195-215`) against exactly the
   config-drift failure mode this ADR cares about (a degenerate band
   silently disabling the rule).

**Checked and ruled out as civil-time cases:**
- `RotationPolicy.IntervalDays` — a plain day-count interval (fixed duration:
  N×24h), not a wall-clock schedule or calendar-based retention. No DST/
  civil ambiguity.
- `AlertEscalationPolicy.EscalateAfterMinutes` — same shape, a duration.
- The NIS2/DORA 12-month audit-retention check
  (`internal/core/audit_retention.go:98-151`, `nis2RetentionDays = 365`) — a
  hardcoded lower-bound day-count used as a compliance-coverage THRESHOLD
  ("have you retained at least this long"), not a stored derived instant. A
  true 12-calendar-month span is never shorter than 365 days, so the
  constant is a safe (conservative) approximation for a >= comparison, not
  the "calendar year is not a fixed number of seconds" hazard this ADR
  warns about — that hazard applies to STORING a civil period as a fixed
  instant/duration, which this does not do.

**The rule, for when a new one arrives** (stated because a time-windowed
access or retention policy is a natural feature for this product, and
whoever adds the next one will store a UTC instant unless told not to,
exactly as `SecretAccessSchedule`'s own author evidently already knew):
store the civil components (hour/day/date) and an IANA zone name as
separate fields; compute the instant only at evaluation time; never persist
the derived instant as the value of record. `SecretAccessSchedule` and
`AnomalyConfigRecord` are the reference implementations — copy their shape,
not `ExpiresAt`'s.

## Task 3 — wall clock vs. monotonic: the duration/comparison verdicts

Every duration-or-comparison site from Table 1's third table, verdict given:

**In-process (safe), spot-checked:**
- `internal/core/rate_limit.go:191` (`at.After(c.now())`) and `:227`
  (`before.Before(cutoff)`) — both compare an externally-supplied instant
  against the hub's own current clock for input VALIDATION (reject a
  future-dated relay timestamp; clamp a caller-supplied prune cutoff), not a
  stored-value staleness check. Not the monotonic hazard; not a live
  concern either way, since the consequence of a backward host clock here
  is a validation check becoming more permissive about what counts as
  "not in the future," not an authorization extension.
- `internal/cli/status/status.go:80,125` — ping round-trip timing, both
  operands `time.Now()`-derived in the same call. Monotonic-safe.
- Rate limiting proper: no persisted rate-limit-window state exists — the
  `RateLimit` model (Table 1) has only `CreatedAt`, and `server.http.ratelimit`
  is (per the server's own boot log, confirmed empirically this pass) an
  in-memory limiter, never round-tripped through storage. Checked, not a
  wall-clock site.
- `internal/core/login_lockout.go:52,124,128,227` — `c.now().Before(*user.LoginLockedUntil)`
  and `now.Sub(*u.LastFailedLoginAt) > Window` DO compare against stored
  values (bucket 3 by definition) but are **directional-safe**: a backward
  clock step only makes `now` earlier, which makes these checks MORE likely
  to conclude "still locked out" / "still within the failure window" —
  extending a restriction, never an authorization. Reported here because
  the task asked for the safe ones too, not because they're findings.

**Against a stored value — wall-clock, and systemic. Larger than the first
pass found — a second, fuller sweep and independent re-verification
corrected the scope before filing.**

Every expiry/validity check in the codebase follows the identical shape:
a fresh clock read (`c.now()`/`time.Now()`, default clock: local `time.Now`,
per Table 2) compared against a `*time.Time`/`time.Time` field loaded from a
database row — either in Go via `.Before()`/`.After()`, or directly in a SQL
`WHERE ... expires_at > ?` bound parameter (the SQL-bound shape is just as
exposed; the comparison happens in the database instead of in Go, but the
bound parameter is still a single fresh wall-clock read). An initial pass
found 9 sites; a fuller sweep across `internal/core`, `internal/storage/store`,
and `server/http`/`server/grpc` found the pattern is far more pervasive, and
a sample of the fuller findings was independently re-verified by reading the
code directly (not accepted from the sweep's own severity claims — see the
one false positive below).

**Directly confirmed** (read the code myself):

| Site | What it gates | Consequence of a backward clock step |
|---|---|---|
| `internal/core/versions.go:124` (`enforceSecretReadGuards`) | The actual secret-value DISCLOSURE guard — per its own `#G09` comment, added specifically because other paths only checked a subset and let a value leak | An already-expired secret's **plaintext value** continues to be disclosed — the most severe single site found |
| `internal/storage/store/local_rbac.go` (~14 sites: `GetUserRoleIDsAt`, `GetUserRoleScopes`, `ListProjectRoleAssignments`, `ListGlobalAdminAssignmentsForUpdate`, `GetUserGroupRoleIDsAt`, `ListGroupRoleAssignments`, `GetUserPermissions`, `GetUserGroupPermissions`, siblings) | Every SQL query underlying role/group-role resolution — `WHERE expires_at IS NULL OR expires_at > ?` bound to `time.Now().UTC()` | Every temporary/JIT/break-glass role or group-role grant is treated as still current — including the last-global-admin guard and the effective-permission computation every authorization decision in the system ultimately depends on. The largest single cluster found. |
| `server/http/handlers/users_crud.go:710` (`ConsumeMFAChallenge`) → `internal/storage/store/local_mfa.go:123-130` | One-time MFA/WebAuthn login-challenge consumption — verified SQL: `UPDATE ... WHERE token_hash = ? AND used_at IS NULL AND expires_at > ?` | An already-expired one-time challenge can still be atomically consumed |
| `internal/license/license.go:179,183,189` (`LicenseStatus`) | Commercial feature gating past grace period | An expired-past-grace license continues reporting active, continuing to grant gated features |
| `internal/core/auth.go:468,477` (`ValidateSessionToken`) | Every authenticated HTTP/gRPC request | An already-expired session continues authenticating |
| `internal/core/auth.go:550,553` (`SessionStillLive`) | Long-lived gRPC stream re-authorization | A revoked/expired session keeps streaming |
| `internal/core/pat_expiry_enforce.go:32` | PAT validity | An expired PAT continues authenticating |
| `internal/core/machine_token.go:265,318` | Machine credential validity | An expired machine credential continues authenticating |
| `internal/core/dynamic_secrets.go:881` | Dynamic-secret lease validity | An expired lease is treated as still issuable/valid |
| `internal/core/setup_token.go:182` | Setup-token consumption | An expired setup token can still be consumed |
| `internal/core/setup_consume.go:280` | Invitation acceptance | An expired invitation can still be accepted |
| `internal/core/mfa_stepup.go:77` (`GetActiveMFAStepUpGrant`) | MFA step-up grant validity | An expired step-up grant still satisfies the MFA gate |
| `internal/storage/store/local_scheduler_lock_lease.go:92` (`TryAcquireSchedulerLock`) | Cross-replica scheduler mutual exclusion | If the LEASE HOLDER's own clock is the one stepped backward, its renewed `ExpiresAt` ends up earlier than other replicas' correct clocks expect — another replica can reclaim and run the same periodic job while the original holder is still executing it |

**Reported by the fuller sweep, same shape, not independently re-verified
to this same depth** (listed, not omitted, per the standing instruction that
a sweep listing only the interesting hits is indistinguishable from one
that didn't look): `auth.go:364,396` (session absolute-ceiling re-check),
`oidc.go:168` (JWT max-age freshness), `connect.go:556`
(`connectGrantActive`), `group_sharing.go:153`, `local_sharing.go:362`
(`CheckSharePermission` — the direct-share authorization gate),
`classification_gate.go:269` (restricted-secret access approval),
`invitations.go:657` (`ApproveAccessRequestWithExpiry`), `break_glass.go:237`,
`permissions.go:18` (`shareActive`), `permission_baseline.go:312`
(`grantExpired`), `risk_exceptions.go:78`, `dynamic_secrets.go:913,924,927`
(lease-renewal ceilings), `local_auth.go:147,234` (session listing/cleanup).

**One claim checked and found FALSE — excluded, not carried forward.** The
fuller sweep flagged `internal/core/authz.go:434`
(`cachedImpersonationCeiling`'s in-memory TTL cache) as wall-clock-hazardous.
Checked directly: `impersonationCeilingCache` (`service.go:368`) is a plain
`sync.Map`, **never persisted or serialized** — both the cached `expiresAt`
and the comparison are `c.now()`-derived from the SAME process with no
database round-trip between them, so Go's monotonic clock reading survives
on both sides and the comparison is immune to a wall-clock step — identical
in shape to the HTTP/gRPC auth-token caches and rate limiters (below,
correctly classified safe). Recorded here specifically so this claim isn't
inherited as a finding by a future reader who only sees the confirmed list.

Every confirmed site fits Task 3's own criterion exactly: a backward clock
step extends something that gates authorization, exclusivity, or
disclosure. **This is not N independent bugs** — it is one systemic
property of every absolute-timestamp expiry check in a system where the
validating process's own wall clock is the only clock available, inherent
to persisting expiry as an absolute instant (Go's monotonic clock cannot
survive a process restart or a value loaded from a different replica/row,
so it is not an available fix here). The actionable mitigation is
operational (NTP keeping clocks converging forward-only, and/or detecting
and alarming on a backward host clock jump), not a per-site code change —
filed as one issue covering the full list, updated in place with the
fuller sweep's corrected scope, rather than filed as separate issues that
would misrepresent a systemic root cause as unrelated coincidences.

**Filed: #1632**, updated with the fuller, verified scope (see Report
section).

## Task 4 — whose clock decides, and the backend asymmetry

### Client-clock-authority check: clean

Swept `internal/cli/**/*.go` for any expiry/validity DECISION (not display)
made from the CLI's own clock, and `internal/storage/store/remote_*.go` for
any `RemoteStorage` method computing validity itself rather than proxying
the hub's answer.

- `internal/cli/secret/get.go:250`, `list.go:235`: `time.Now().After(*secret.Expiration)`
  — cosmetic only. The secret's value has already been fetched/authorized
  by the point this runs; the check only adds a "(EXPIRED)" display
  annotation. Not a gate.
- `internal/cli/license/license.go` / `bundle/bundle.go` → `ilicense.Evaluate(...,
  time.Now(), ...)`: license-token verification (cryptographically signed,
  verified against a pinned key registry, `internal/license/license.go:135-175`).
  Not a hub/spoke relationship at all — an air-gapped/self-hosted product's
  license check is necessarily local (there is no hub to phone home to),
  and it degrades rather than denies on any anomaly (mismatch, expiry) per
  its own documented design. Correctly local, not a finding.
- `internal/cli/machine/token.go:92`: `time.Now().AddDate(0,0,days)` computes
  a PROPOSED `ExpiresAt` to send to `IssueMachineToken` — this is the
  embedded/local-mode path (`common.InitializeCoreService()`), where this
  process's `core.KeyorixCore` IS the authority; there is no separate hub
  whose clock should decide instead. Proposing a value to persist is not
  the same as deciding validity.
- `grep -rn "time\.Now()\|\.Before(\|\.After(" internal/storage/store/remote_*.go`:
  **zero hits.** Every `RemoteStorage` method is a pure HTTP passthrough
  with no time-comparison logic of its own — confirmed, not assumed.

**No instance found of a client or spoke deciding an expiry/validity
question that should be the hub's.**

### The backend asymmetry: tested, not reasoned about

Wrote a standalone Go program (`.scratch/timeaudit/roundtrip.go`, not
committed — throwaway) against a real SQLite (in-memory) and a real
Postgres 15 (Docker, `postgres:15-alpine`) instance: construct a
non-UTC input (`2026-03-08T01:30:00-05:00`, America/New_York, the night
before a US DST spring-forward — chosen so the same wall-clock hour is
genuinely ambiguous without an explicit offset), write it two ways (raw,
and explicitly `.UTC()`-normalized first), read it back, compare.

**Output, quoted verbatim:**

```
Input (constructed, America/New_York): 2026-03-08T01:30:00-05:00
Input .UTC():                            2026-03-08T06:30:00Z

=== SQLite (in-memory) ===
  [raw local input, no .UTC()]
    stored value read back: 2026-03-08T01:30:00-05:00 (Location=)
    .UTC() of what we read back:            2026-03-08T06:30:00Z
    equal to input .UTC() (correct instant)? true
  [explicitly normalized to .UTC() before write]
    stored value read back: 2026-03-08T06:30:00Z (Location=UTC)
    equal to input .UTC() (correct instant)? true
  [raw SQL Scan of the same raw-local row]
    scanned value: 2026-03-08T01:30:00-05:00 (Location=)

=== Postgres (localhost:15499, current DSN -- no TimeZone param) ===
  [raw local input, no .UTC()]
    stored value read back: 2026-03-08T07:30:00+01:00 (Location=Local)
    .UTC() of what we read back:            2026-03-08T06:30:00Z
    equal to input .UTC() (correct instant)? true
  [explicitly normalized to .UTC() before write]
    stored value read back: 2026-03-08T07:30:00+01:00 (Location=Local)
    equal to input .UTC() (correct instant)? true
  [raw SQL Scan of the same raw-local row]
    scanned value: 2026-03-08T07:30:00+01:00 (Location=Local)

=== Postgres (localhost:15499, DSN WITH TimeZone=UTC) ===
  (identical to the no-param case above -- the DSN's TimeZone setting has
  no effect on this behavior)
```

**Interpretation:**

- **The absolute instant is preserved correctly on both backends, in every
  case tested, including the raw non-UTC input.** `.Equal()`/`.UTC()`
  comparisons are correct everywhere. This is not an instant-corruption bug.
- **SQLite preserves whatever offset was written, verbatim**, as a string
  (confirmed at the raw-SQL level, not just through GORM's struct mapping —
  SQLite has no native timestamp type, per Task 4's own framing, and GORM's
  sqlite driver stores/returns the RFC3339 text as-is). Writing `.UTC()`
  first gets `.UTC()` back; writing a local offset gets that same local
  offset back.
- **Postgres's `timestamptz` column is correctly zone-aware at the SQL
  level** (verified directly: `SELECT data_type FROM information_schema.columns`
  reports `timestamp with time zone` — GORM's default for a `time.Time`
  field, confirmed empirically, no `type:timestamp` override exists
  anywhere in this codebase's model tags) — but **the Go driver ALWAYS
  converts the scanned value to `time.Local` — the reading PROCESS's own
  OS timezone — regardless of what zone was written, and regardless of
  whether the value was explicitly `.UTC()`-normalized before write.** A
  `TimeZone=UTC` DSN parameter does not change this (tested explicitly:
  identical output with and without it) — this is Postgres Go driver
  scan-time behavior, not a Postgres-server session setting.
- **This means "normalize before write" (a `BeforeSave` hook, or the
  recommended type/parse-boundary invariant) is necessary but NOT
  sufficient for a value read back from Postgres to also present as UTC.**
  On SQLite, a `BeforeSave`-normalized write round-trips as UTC on read. On
  Postgres, the identical write round-trips in whatever zone the
  READING PROCESS's OS is configured with — which in a typical container
  deployment IS UTC (most base images default `TZ=UTC` or unset resolving
  to UTC), but is NOT guaranteed by anything in this codebase, and is
  exactly the kind of thing that differs between a customer's on-prem
  server (this product's own stated deployment target) and a CI runner or
  a developer's laptop.
- **Concrete, wire-format consequence**: `time.Time.MarshalJSON()` emits
  RFC3339 including whatever offset is attached to the `Location`. For the
  IDENTICAL underlying data, a SQLite-backed API response would emit
  `"...Z"` and a Postgres-backed one would emit `"...+02:00"` (or whatever
  the server process's OS zone is) for the same field — a real,
  backend-dependent difference in what a client/audit-export/SIEM receives
  for the same value, silently.

**Which one is canonical when they disagree: neither backend's read-side
behavior is trustworthy on its own — the instant is always correct, the
presented offset is not.** The only reliable fix is re-normalizing at (or
after) every read, or a type/`sql.Scanner` boundary that does it
automatically (see Recommendation below) — a write-side-only hook, on
Postgres, does not close this gap the way it appears to on SQLite.

## Task 5 — the rule

**UTC everywhere internally.** Every persisted, compared, or transmitted
time value is UTC. Local time exists only at the final rendering boundary
(CLI table/detail-view formatting, already the exclusive pattern observed —
every display site found in this investigation formats for a human, never
feeds a decision) and is never itself persisted.

**Wire and export format is RFC 3339 with an explicit offset** — in
practice, always `Z` (UTC), since internal values are always UTC by the
rule above. A naive local-feeling string with no offset in an audit export
gets the receiving SIEM's own zone silently applied to it; an explicit `Z`
forecloses that regardless of what zone the exporting process happens to be
running in — directly motivated by Task 4's finding that the exporting
process's own OS zone is not otherwise pinned down.

**Where normalization happens — the real decision.** Today: a `BeforeSave`
hook per model, covering exactly one field each, backstopped by nothing for
every other field, resting on a shared clock (`c.now()`, default `time.Now`)
that is itself local. Task 1/2's `User.UpdatedAt` finding is not a
hypothetical the recommendation is guarding against — it is a proven,
current production behavior. **Recommend the stronger shape**: the
invariant carried by the type — a `UTCTime` wrapper implementing
`sql.Scanner`/`driver.Valuer` (or GORM's `Valuer`/`Scanner` hook interfaces)
so a value cannot be constructed OR scanned back out as non-UTC — over
"normalize at the parse/API boundary alone," because Task 4's Postgres
finding shows the boundary that needs closing is BOTH write AND read, and a
type-level `Scanner` is the only shape that closes the read side
automatically for every future query without requiring every call site to
remember `.UTC()` again. A parse-boundary-only fix (normalize incoming
request bodies) would still leave GORM's own driver-level Postgres reads
un-renormalized.

**Cost, not implemented in this pass**: touches all 65 models with a time
field (141 fields) — every declaration changes type, every hand-written
`BeforeSave` hook becomes redundant and should be removed (23 sites), every
place that currently does `field.UTC()` defensively becomes a no-op to
clean up (not required to, since `UTCTime.UTC()` would be a safe idempotent
op if the wrapper embeds `time.Time`), and every `gorm:"..."` tag needs
re-verification that the wrapper round-trips identically to bare
`time.Time` for existing migrations (SQLite text format, Postgres
`timestamptz` binary format) — a real, repo-wide, one-PR-per-model-cluster
migration, not a quick fix. This is why it is recommended and costed here,
not started.

**The instant/civil-time rule** (Task 2): store civil components (hour,
day-of-week, calendar date) plus an IANA zone name as separate fields;
compute the instant only at evaluation time; never persist the derived
instant. `SecretAccessSchedule`/`AnomalyConfigRecord` are the reference
shape.

**The duration rule** (Task 3): a duration or validity decision is not
computed against a value round-tripped through storage using the process's
own wall clock as ground truth, because that clock is not trustworthy
against a stale row (NTP correction, or an operator setting it backward —
worse in air-gapped deployments, where NTP is often simply absent and the
correction is manual). Where it must be (every expiry check in this
system, because the alternative — Go's monotonic reading — cannot survive
persistence or a process boundary), the hazard is named at the call site
(this ADR's Task 3 table is that naming) and the actionable mitigation is
operational: detect and alarm on a backward host-clock jump, don't rely on
application code to distinguish "NTP slewed this forward correctly" from
"an operator set this back."

**The clock-authority rule** (Task 4): an expiry or validity decision is
evaluated on the system that owns the record being checked — the hub, for
anything hub/spoke — never inferred by a client from its own clock. Checked
clean across the CLI and every `RemoteStorage` method; state the rule
anyway so the next spoke-side feature doesn't reintroduce it.

**What the two backends do, and which is canonical**: both preserve the
correct absolute instant always. Neither backend's READ-side zone
presentation is trustworthy without explicit renormalization — SQLite
returns whatever was written (correct if the write was normalized);
Postgres returns the reading process's own OS zone, unconditionally,
regardless of what was written or what `TimeZone` the DSN requests. Treat
the INSTANT as canonical (it always agrees); treat neither backend's
returned `Location` as meaningful without calling `.UTC()` again, until the
recommended type-level fix makes that automatic.

### Guard candidate, costed, not built

**Option A — AST check that every persisted time field is a normalized
type (`UTCTime`, not bare `time.Time`/`*time.Time`).** Buildable today,
cheaply — this ADR's own Task 1 script IS most of it (parse
`internal/storage/models/*.go`, walk struct fields, flag any
`time.Time`/`*time.Time` not already known-exempt). Runs once the type-level
fix exists; until then it would flag all 141 current fields, which is
correct (they're not yet fixed) but not useful as a merge gate. **What it
would miss**: it only verifies the DECLARED field type, not that every
CONSTRUCTION path actually produces a normalized value — a `UTCTime`
wrapper could still be built with a non-UTC `time.Time` inside if its own
constructor doesn't enforce it (the guard would need a second check, that
`UTCTime{}` composite literals never appear outside the wrapper's own
package — buildable, but a second, separate rule). It would also miss a
`time.Time` arriving via an embedded/anonymous struct or stored inside a
`map[string]any`/`interface{}` field (none observed in Table 1, but the
guard's coverage is exactly "declared struct fields," not "every path a
time value could take").

**Option B — flag `time.Now()` (or a variable assigned from it) appearing
in `.Before()`/`.After()`/`.Sub()`/`time.Since()` against a stored value,
outside an allowlist.** Harder, and this ADR's own Task 3 analysis is
direct evidence of the cost: doing this precisely requires tracing which
operand of a comparison originated from a database read versus an
in-process computation, which is not a syntactic property — it required
reading each enclosing function's full body, not a single-line grep, to
classify correctly (confirmed firsthand: an initial same-line-only grep for
this investigation found 0 of the real `.Sub()`/`.Since()` sites and only
12 of ~14 `.Before()`/`.After()` sites the full trace found). A buildable
simplified version: flag any `.Before(`/`.After(` call where at least one
operand is a struct-field selector on a known `*models.X` type, allowlisting
the confirmed-safe sites (Table 3's login-lockout/rate-limit rows). **What
it would miss**: a stored value first copied to a local variable before
comparison (breaks the "is a field selector" syntactic check — several of
this ADR's own Table 3 findings are exactly this shape, e.g.
`local_scheduler_lock_lease.go`'s `existing.ExpiresAt` compared as
`existing.ExpiresAt.After(now)` — a field selector, would be caught — versus
a hypothetical `expiry := existing.ExpiresAt; ...; expiry.After(now)` a few
lines later, which would not be, without following the assignment); and any
comparison reached through a helper function one level removed (this ADR's
`enforceSchedule`/`isOffHours` pattern), which needs interprocedural
tracing the AST-only version doesn't have.

**Recommendation for a future guard, if this ADR's normalization
recommendation is adopted**: Option A is worth building immediately as a
ratchet once the `UTCTime` migration starts (one model cluster at a time,
the guard's failing-count only decreases). Option B is worth building as a
repo-wide allowlist snapshot (like this codebase's own
`remoteUnsupportedAllowlist`/`knownUnfixedRawStorageBypasses` pattern) —
capture today's Table 3 as the allowlist baseline, fail on anything NEW —
rather than trying to solve interprocedural taint tracing generally.

## Report

- **Task 1's three tables**: machine-derived via `go/parser` AST scripts
  (not hand-listed) — 141 time fields / 65 models, 23 single-field
  `BeforeSave` hooks, 163 `time.Now()` call sites. Full data in
  `.scratch/timeaudit/` (not committed — reproducible via the scripts
  described above, which are the actual derivation, not a transcription of
  their output).
- **Instant/civil-time answer**: two genuine civil-time cases
  (`SecretAccessSchedule`, `AnomalyConfigRecord`'s off-hours rule), both
  already correctly modeled. Rule stated for the next one.
- **Duration verdicts**: systemic wall-clock exposure across every
  expiry/validity check in the codebase — larger than the first pass found;
  a fuller sweep plus independent re-verification confirmed the most severe
  sites directly (secret-VALUE disclosure at `versions.go:124`, the ~14-site
  `local_rbac.go` permission-resolution cluster, SQL-bound MFA-challenge
  consumption, license grace-period bypass), and caught one false positive
  (`authz.go:434`'s impersonation-ceiling cache, actually monotonic-safe —
  in-memory only, never serialized) before it was filed. One root cause,
  filed and then updated in place as one issue, not per-site. Login-lockout
  and rate-limit checks verified directional-safe. In-process duration sites
  (ping timing, HTTP/gRPC auth-token caches, rate limiters) verified
  monotonic-safe. `RemoteStorage`'s own pattern — deliberately dropping
  `now` from wire payloads so the hub's clock is always authoritative
  (`internal/storage/store/remote_mfa_stepup_grant.go`,
  `remote_mfa.go`) — is the correct shape already in place, cited as the
  reference, not a finding.
- **Client-clock check**: clean. No CLI or `RemoteStorage` path decides
  expiry/validity from its own clock — the one CLI-local exception
  (`internal/license`'s offline license evaluation) is by design for an
  air-gapped deployment with no hub to check against, not an instance of
  the fat-client pattern.
- **Backend round-trip**: tested against real SQLite and real Postgres 15,
  output quoted above. Instant always correct; read-side zone presentation
  differs by backend and, on Postgres, by the reading process's own OS
  timezone — not fixed by a DSN parameter.
- **The ADR's rule**: UTC internally, RFC 3339 with explicit offset on the
  wire, `UTCTime`-wrapper-at-the-type recommended over per-model
  `BeforeSave` hooks (costed, not implemented), civil time as
  local-components-plus-IANA-zone (already correctly done twice), clock
  authority on the hub (already correctly done everywhere checked).
- **Issues filed**: #1632 (wall-clock backward-step hazard across every
  absolute-timestamp expiry check — filed, then updated in place with the
  fuller, independently-verified scope and the one excluded false
  positive).

## Guardrails followed

Nothing implemented beyond this document and the one filing. The
normalization-boundary (`UTCTime`) migration is recommended and costed, not
started, per the explicit instruction that it touches every model and is a
separate decision. One worktree, one tally.
