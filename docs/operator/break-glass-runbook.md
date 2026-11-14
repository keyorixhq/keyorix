# Break-glass runbook: emergency access, and what happens when the audit log is down

Break-glass lets a project member grant themselves the configured emergency role,
immediately and for a limited time, with a written justification. It is off by default
(`break_glass.enabled`). This runbook covers what operators see, and what to do, in the
normal case and in **degraded mode**: an activation made while the audit log refuses
writes. Configuration keys are in `docs/CONFIGURATION.md` (`break_glass`); the policy
behind it is ADR-112 §3 and its Amendment 6.

## 1. Normal activation

```bash
keyorix break-glass activate --project-id 3 --justification "INC-4711: prod DB down, paging on-call"
```

Replace `3` with the project's id (`keyorix project list`). The caller must be a member of the
project and, on an install with `security.require_mfa` (the default), must already have a
second factor: without one the activation is refused with `This deployment requires
multi-factor authentication. Enrol MFA to continue. (HTTP 403)`.

On success the CLI prints:

```
Emergency access activated (id=1): role "project_developer" until 2026-11-14T13:34:46.676601Z.
  "project_developer" is now granted to you on project 1, in addition to the access you already had there.
  It expires automatically; a project administrator can end it early with: keyorix break-glass revoke --project-id 1 --activation-id 1
```

and the server does the following:

- The emergency role is granted at the project scope until `default_ttl` (or the requested
  `ttl`, capped at `max_ttl`). It expires on its own.
- Two audit rows are written **in the same database transaction** as the grant:
  `role.assigned` and `break_glass.activated` (with the justification).
- The project's administrators get a notification "Break-glass emergency access activated".
- The activation must be reviewed by someone other than the activator once it has ended
  (`POST /api/v1/projects/{id}/break-glass/{activationId}/review`, roles.assign on the
  project). Unreviewed past
  `review_window` (72h by default), it is a compliance posture deviation and a repeating
  reminder.

### Listing, revoking, expiry and the counter

The activator's `keyorix break-glass list --project-id 1` shows only their own activations;
a caller with `roles.read` on the project (an administrator) sees all of them:

```
Break-glass activations — project 1:

ID    USER  STATE     ROLE              EXPIRES (UTC)        JUSTIFICATION
1     alice active    project_developer 2026-11-14 13:34:46  INC-4711: prod DB down, paging on-call
```

(The activator's own view starts `Your break-glass activations — project 1 (only your own;
other users' need roles.read):`.) A project administrator ends an activation early with
`keyorix break-glass revoke --project-id 1 --activation-id 1` (`Revoked break-glass
activation 1 in project 1.`); `list` then shows `revoked`, and an activation that reaches its
expiry shows `expired`. Both leave the grant removed, with these audit rows (`keyorix audit
logs`): `break_glass.activated` + `role.assigned` on activation, `break_glass.revoked` +
`role.removed` on revocation, and `break_glass.reviewed` on review. Expiry by itself writes no
`break_glass.*` row. The review has no CLI command: `curl -H "Authorization: Bearer $TOKEN" -H
'Content-Type: application/json' -d '{"note": "at least ten characters"}'
https://HOST/api/v1/projects/1/break-glass/1/review` answers `Break-glass activation
reviewed`, and refuses the activator themselves (403) and an activation that is still active
(400).

`keyorix compliance report` shows the count under "Emergency access (break-glass)" as
`active / total activations : 1 / 1`. The JSON from `GET /api/v1/compliance/posture` carries
`emergency_access.{active_activations, total_activations, unreviewed_activations,
oldest_unreviewed_age_hours, review_window_hours}`; `unreviewed_activations` counts ended
activations still unreviewed after `review_window`.

## 2. Degraded mode: the audit log refuses the activation

Emergency access has to work during an incident, and an incident can be the audit
subsystem itself (a full disk, a broken audit table, a stuck lock, or someone making it
refuse writes on purpose). It must also never be unrecorded. So when, and only when, the
activation's audit append fails (an error, a panic, or a chain lock that does not come
within the audit write path's 10-second bound), the server does this instead:

1. In **one** transaction it commits the activation, the role grant, and an **owed-audit
   record** (`pending_audit_events`) of each audit row it could not append. Never one
   without the other.
2. The activation is marked **degraded** and is **short-lived**: it expires after
   `break_glass.degraded_ttl` (default **15 minutes**), or after the lifetime it would have
   had normally if that is shorter. A longer request or setting never lengthens it. It
   cannot be renewed while it is active, as usual.
3. It is **loud**:
   - a server log line at level ERROR starting `SECURITY: break-glass activation <id> is DEGRADED`;
   - the Prometheus counter `keyorix_breakglass_degraded_activations_total` goes up by one;
   - the project's administrators get a notification titled
     "Break-glass activated in DEGRADED mode (audit log unavailable)";
   - administrators (system.write) see a red banner in the web UI, and
     `GET /api/v1/system/info` → `security.break_glass_degraded` shows
     `{unsettled, unreviewed, activation_ids}`; the existing audit-owed banner
     (`security.audit_owed`) counts its owed rows too;
   - the activation carries `"degraded": true` in the API (HTTP and gRPC) and a
     **Degraded · audit owed** badge in the project's break-glass tab.
4. Its post-activation **review is mandatory at once**: a degraded activation is listed in
   the review reminder and in `security.break_glass_degraded` from the moment it exists, with
   no grace window. The compliance posture counter `emergency_access.unreviewed_activations`
   does not (yet) treat it differently: it counts a degraded activation only after
   `review_window`, like any other (verified: still 0 after the degraded activation ended).

The activator sees the shortened expiry. The web UI adds a note that the audit log was not
accepting writes; the CLI prints the same text as for a normal activation (only the shorter
`until` time tells them), and `keyorix break-glass list` does not mark it. The HTTP response
carries `"degraded": true`.

### What an operator should do

1. Treat the alert as two incidents: the one the user is handling, and the audit log.
   Check the server log for the `SECURITY: failed to persist audit event` lines that
   preceded it, the database's free disk space and health, and `audit_events` triggers or
   permissions nobody should have changed.
2. Fix the audit log. Nothing else is needed for the record: the **owed-audit backfill**
   (`audit_owed_backfill`, every minute, one replica at a time) writes each owed row into
   the hash chain as soon as the audit log accepts writes again:
   - in the order they were owed;
   - with their **original event time** (the moment of activation, not of the backfill),
     and a description that says they were recorded late;
   - exactly once (the claim of the owed record and the append share a transaction);
   - and in the same transaction as the activation's last owed row, the activation is
     marked **settled** (`audit_settled_at`).
   The server log says `Audit backfill: wrote owed audit event ...` for each row.
3. Review the activation (someone other than the activator), as for any activation. The
   banner goes away when every degraded activation is both settled and reviewed.
4. Confirm with the offline verifier (an admin command: with a server running on the same
   database it refuses with `appears to be using this database ... stop it first` and exit
   code 3, so stop the server first, or add `--force` if you accept the race):

   ```bash
   keyorix-server admin verify-audit --config ./keyorix.yaml
   ```

   While any degraded activation is unsettled the report says, under
   "Owed break-glass audit records", `N UNSETTLED -- activation ids [...]`, and the
   verdict is **INDETERMINATE** (exit code 2): the chain is intact but known to be missing
   those rows. When they are settled the section says `none` and the verdict is VALID
   again. On a database the verifier's role cannot read `break_glass_activations` from,
   the section says NOT CHECKED and the "does NOT prove" list says so. For any other
   BROKEN or INDETERMINATE verdict, see `docs/operator/audit-chain-break-runbook.md`.

An unsettled degraded activation is never removed by `data_retention.break_glass_days`.

### Watching the queue: how old is the oldest owed row

The owed rows (every owed revocation, not only break-glass) sit in `pending_audit_events`
until the backfill writes them. Three series on the authenticated
`GET /api/v1/admin/scheduler-metrics` (the `keyorix-protected` scrape job) show it; the
shipped rules are in `deploy/observability/prometheus-alerts.yaml`:

| Series | Normal | Alert |
|---|---|---|
| `keyorix_audit_owed_pending` (count) | 0 | `KeyorixAuditOwedPending`: above 0 for 10 minutes |
| `keyorix_audit_owed_oldest_pending_age_seconds` | 0 | `KeyorixAuditOwedOldestPendingWarn` above 1 hour, `KeyorixAuditOwedOldestPendingCritical` above 24 hours (both for 5 minutes; thresholds are the numbers in each rule's `expr`, see `deploy/observability/README.md`) |
| `keyorix_audit_owed_metric_scrape_errors_total` | flat | `KeyorixAuditOwedMetricUnreadable`: increasing for 15 minutes |

The count says rows exist; only the age tells a row that is delayed (minutes, the backfill is
catching up) from one that is stuck (hours, nothing is bringing it in), so a delayed row cannot
quietly become one that never arrives. Each alert has a section in
`deploy/observability/runbook.md`.

During an audit outage the database is often the thing that is down. The two gauges read the
database when scraped, with a 3-second bound, and answer **NaN, never 0 and never their last
value**, when they cannot: `KeyorixAuditOwedPending` and the age alerts then cannot fire, which is
why `KeyorixAuditOwedMetricUnreadable` watches the scrape-error counter instead. If it fires, you
are blind to the queue; restore the database, then look at the age at once. The age read is one
index lookup on `pending_audit_events.created_at` and takes no lock, so it cannot slow the
backfill. A replica whose clock is ahead of the one that wrote the oldest row reads as age 0 for
that row, not negative.

### Settling by hand (mixed-version upgrade only)

During a rolling upgrade from a version without degraded mode, an older replica's
backfill can write a degraded activation's owed rows without marking the activation
settled (it does not know the column). The rows are in the chain; only the marker is
missing, so verify-audit keeps listing the activation. Nothing else clears it, on
purpose: a marker that set itself whenever the owed records disappeared would also hide
records deleted by someone covering their tracks. Confirm, then set it:

1. `keyorix audit logs --limit 50` (or the web audit log): find the `break_glass.activated`
   row whose description says `DEGRADED ... activation <id>` and `recorded late`, and its
   `role.assigned` row.
2. Check that no owed record is left for it:
   `SELECT count(*) FROM pending_audit_events WHERE break_glass_activation_id = <id>;` → 0.
3. `UPDATE break_glass_activations SET audit_settled_at = CURRENT_TIMESTAMP WHERE id = <id> AND degraded AND audit_settled_at IS NULL;`
   (SQLite: `degraded = 1`). Do this with the server stopped on SQLite.

## 3. Last resort: when even the owed record cannot be written

If the audit log refuses the activation **and** the database cannot store the owed-audit
record either, nothing is granted. The user gets:

- HTTP **503**, error code `BreakGlassUnrecordable` (gRPC: `Unavailable`), with a message
  that the database itself is failing and names `keyorix-server admin recover-admin`;
- the server logs `SECURITY: break-glass activation REFUSED ...` at level ERROR with both
  causes.

At that point the database is broken, not just the audit log, and break-glass cannot work
without giving up the "never unrecorded" rule. The way back in is offline, on the host,
with exclusive access to the database:

```bash
keyorix-server admin recover-admin --user admin@example.com --recovery-key - --config ./keyorix.yaml
```

See `docs/operator/j5-lost-admin.md` for the full procedure (it needs the recovery key you
generated in advance; every use is written to the audit trail as `admin.recover_admin` and
notifies every current admin). Fix the database
first (disk, permissions, storage health): the server cannot record anything until then.

## 4. Configuration

| key | default | meaning |
|---|---|---|
| `break_glass.enabled` | `false` | turn self-service emergency access on |
| `break_glass.emergency_role` | | the contained role granted (no `roles.assign`) |
| `break_glass.default_ttl` | `4h` | lifetime when none is requested |
| `break_glass.max_ttl` | `24h` | ceiling on a requested lifetime |
| `break_glass.review_window` | `72h` | unreviewed longer than this: posture deviation |
| `break_glass.degraded_ttl` | `15m` | lifetime of a degraded activation; never longer than the normal lifetime of the same request |
