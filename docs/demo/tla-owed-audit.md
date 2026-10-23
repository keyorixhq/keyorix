# Demo: model-checking the owed-audit design (5 minutes)

What it shows: with a TLA+ model of how Keyorix records security changes
while the audit log is down, a model checker proves four properties within
bounds. It then finds a planted bug as a concrete step-by-step trace.
Background: `docs/design-rd-tla-owed-audit.md`. Model:
`docs/formal/owed-audit/`.

Needs: Java 11+ and network access to github.com (first run only, to fetch
the pinned TLA+ tools, about 2 MB). No server, no database, no Docker.

## 0:00 – 0:45 The promise (talk)

- "Revoking access must never wait for the audit log. Granting access must
  never happen without a record. And nothing may happen with no record at
  all."
- Open `docs/formal/owed-audit/OwedAudit.tla` at `CommitOwed`. Point out
  that the revocation's commit has no `auditUp` condition. Then show
  `CommitAudited`: a grant commits only `IF auditUp`.

## 0:45 – 1:45 It holds (run)

```
docs/formal/owed-audit/run-tlc.sh small.cfg | tail -6
```

Expected: `Model checking completed. No error has been found.` and
`27242 distinct states found`. Say: "Every interleaving of one revocation,
one grant and one break-glass activation, with the audit log failing and
recovering twice, a crash, and two backfill replicas. All four properties
hold, including the liveness one: the revocation takes effect even if the
audit log never returns."

## 1:45 – 3:15 Plant a bug, watch it get caught (run)

```
docs/formal/owed-audit/run-tlc.sh bug_widen_owed.cfg | grep -E "^Error|^State|auditUp|applied|chain ="
```

The planted bug: a grant takes the revocation's "owe it later" path. Read
the trace aloud: the audit log goes down (`auditUp = FALSE`), the grant
commits (`applied` gains it), and its row is not in `chain`. Result:
`Invariant WideningFailClosed is violated`.

Then the bug review found by hand in October (REVIEW-3482 F1):

```
docs/formal/owed-audit/run-tlc.sh bug_mixed_fail_closed.cfg | grep -E "^Error|Temporal|Back to state|^State"
```

Result: `Temporal properties were violated`, with a loop. The audit log
stays down, and the mixed "deactivate and change email" request fails and
retries for ever, so the deactivation never takes effect. Say: "This is the
bug a reviewer found in October. The model finds it in under a second."

## 3:15 – 4:15 The honest part (run)

```
docs/formal/owed-audit/run-tlc.sh pendingfault_silent.cfg | grep -E "^Error|^State|lostLogged|sink"
```

With the owed-record table refusing inserts and a crash at the wrong
moment (no audit outage needed), a revocation's audit row is lost with no
log line. Say:
"The model exists to find this. The gap is already documented for the loud
case; the silent variant was new." That configuration now runs the pre-fix
code as seeded bug `late_after_wait`. Show the fix passing:
`run-tlc.sh pendingfault_fixed.cfg` (RD-TLA-OWED-FIX-1: late record right
after the commit, rows named before it).

## 4:15 – 5:00 Everything at once (optional: the full run takes about 20 minutes, so start it before the demo and show its table)

```
docs/formal/owed-audit/run-tlc.sh
```

It prints one line per configuration: expected verdict, actual verdict,
distinct states. Every line ends in `ok`. The command exits non-zero if any
verdict changes, so it can guard a future protocol change.
