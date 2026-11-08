# Upgrade-path fuzz (TestUpgradePathFuzz) -- pre-registration

Committed BEFORE the first campaign run. Rules are fixed; results are recorded
in a later commit and may not edit these rules.

## What it does

For each released tag with a prebuilt `keyorix-server` (built from the tag's
own source by scripts/fuzzing/upgrade-path/build-tags.sh): the OLD binary
installs, bootstraps and is populated through the REST API with seeded fuzzed
data (10-24 secrets; fuzzed names; 1-5 versions each with unicode, newlines,
quotes, long runs, JSON-ish text; ~1/6 soft-deleted), then stopped; the OLD
binary also takes a backup. Then, with the HEAD binary:

S2  clean upgrade: `admin migrate` on a copy, server boots, all invariants hold.
S3  idempotence: a second `admin migrate` changes neither schema fingerprint nor
    data fingerprint (secret_versions bytes, secret_nodes rows).
S4  interrupted migration: `admin migrate` SIGKILLed (dir-change index / time
    fraction / `ulimit -f` disk-full); then BOTH (a) a plain server start
    (auto-migration) and (b) a re-run of `admin migrate` must reach the clean
    upgrade state (values + schema fingerprint equal to S2's).
S5  old backup: the OLD-format backup restores with the HEAD binary into a
    wiped host (db + keys removed) and the data matches the ledger.

Invariants after any upgrade path: every non-deleted secret's latest value
equals the ledger; deleted ones read as gone; version-row count per secret
equals the ledger; `PRAGMA integrity_check`=ok; no orphan secret_versions;
`admin verify-audit` VALID; `admin encryption validate` ok.

## Rules (fixed in advance)

R1  Planted-defect control: the invariant checker is the one proven by the
    crash-recovery planted-defect suite (same code, fuzzharness_common_test.go).
    Additionally this suite plants (U1) one flipped ciphertext byte in a
    cleanly upgraded copy: the S2 verification path must report it, else the
    campaign is void. (Revision before any run: U1 was first written as a
    no-op migrate; dropped because HEAD's server re-migrates on boot, so it
    could not be made to fail meaningfully.)
R2  A tag is "covered" only if S2-S5 all ran. A tag whose old binary cannot be
    installed/populated/backed-up by this harness is reported BLOCKED with the
    reason; BLOCKED is never reported as PASS.
R3  Pass = every covered tag, >= 3 interrupted-migration kills per tag (>= 9
    kills mixed over the three kill kinds, counting only kills that landed),
    zero violations.
R4  A violation becomes a FINDING only after the saved post-kill snapshot (or
    for S2/S3/S5 the same seed) replays with the identical verdict 3 times, and
    is classified BUG / OPERATOR-HOSTILE / TEST-ARTIFACT / EXPECTED. Old-config
    keys rejected by HEAD with an actionable message are EXPECTED, not BUG.
R5  Data-loss or undecryptable-after-upgrade BUGs go to the private findings
    ledger first.
R6  Serialized, load kept below 60% of cores.

Wording of R5/R6 was shortened after pre-registration (a private path and the
campaign deadline do not belong in a repo document); the rules are unchanged.
The harness enforces R3 (a tag with fewer than 3 landed kills fails) and R2 (a
tag whose old binary cannot take a backup is skipped as BLOCKED, never PASS).
A kill "lands" when the child died of SIGKILL (change/time plans) or failed
under the file-size limit (diskfull plan).

## Results (2026-11-07)

Every tag is listed; there is no "out of scope" status (R2 allows only covered
or BLOCKED). v0.95.x is the documented in-place upgrade path
(docs/UPGRADING.md), so all of it is in scope. Rows other than v0.92.0/v0.93.0
were measured by an independent review of the campaign (seed 4015, 6 kill
attempts per tag, native macOS, SQLite) on the first version of this harness,
which logged but did not count landed kills.

| Tag | Result |
| --- | --- |
| v0.92.0, v0.93.0 | BLOCKED: no admin CLI, the harness cannot install and populate them (not re-run by the review) |
| v0.94.0 | BLOCKED: no server/admin in the tree (confirmed by the review) |
| v0.95.0 | S2-S5 pass |
| v0.95.1 | S2-S5 pass |
| v0.95.2 | FINDING: S5 fails, see below |
| v0.95.3 | FINDING: S5 fails, same shape as v0.95.2 |
| v0.96.0 | S2-S5 pass |
| v0.96.1 | S2-S5 pass |
| v0.96.2 | S2-S5 pass |
| v0.96.3 | S2-S5 pass |

The schema did change between the covered tags and HEAD, so the covered upgrades exercise real migrations. Planted-defect self-test (U1) detects the injected fault on v0.96.3.

After the review fixes (S4 now checks values and schema on both paths, landed
kills are counted) the harness was re-run on v0.95.2 and v0.96.3 only, seed 4015:
v0.96.3 passes with 5 of 6 kills landed (change=1 time=2 diskfull=2); v0.95.2
fails S5 as before, with 5 of 6 landed (change=2 time=2 diskfull=1). The other
tags have not been re-run with the fixed harness, so their pass rows above come
from the first version of the harness.

### Finding F1 (R4): v0.95.2 and v0.95.3 backups are refused on restore

- Observed: S5 `restore refuses: 18 dangling reference(s) ... table
  "secret_versions" column "secret_node_id" row 5 references missing
  secret_nodes.id=2` with HEAD. The old binary refuses its own backup too (64
  dangling references).
- Replay (R4, by the review): v0.95.2 and v0.95.3, same seed, no kills, 3 runs:
  identical failure 3 of 3. A second seed (777) fails the same way.
- Cause: backup v2 (`internal/backupfmt`) first ships in v0.95.2. Backups from
  v0.95.2 and v0.95.3 omit soft-deleted rows while rows that reference them are
  kept. v0.96.0 adds `TestRoundTrip_PreservesSoftDeletedRows`, whose comment says
  a backup "silently dropped every soft-deleted" row. HEAD's refusal is correct
  fail-closed behaviour.
- Classification: BUG in the released v0.95.2 and v0.95.3, fixed from v0.96.0.
  Not a HEAD bug and not a harness artifact. Reproduces only when the install
  holds soft-deleted secrets (every harness run has some).
- R5: a backup that cannot be restored by either release is a data-loss risk for
  disaster recovery, so it is to be entered in the private findings ledger (not
  done from this PR). The live database is not affected.
- Operator note not yet written: operators of v0.95.2/v0.95.3 with soft-deleted
  secrets should take a new backup after upgrading to v0.96.0 or later.

## Limitations (what the harness does not prove)

- Planted-defect control: R1 relies on the crash-recovery planted-defect suite,
  which is in a separate PR and not in this tree. In this tree only U1 exists, and
  it exercises the S2 value check only. No planted defect shows that the harness
  sees a missing migration, a non-idempotent re-run (S3), a schema or value
  difference after a killed migration (S4), or a bad restore (S5). Those checks
  are unproven against a failure. U1 was rewritten after the pre-registration
  commit (disclosed in R1).
- SQLite only (no Postgres), and only run on macOS so far (no Linux run).
- The disk-full kill uses `ulimit -f` and lands only if the migrate fails under it.
- The fuzzer runs only when `KX_UPGRADE_BINDIR` is set; CI does not run it.
