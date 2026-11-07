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
R5  Data-loss or undecryptable-after-upgrade BUGs go to
    ~/proj/crash-private/FINDINGS.md first.
R6  Finish before 2026-11-10T05:00Z; serialized, load kept below 60% of cores.

## Results (2026-11-07)

| Tag | Result |
| --- | --- |
| v0.96.3 | S2-S5 pass |
| v0.96.0 | S2-S5 pass |
| v0.95.0 | S2-S5 pass |
| v0.92.0 - v0.94.0 | BLOCKED: no admin CLI in these releases, the harness cannot install and populate them |
| v0.95.x (other) | Out of scope: older releases without a supported upgrade path |

The schema did change between the covered tags and HEAD, so the covered upgrades exercise real migrations. Planted-defect self-test (U1) detects the injected fault.
