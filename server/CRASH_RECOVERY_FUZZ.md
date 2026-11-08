# Crash-recovery fuzz (TestCrashRecoveryFuzz_SQLite) -- pre-registration

Written BEFORE the first campaign run. On PR #4014 the commit with these rules
(5bd0af7b2) precedes the one with the results (2c4ef818e); a squash merge removes
both from main's history, so the PR's commit list is the record. Rules below are
fixed; results are appended later and may not edit these rules. Changes to the
harness after a campaign are listed under "Amendments", not edited into the rules.

## What it does

Drives the real `keyorix-server` binary on SQLite. Per iteration: copy a
populated base install (secrets with several versions each), run one
maintenance operation as a child process, SIGKILL it at a chosen point, then
recover the way the documentation says an operator would, then check
invariants. Operations: `encryption rotate --confirm` (DEK sweep),
`encryption rotate-kek --confirm`, `backup`, `restore --overwrite-existing`.
Kill points: (a) the Nth observed change of the install directory's file
signature (names+sizes, polled ~0.5 ms), N drawn uniformly from the count seen
in a calibration run; (b) a time fraction of the calibrated runtime; (c)
"disk full": child runs under `ulimit -f` set below the output it needs (the
process either errors or dies on SIGXFSZ). Fault injection of fsync/rename
inside the process is NOT repeated here: `FuzzFaultInjectedOperations`
(internal/encryption) already does it at the seam level.

Scope limit, stated up front: SIGKILL stops the process; the kernel still
flushes the page cache. This is the "process crash" row, not a power cut.

## Invariants (a violation is a candidate finding)

I1  After documented recovery, the server starts unattended and every secret
    reads back a value equal to its last acknowledged value (for restore: equal
    to the pre-restore ledger OR the backup ledger, as a whole, never a mix).
I2  `admin verify-audit` reports VALID.
I3  `PRAGMA integrity_check` = ok; no `secret_versions` row without a live-or-
    soft-deleted `secret_nodes` parent; every secret's version count equals its
    ledger count (no lost/duplicated versions).
I4  `admin encryption validate` succeeds and every secret decrypts (covered by
    I1) -- no half-encrypted state. For rotate-kek exactly one of {old, new}
    passphrase works, never neither and never both.
I5  Interrupted rotation is resumable or rolled back: re-running the same
    command to completion succeeds and I1-I4 still hold.
I6  A killed backup leaves either no file at `--output` or a file that restore
    either rejects with an error or restores to exactly the ledger. A truncated
    archive that restores "successfully" with fewer secrets is a finding.
I7  A killed restore leaves a state that `restore --recover` (or a plain
    restart if no journal) resolves to wholly-old or wholly-new.

"Documented recovery" = only the commands named in the CLI help / docs:
re-run the same command, `admin restore --recover`. Needing any other manual
step (deleting files, editing the DB) is classified `OPERATOR-HOSTILE`, not a
pass.

## Success / failure rules (fixed in advance)

R1  Planted-defect self-tests must ALL be detected by the checker, or the
    campaign is void and no result may be reported: (P1) flip one byte in a
    secret's stored ciphertext; (P2) insert a `secret_versions` row whose
    parent does not exist; (P3) tamper one audit row; (P4) swap in the pre-
    rotation `dek.key` after a DEK rotation; (P5) delete one version row of a secret
    (lost version). Each is an independent test; 5/5 required, and the
    unmodified control must report zero violations.
    (Revision before any campaign run: P5 was first written as "truncate a
    backup archive"; replaced because a truncated archive is rejected by the
    signed manifest, which tests restore, not the checker. Backup-file
    behaviour is covered by I6 in the campaign itself.)
R2  Campaign passes if >= 300 kill iterations (>= 60 per operation, spread over
    the three kill-point kinds) end with zero invariant violations.
R3  A violation becomes a FINDING only after the post-kill directory snapshot
    (saved to the artifacts dir) is replayed through the recovery+checker path
    3 times with the identical verdict, then classified as one of: BUG
    (data loss / undecryptable / chain invalid / orphan), OPERATOR-HOSTILE
    (recoverable only by an undocumented step), TEST-ARTIFACT (harness fault,
    e.g. port clash, timeout under load), or EXPECTED (documented behaviour).
    Timing-based kill points are not replayable by themselves; the snapshot is
    the repro. A violation that does not reproduce 3/3 on the snapshot is
    TEST-ARTIFACT-suspected and reported as "unreproduced", not as a finding.
R4  Data-loss/security-class BUGs go to ~/proj/crash-private/FINDINGS.md only,
    not to the public repo or PR text.
R5  Campaign wall-clock must end before 2026-11-10T05:00Z; load average on the
    host is kept below 60% of cores (campaign serialized).
R6  An iteration where the child finished before the kill landed is counted
    as "completed" and excluded from the 300 total (reported separately).

## Results (2026-11-07)

Three rounds of 160 iterations each (480 total), run on a separate host at nice 19.

- Rule R2: NOT MET. This campaign must not be cited as passing R2. It recorded 320 SIGKILLs, 78 / 81 / 81 / 80 per operation (rotate-dek, rotate-kek, backup, restore), 166 at a directory-change count and 154 at a time fraction. That falls short of R2 for three reasons:
  - The disk-full kind (ulimit -f) produced no kills, only about 81 runs that ended in an error, so the kills were not spread over the three kinds.
  - Most time-fraction kills tested nothing. A later probe (30 kills per operation, comparing the SHA-256 of every file before and after each kill) found 42 of 45 time kills on rotate-dek, backup and restore left the install byte-for-byte unchanged, because they landed during startup and key derivation. The change-count kills alone, about 42 per operation, are below both the 300 and the 60 bars.
  - The 320 count came from a flag set when the signal was sent, not from the exit status, so it may include children that had already finished (R6).
- Violations of I1-I7 after documented recovery: 0 in all three rounds, over the states those kills actually reached. The checker could not yet see a resurrected soft-deleted secret (see Amendments).
- Planted-defect self-test (P1-P5): all detected, but only through the boot and quiescent checks.
- Scope limit: SIGKILL of the process is not a power cut. Page-cache loss and torn writes below the file system are not exercised.

## Amendments after the first campaign (review of PR #4014)

These change the harness, not the rules above, and apply to any later campaign.

- Kill points: the directory signature also includes mtimes. Time kills are drawn between the first and the last signature change seen in calibration, replacing the time fraction of the whole runtime.
- Counting: a kill counts only if the wait status shows SIGKILL ended the child and the SHA-256 of the install changed. Other kills are reported as `killed-noeffect`. The test logs the tally per operation.
- Checker: soft-deleted secrets are read as well and must stay `<gone>`. The planted-defect test now drives every case through the full recovery path and requires the planted invariant to fire. It adds P6 (a resurrected soft-deleted secret) and cases for the I4, I5, I6 and I7 branches.
- A child or post-kill admin command past its deadline is reported as a violation with its snapshot.
