# Crash-recovery fuzz (TestCrashRecoveryFuzz_SQLite) -- pre-registration

Committed BEFORE the first campaign run (see git history: this file's commit
precedes the commit that records results). Rules below are fixed; results are
appended in a separate, later commit and may not edit these rules.

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
    rotation `dek.key` after a DEK rotation; (P5) truncate a backup archive and
    present it as complete. Each is an independent test; 5/5 required.
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
