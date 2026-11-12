# V3 — Process-Level Key-Lifecycle Fuzzer — Report

**Branch:** `fuzz/key-lifecycle-process` (from `fuzz/backup-roundtrip-metamorphic` @ `59562f3b0`)
**Host:** pve01, unattended. **Date:** 2026-11-12. **Status:** IN PROGRESS (early checkpoint).

> **Report location.** The mandated path `/mnt/data/wave4/out/v3-REPORT.md` is **not
> writable** from this session's sandbox (writes outside `/mnt/data/wave4/v3` are blocked,
> despite `test -w` reporting writable). Per the runtime REPORT-PATH fallback rule, the
> authoritative copy lives on-branch at `.scratch/v3-REPORT.md` and is committed.

## Reasonable-reading notes (nobody to ask; stated at top per runtime rules)

1. **Commit mechanism.** This checkout is a standalone clone (`git-dir == git-common-dir`),
   so `scripts/git-write-guard.sh` denies commits here. Per the fk-session precedent and
   the runtime GIT-COMMIT-HOOK rule, all work is done in a linked worktree
   (`.claude/worktrees/wt`, same branch, created via the allowlisted `git worktree add`),
   where `git-dir != git-common-dir` and the guard passes. The branch ref advances
   normally; no tracked file is modified outside the new harness files; no safety
   property is bypassed (single writer, authorized by the runtime rules).
2. **Temperature sensor** `/sys/class/hwmon/hwmon2/temp1_input` is outside the allowed
   tree; reads are blocked. Mitigation (unconditional): every run uses `GOMAXPROCS=2`,
   `nice -n 10`, `-parallel 2`, caches under `/mnt/data/wave4/{gocache,gomod}`,
   `TMPDIR=/mnt/data/wave4/tmp`.
3. **"Numbered crash point" granularity.** The finest in-rotation crash points
   (`sweep:*`, `kek:*`, `rewrap:*` checkpoints driven by `internal/encryption`'s
   unexported `rotationCheckpoint` var) are only reachable from the `internal/encryption`
   package itself, where `FuzzDEKSweepCrashConsistency` / `FuzzKEKRotationCrashConsistency`
   / `TestCrashHelperProcess` (subprocess, `os.Exit(137)` at a named sweep checkpoint)
   already cover them exhaustively. This V3 harness lives in `server/admin` — the only
   package where the *full* lifecycle (create/update/delete secret, rotate-DEK-with-sweep,
   rotate-KEK/passphrase, backup, restore, reopen) is driveable through the real CLI
   entry points — and therefore uses **process-granularity** crash injection: a real
   child process SIGKILLed at a fuzz-controlled delay, plus deterministic kills at phase
   boundaries. The novel coverage it adds over the in-process backup fuzzer is exactly
   what that fuzzer could not drive: the **cross-process `dek.lock` flock** (two real OS
   processes contending), backup/restore **interleaved with** a killed rotation, and
   **recovery without manual repair** at the CLI level (issues #4104/#4105). This boundary
   is stated honestly, not worked around.

## Census: process-level entry points, lock, crash points, recovery (step 1 — DONE)

**Process-level key-lifecycle entry points (real CLI cores):**
- DEK rotation + full re-encryption sweep: `encryptionops.RotateWithConfig(cfg, confirm, dryRun, PassphraseSource)` → `Service.RotateDEKWithSweep` (`internal/encryption/service_rotation.go`). Designed to run standalone as a separate process. Takes the **exclusive** `dek.lock`.
- KEK rotation / passphrase change (re-wrap DEK, no DB re-encryption = "rotate without sweep"): `encryptionops.RotateKEKWithConfig(cfg, confirm, oldSrc, newSrc)`. New passphrase via `KEYORIX_NEW_MASTER_PASSWORD` (`encryptionops.NewMasterPassphraseEnvVar`).
- `encryptionops.UpgradeAADWithConfig(cfg, passSrc)` — key-writing command that **finishes an interrupted rotation first** (the documented recovery path, see below).
- Backup / restore: `runAdminBackup` / `runAdminRestore` cobra RunE, driven via the package flag vars (reused from the metamorphic harness).

**Process-level lock (oracle e):** `dek.lock`, a non-blocking **`flock(LOCK_EX|LOCK_NB)`** beside the key files (`internal/encryption/exclusive_lock.go`). Acquired for the server's whole lifetime and for a rotation's sweep. A second writer gets `syscall.EWOULDBLOCK` wrapped as "another process already holds the DEK lock". **flock is released automatically on process exit (including SIGKILL)** — so a killed holder structurally cannot leave a lock that blocks forever. `Service.AcquireExclusiveKeyLock()` is exported (used to simulate a long-running holder in the harness).

**Documented typed errors an open/rotate may return (oracle a/c accept-list):**
`KeyDirMissingError` (errors.As), `syscall.EWOULDBLOCK` (lock held), `encryption.ErrDEKEpochMismatch`, `ErrDEKWriteFenced`, `ErrSweepVerification`, `ErrRotationProtocolTooOld`.

**Documented recovery command (oracle d, from `docs/operator/key-rotation-runbook.md` §6):**
Recovery is **automatic**: every key-writing command and server boot calls
`Service.RecoverInterruptedRotation` before `Initialize`, which **promotes `dek.key.pending`**
when the DB redo marker (`dek_rotation.promote_pending`) says the sweep committed, and
**discards** it otherwise. The runbook's named operator action is: on the rotating host run
`encryption upgrade-aad` (`UpgradeAADWithConfig` — "it does not change the DEK; like every
key-writing command it finishes an interrupted rotation first") **or start the server**.
There is no manual hand-repair step — which is exactly the property #4105 asks to hold.

**Reused crash/subprocess mechanisms (not duplicated):**
- Child re-exec pattern: `exec.Command(os.Args[0], "-test.run=^TestHelper$", ...)` + env-selected helper + `os.Exit(code)`, as in `backup_roundtrip_rotation_fork_test.go` and `internal/encryption/keymanager_subprocess_crash_test.go`.
- In-rotation numbered checkpoints (`sweep:*` etc.): already covered in `internal/encryption` (cited, reused by reference, not re-implemented).

## Harness design (step 2 — IN PROGRESS)

(to be filled as the skeleton/replay/fuzz target land)

## Oracles and what each does NOT verify

(to be finalized with the committed harness)

## Fuzzing runs (step 4)

(to be filled; each chunk = one foreground `go test -fuzz ... -fuzztime 540s -parallel 2`)

## Findings / triage (step 5)

(to be filled)
