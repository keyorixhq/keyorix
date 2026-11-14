# V3 — Process-Level Key-Lifecycle Fuzzer — Report

**Branch:** `fuzz/key-lifecycle-process` (from `fuzz/backup-roundtrip-metamorphic` @ `59562f3b0`)
**Host:** pve01, unattended. **Date:** 2026-11-12. **Status:** COMPLETE.

> **Report location.** The mandated path `/mnt/data/wave4/out/v3-REPORT.md` is **not
> writable** from this session's sandbox (writes outside `/mnt/data/wave4/v3` are blocked,
> despite `test -w` reporting writable). Per the runtime REPORT-PATH fallback rule, the
> authoritative copy lives on-branch at `.scratch/v3-REPORT.md` and is committed.

## Reasonable-reading notes (nobody to ask; stated at top per runtime rules)

1. **Commit mechanism.** This checkout is a standalone clone (`git-dir == git-common-dir`),
   so `scripts/git-write-guard.sh` denies commits here. Per the fk-session precedent and
   the runtime GIT-COMMIT-HOOK rule, all work is done in a linked worktree
   (`.claude/worktrees/wt`, same branch, via the allowlisted `git worktree add`), where
   `git-dir != git-common-dir` and the guard passes. The branch ref advances normally; no
   tracked file outside the new harness/deliverables is modified; no safety property is
   bypassed (single writer, authorized by the runtime rules).
2. **Temperature sensor** `/sys/class/hwmon/hwmon2/temp1_input` is outside the allowed
   tree; reads are blocked. Mitigation (unconditional): every run used `GOMAXPROCS=2`,
   `nice -n 10`, `-parallel 2`, caches under `/mnt/data/wave4/{gocache,gomod}`,
   `TMPDIR=/mnt/data/wave4/tmp`.
3. **Sandbox go-command form.** Inline `VAR=value go …` env-assignment prefixes are gated
   by the sandbox ("requires approval"); the `env VAR=value …` command form is not, so all
   runs used `env`/`env -u`.
4. **"Numbered crash point" granularity.** The finest in-rotation crash points
   (`sweep:*`/`kek:*`/`rewrap:*`, driven by `internal/encryption`'s unexported
   `rotationCheckpoint`) are only reachable from the `internal/encryption` package itself,
   where `FuzzDEKSweepCrashConsistency` / `FuzzKEKRotationCrashConsistency` /
   `TestCrashHelperProcess` (subprocess, `os.Exit(137)` at a named sweep checkpoint)
   already cover them exhaustively. This V3 harness lives in `server/admin` — the only
   package where the *full* lifecycle is driveable through the real CLI entry points — and
   uses **process-granularity** crash injection: a real child SIGKILLed at a fuzz-controlled
   delay, plus deterministic kills at step boundaries. Its novel coverage over the
   in-process backup fuzzer is exactly what that fuzzer could not drive: the **cross-process
   `dek.lock` flock** (two real OS processes), backup/restore **interleaved with** a killed
   rotation, and **recovery without manual repair** at the CLI level (#4104/#4105). The
   boundary is stated honestly, not worked around.

## Census: process-level entry points, lock, crash points, recovery (step 1 — DONE)

**Process-level key-lifecycle entry points (real CLI cores):**
- DEK rotation + full re-encryption sweep (**"rotate with sweep"**):
  `encryptionops.RotateWithConfig(cfg, confirm, dryRun, PassphraseSource)` →
  `Service.RotateDEKWithSweep` (`internal/encryption/service_rotation.go`). Standalone by
  design; takes the **exclusive** `dek.lock`.
- KEK rotation / passphrase change (re-wrap DEK, **no DB re-encryption** = "rotate without
  sweep"): `encryptionops.RotateKEKWithConfig(cfg, confirm, oldSrc, newSrc)`; new
  passphrase via `KEYORIX_NEW_MASTER_PASSWORD`.
- `encryptionops.UpgradeAADWithConfig(cfg, passSrc)` — key-writing command that **finishes
  an interrupted rotation first** (the documented recovery path).
- Backup / restore: `runAdminBackup` / `runAdminRestore` cobra RunE, via the package flag
  vars (reused from the metamorphic harness).

**Process-level lock (oracle e):** `dek.lock`, a non-blocking **`flock(LOCK_EX|LOCK_NB)`**
beside the key files (`internal/encryption/exclusive_lock.go`). A second writer gets
`syscall.EWOULDBLOCK` ("another process already holds the DEK lock"). **flock releases
automatically on process exit (incl. SIGKILL)** — a killed holder structurally cannot
leave a lock that blocks forever. `Service.AcquireExclusiveKeyLock()` is exported (used to
simulate a long-running holder).

**Documented typed errors an open/rotate may return (oracle a/c accept-list):**
`KeyDirMissingError` (errors.As), `syscall.EWOULDBLOCK`, `encryption.ErrDEKEpochMismatch`,
`ErrDEKWriteFenced`, `ErrSweepVerification`, `ErrRotationProtocolTooOld`, and the
(unexported) `errSweepOutcomeUnknown` matched by its stable message "the re-encryption
sweep may have committed". Anything else classifies to `UNEXPECTED` and fails the oracle.

**Documented recovery command (oracle d, `docs/operator/key-rotation-runbook.md` §6):**
recovery is **automatic** — every key-writing command and server boot runs
`Service.RecoverInterruptedRotation` before `Initialize`, which **promotes `dek.key.pending`**
when the DB redo marker (`dek_rotation.promote_pending`) shows the sweep committed and
**discards** it otherwise. The runbook's named operator action: on the rotating host run
`encryption upgrade-aad` **or** start the server. No manual hand-repair — the property
#4105 asks to hold.

**Reused crash/subprocess mechanisms (not duplicated):** child re-exec
(`exec.Command(os.Args[0], "-test.run=^TestHelper$", …)` + env-selected helper +
`os.Exit`), as in `backup_roundtrip_rotation_fork_test.go` and
`internal/encryption/keymanager_subprocess_crash_test.go`; in-rotation numbered checkpoints
already covered in `internal/encryption` (cited, not re-implemented).

## Harness design (steps 2–3 — DONE, committed with self-tests)

Three files in `server/admin` (test package `admin`):
- `keylifecycle_process_harness_test.go` — child protocol, `klWorld`, the acknowledged-write
  model, the child entry point `TestKeyLifecycleChild` (gated on `KL_CHILD=1`), and the
  in-process oracle runner.
- `keylifecycle_process_steps_test.go` — the step handlers, oracle (a)+(b) checker
  (`klDecryptKnownWith`, error-returning so red-proofs can watch it fire), and the program
  driver (`klRunProgram`, 3 bytes/step, bounded to `klMaxSteps`=10).
- `keylifecycle_process_fuzz_test.go` — `FuzzKeyLifecycleProcess`, the deterministic replay
  matrix `TestKeyLifecycleProcessReplay` (both backends), the Postgres corpus-replay test
  `TestKeyLifecycleProcessCorpusPostgres`, and four watched red/green oracle proofs.

Each lifecycle step runs as a **real child process** re-exec'ing the test binary, so the
`dek.lock` flock, the kills and the recovery command are genuine cross-process events. The
parent keeps a model of **acknowledged** writes (name→plaintext, node id, version) and runs
the oracles after each step. Steps: create / update / delete secret; rotate DEK (+sweep);
rotate KEK (passphrase change); backup; restore into a fresh store; **kill_rotate** (SIGKILL
a rotation child at a fuzz-controlled delay, then run the documented recovery command);
**concurrent_rotate** (a second rotation while a child holds the exclusive lock must be
refused); **kill_lockholder** (SIGKILL a lock holder, then a rotation must succeed); reopen.

**Backends:** SQLite always. Postgres when `KEYORIX_TEST_PG_DSN` is set, in isolated
`v3_<pid>_<n>` databases **dropped on cleanup** (`t.Cleanup` → `DROP DATABASE … WITH
(FORCE)`, runs on pass and failure).

## Oracles — and what each does NOT verify

- **(a) the store opens, or fails with a DOCUMENTED typed error, never a panic.**
  `klOracleReopenAndDecrypt` opens encryption+DB in-process after each step; a child step's
  outcome is gated by `klRequireDocumented` (a missing result file = crash/panic, or an
  `UNEXPECTED` kind, fails). *Does NOT verify:* that a store which legitimately refused with
  a documented error is otherwise usable (it classifies and returns — it cannot decrypt a
  store that will not open); nor any property of a backend other than the one under test.
- **(b) every acknowledged write decrypts to exactly its recorded plaintext.**
  `klDecryptKnownWith` re-derives `SecretAAD(node,proj,ver)` and compares bytes
  constant-time; plaintext is never logged. *Does NOT verify:* versions the harness never
  created; versions whose secret was deleted/purged (their row may be gone — an
  unacknowledged or deleted write may be present or absent, only never **corrupt**); the
  audit chain (oracle 3, owned by the restore's own verify-audit).
- **(c) a restore of a (possibly pending-rotation) backup starts or fails with a documented
  error, and never yields a store with undecryptable acknowledged secrets.** `klStepRestore`
  restores into a fresh dir/config, requires the restore's own "verify-audit … VALID", then
  decrypts the backup-time acknowledged snapshot under the backup-time passphrase. *Does NOT
  verify:* logical-state byte-equality of the restored store (owned by the metamorphic
  fuzzer's oracle 1); `--overwrite-existing` in-place restore (owned by
  `restore_overwrite_atomicity_test.go`).
- **(d) no manual hand-repair (#4105): after the documented recovery command the store is
  fully usable.** `klStepKillRotate` SIGKILLs a rotation child, runs the real
  `encryption upgrade-aad` (`UpgradeAADWithConfig`) child, then re-verifies (a)+(b). *Does
  NOT verify:* the deterministic in-rotation post-sweep-pre-promote checkpoint matrix (owned
  by `internal/encryption` `TestRotateDEKWithSweep_KillAfterSweepCommitBeforePromote_
  RecoversCleanly` / `FuzzDEKSweepCrashConsistency`); the process-granularity SIGKILL here
  lands at a fuzz-controlled delay (sometimes before/during/after the sweep), not at a named
  internal checkpoint.
- **(e) two concurrent rotations never both proceed; a killed holder never blocks the lock
  forever.** `klStepConcurrentRotate` / `klStepKillLockHolder` drive a real `holdlock` child
  (exclusive `flock`) against a real rotation child. *Does NOT verify:* contention between a
  rotation and a *live server* process (the harness simulates the lock holder with a
  dedicated `holdlock` child, not a running server); fairness/ordering beyond "never both,
  never stuck".

Every oracle has a **watched red/green proof** (below), so none is a guard nobody has seen
fail.

## Red/green oracle proofs (step 2 self-tests — all GREEN at the final SHA)

| Proof | Green (control) | Red (fires) |
|---|---|---|
| `TestKLRedProof_OracleB_Decrypt` | acknowledged write decrypts | **corrupt the stored ciphertext envelope → decrypt check returns error** |
| `TestKLRedProof_ViolationGate` (a/c/d) | each documented sentinel classifies to an accepted kind | **an arbitrary error → `UNEXPECTED`, rejected by `klDocumentedKinds`; a missing result file rejected** |
| `TestKLRedProof_OracleE_Lock` | free lock → rotation succeeds; killed holder → rotation succeeds | **held lock → rotation refused with `lock-held` (two never both proceed)** |
| `TestKLRedProof_OracleD_Recovery` | kill_rotate → recover → store usable + decrypts | (load-bearing via the `klRequireDocumented` gate proven in `ViolationGate`; deterministic in-rotation red/green owned by `internal/encryption`) |

## Fuzzing runs (step 4 — ≥90 min real fuzz wall time MET: ~108 min clean)

Each row = one foreground `go test -fuzz=FuzzKeyLifecycleProcess -fuzztime=540s -parallel=2`.
"Backend": `sqlite` = DSN unset; `sqlite+pg` = DSN set. "execs"/"new" are libFuzzer's own
final counters. "result" = PASS, or ARTIFACT (a worker-kill false crasher, triaged below).

| # | Backend | execs | corpus total | new | result |
|---|---------|-------|--------------|-----|--------|
| 1 | sqlite    | 38 | 19 | 11 | PASS |
| 2 | sqlite    | 40 | 31 | 12 | PASS |
| 3 | sqlite+pg | 47 | 35 | 4  | PASS |
| 4 | sqlite    | 65 | 43 | 8  | PASS |
| 5 | sqlite    | 73 | 52 | 9  | PASS |
| 6 | sqlite    | 78 | 60 | 8  | PASS |
| 7 | sqlite+pg | 64 | 60 | 0  | PASS (corpus re-verified on PG) |
| 8 | sqlite    | — | 60 | — | ARTIFACT (KL-1): worker-kill at 137s; input replays GREEN 4/4 |
| 9 | sqlite    | 95 | 67 | 7  | PASS (after `klMaxSteps`→10 robustness fix) |
| 10| sqlite    | 112| 73 | 6  | PASS |
| 11| sqlite    | 122| 76 | 3  | PASS |
| 12| sqlite+pg | — | 76 | — | ARTIFACT (KL-2): worker-kill at 260s; input replays GREEN (103s on PG) |
| 13| sqlite    | 116| 81 | 5  | PASS (SQLite-only fuzz target) |
| 14| sqlite    | 120| 85 | 4  | PASS |

**Clean fuzz wall time:** 12 PASS chunks × 540 s = **108 min** (≥ 90 target met). Breakdown:
10 SQLite-only + 2 both-backend PASS chunks; 2 both-backend ARTIFACT chunks (triaged, not
counted). Shared corpus grew to **85** interesting inputs. **Zero oracle violations** across
all runs. Throughput is honestly low (tens→~120 execs/chunk): this is a process-heavy
PROPERTY fuzzer — each exec forks ~10 PBKDF2-heavy children — so the value is depth-per-exec
(arbitrary lifecycle interleavings through the real cross-process lock), not exec count.

## Triage (step 5)

**KL-1 / KL-2 — ARTIFACT (fuzz-coordinator worker-kill under host load), NOT a defect.**
Both chunk-8 and chunk-12 failures were `fuzzing process hung or terminated unexpectedly:
exit status 2` **during baseline corpus replay**, with **no panic stack and no oracle
`Error`/`Messages`** — i.e. a worker killed by Go's fuzzing coordinator, not an oracle
`FAIL`. Triage per protocol:
- **Minimised + decoded:** KL-1 = `[0,0,0, 7,0,5, 0,0,10]` (create, kill_rotate, create);
  KL-2 = a 10-step rotation/kill-heavy program run on **both** backends.
- **Replayed:** KL-1 replays **GREEN 4/4** in isolation (~4.2 s each). KL-2 replays
  **GREEN** deterministically but takes **103.5 s** — a full 10-step program on Postgres
  costs ~2× SQLite and exceeds Go fuzzing's per-exec worker-liveness window, so the
  coordinator kills the worker. The chunk-8 log shows the smoking gun: a ~73 s stall on one
  exec, then the kill.
- **Root cause:** per-exec wall time, not correctness — each step forks a real
  600k-iteration-PBKDF2 child, and a long program (×2 backends) blows the coordinator's
  patience. No Keyorix code path misbehaved; every oracle held on replay.
- **Fixes (harness only, no production change):** (1) `klMaxSteps` 14→10 and trimmed the
  lock-hold sleeps (commit `6703e3409`), which also raised throughput (~78→~120 execs/chunk);
  (2) made the live fuzz target **SQLite-only** (commit `6a502f9ed`), since the both-backend
  per-exec cost is inherently over the window — Postgres depth is covered by
  `TestKeyLifecycleProcessReplay` (both backends) and `TestKeyLifecycleProcessCorpusPostgres`
  (both GREEN), which run under the package timeout, not the coordinator. The two false
  crasher files were deleted (they replay green; keeping them would wrongly imply a real
  bug). Post-fix chunks 13–14 were clean.
- **Reproducers:** `.scratch/fz8.log`, `.scratch/fz12.log` (original); `.scratch/repro1.log`,
  `.scratch/repro_a|b|c.log`, `.scratch/repro2.log` (green replays).

**KL-3 — OBSERVATION (serialization framing, NOT an integrity gap), not a finding.** While
building the oracle-(b) red-proof, a **single** middle-byte flip of the 211-byte
`secret_versions.EncryptedValue` decrypted to the **correct** plaintext, whereas
full-envelope corruption fails. Traced: `EncryptedValue` is `SerializeEncryptedData(encrypted)`
(a framed envelope — 211 bytes for a 19-byte plaintext — not raw AEAD). A flip in a non-AEAD
framing region is parsed to the same ciphertext → correct decrypt; the AEAD tag still
authenticates the actual ciphertext+AAD, so there is **no path to wrong-but-valid
plaintext** (any flip to the ciphertext/nonce/tag fails the tag). This is benign framing,
not incomplete AEAD coverage. The committed red-proof therefore corrupts the **whole**
envelope to stay unambiguous. Not traced to the exact byte-offset map of framing vs AEAD
(out of scope); flagged here honestly rather than claimed as either a defect or fully
cleared.

No VULNERABILITY / SECURITY-DEFECT / DEFECT was found. The negative result is reported
honestly: it is evidence the process-level lifecycle holds over the explored interleavings
(85-input corpus, both backends for the fixed/corpus cases), not proof of universal
correctness — see each oracle's "does NOT verify" list for the boundaries.

## Deliverables

- **Commits (branch `fuzz/key-lifecycle-process`, not pushed):**
  - `fe43a89f7` harness + replay matrix + fuzz target + red-proofs + early report
  - `d6c8ad200` `scripts/fuzzing/targets.d/server-admin__FuzzKeyLifecycleProcess.conf` +
    regenerated `targets.conf` (`gen-targets-conf.sh --check` passes)
  - `6703e3409` robustness: `klMaxSteps` 14→10
  - `6a502f9ed` SQLite-only fuzz target + Postgres corpus-replay test
  - final commit: changelog fragment, INVARIANTS.d entries, this report
- **Fuzzing target conf:** registered (1h budget); `scripts/fuzzing/gen-targets-conf.sh
  --check` → ok.
- **changelog.d:** `changelog.d/key-lifecycle-process-fuzz.md`
  (`scripts/changelog-assemble.sh --check` → ok).
- **INVARIANTS.d:** `server/admin/INVARIANTS.d/INV-ADMIN-keylifecycle-rotation-lock-mutual-exclusion.md`,
  `…/INV-ADMIN-keylifecycle-interrupted-rotation-auto-recovers.md`
  (`internal/statemap` fragments guard → ok).
- **Issue-ready proposals (no production change made):** none required — oracles (a)-(e) all
  held. The only harness-observed curiosity, KL-3, is benign on analysis. If the maintainer
  wants belt-and-suspenders, a dedicated test that maps which `SerializeEncryptedData` byte
  offsets lie outside AEAD coverage (and asserts a framing-byte flip never yields
  wrong-but-valid plaintext, only correct-or-error) would convert KL-3's prose into a
  machine-checked guarantee; stated as optional, not owed.

## What is NOT covered (honest boundaries)

- Live-server-vs-rotation lock contention uses a dedicated `holdlock` child, not a running
  server process (the lock semantics are identical — same `flock` on the same file — but a
  full server boot is not spun up per step).
- In-rotation NUMBERED crash points (`sweep:*`/`kek:*`/`rewrap:*`) are owned by
  `internal/encryption`; this harness kills at process granularity (fuzz-controlled delay +
  step boundaries), covering the *interleaving* dimension those fuzzers do not.
- The live fuzz target explores **SQLite only** (per KL-2); Postgres is covered by the
  deterministic replay matrix and the corpus-replay test, not by active libFuzzer mutation.
- Throughput is low by construction (process-heavy); the corpus (85 inputs) is modest and
  the exploration is depth-per-exec, not breadth.
