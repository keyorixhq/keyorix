# NR1 — At-rest & memory canary fuzzer ("where can a secret rest that it should not?")

**Status:** COMPLETE. Fuzzer + red/green self-tests committed; 4×540 s chunks run, no leaks.
**Report location:** `/mnt/data/wave4/out/` is NOT writable from this sandboxed
session (harness restricts writes to the worktree `/mnt/data/wave4/nr1`). Per the
runtime fallback rule this report lives, committed, on the branch at
`.scratch/nr1-REPORT.md`.
**Temperature:** `/sys/class/hwmon/hwmon2/temp1_input` is NOT readable from this
sandbox (same working-dir restriction). Thermal safety relied on `nice -n 10`,
`GOMAXPROCS=2`, `-parallel 2` throughout, as the runtime rules permit.
**Writer lock:** a SessionStart hook reported another session holding the repo
write-lock. All work was append-only on `fuzz/nr1-atrest-memory`; no production
code changed; the final commit is made via a linked worktree if the hook denies
`git commit` in this shared `.git`.

Branch: `fuzz/nr1-atrest-memory`. Date: 2026-11-16. Author: Andrei Beshkov.

---

## 0. Most-reasonable reading (stated up front — nobody to ask)

The task: a fuzzer for "where can a secret rest or linger that it should not?",
watching **disk** and **memory**, which the existing canary family does not.

**The task demands I grep first and say so if disk-scanning already exists. It
does** — thoroughly, for secret *values*. So, per the task's own instruction
("if one exists, say so and extend it instead of duplicating"), I did **not**
rebuild Part A for secret values. I targeted the two genuinely **unwatched**
gaps the existing targets leave open:

1. **Key material at rest (DEK/KEK bytes).** No existing fuzzer plants a
   canary-valued KEK or tracks the raw DEK bytes and checks they never land in
   plaintext/hex/base64 anywhere on disk except the operator's own key file.
   ADR-004 states plainly *"Never: raw KEK on disk"*; that claim had no
   byte-level at-rest fuzzer.
2. **Process-memory remnants of key material (Part B).** No existing target does
   a heap-dump / `/proc/self/mem` scan. INV-ENCRYPTION-24 is guarded by a
   *targeted in-place* check (`IsDEKWiped` on one backing array) and
   INV-ENCRYPTION-25 by a *static AST sweep* that `defer wipeBytes` appears —
   neither does a whole-address-space scan.

The new target lives in `internal/encryption` (where key material and its
zeroization claims live, and where test code can read `GetDEK()`/`IsDEKWiped()`).

---

## 1. What already exists (verified by grep + reading) — NOT duplicated

| Target | Scans | Classes | Raw disk bytes? |
|---|---|---|---|
| `internal/core/secret_ops_canary_fuzz_test.go` | `.db`, `-wal`, every DB cell, exports, logs, metrics, errors | secret values, metadata | **YES** (`.db`+`-wal`, ~L720-728) |
| `server/http/canary_sweep_core_test.go` | `.db`, `-wal`, **`os.TempDir()` recursively**, DB cells, responses, headers, logs, `/metrics` | request-surface secrets | **YES** |
| `internal/core/secret_ops_canary_pg_fuzz_test.go` | PG cells + pgx driver errors | secret values, metadata | N/A (no raw file on PG) |
| `internal/fuzzutil/canary/cli_args_canary_fuzz_test.go` | stdout/stderr, **every file under $HOME** | CLI secrets, metadata | **YES** (files under HOME) |

All reuse `internal/canary`'s scanner (raw, JSON-HTML, JSON, url-query/path/
double, html, go-quoted, hex lo/hi, base64 std/url/raw + phase-aligned,
basic-auth, 12-hex-char truncation window). The task's "common trivial
encodings" requirement is **already met** by that engine for secret *values*.

**Gap confirmed by grep:** none of these plants or scans for **DEK/KEK
key-material bytes**, and **none scans process memory**. Those are what NR1 adds.

---

## 2. What the new fuzzer does

**Files added (test-only, no production change):**
- `internal/encryption/atrest_memory_canary_fuzz_test.go` — `FuzzAtRestKeyMaterial`
  + the lifecycle driver + disk/heap scanners.
- `internal/encryption/atrest_memory_canary_selftest_test.go` — the red/green
  proofs and the HARDENING heap-residue probe.

**Lifecycle driver (`keyWorld`).** Builds a real `encryption.Service` whose KEK
comes from a **file key provider** — the production path per ADR-038
(`keymanager_lifecycle.go` records that the legacy passphrase+salt derivation is
*"unreachable from any live production caller today"*). This makes the exact KEK
bytes trackable and avoids a 600k-iteration PBKDF2 per exec. A file-backed
SQLite DB holds encrypted secret rows. The fuzz input is a byte string decoded
into an operation sequence (len ≤ 24):

- **op 0** — encrypt a secret value into the DB (`EncryptSecretWithAAD`).
- **op 1** — `RotateDEKWithSweep` (new DEK generation, re-encrypt all rows, same KEK).
- **op 2** — `RewrapDEKWithProvider` (migrate to a NEW file-provider KEK whose bytes we control).

**Tracked values.** Every DEK generation (read via `GetDEK()` before each
rotation), every file-provider KEK (the exact bytes written to its key file),
and every secret value. Each carries an `allowPath`: the single file where it may
legitimately rest (`""` = nowhere). A DEK's allow-path is `""` (the on-disk
`dek.key` holds the *wrapped* DEK = ciphertext, never the raw DEK). A file KEK's
allow-path is its own provider key file.

**Part A oracle (at rest).** After every op and once more at the end, scan every
file under the key dir (recursively: `dek.key`, `kek.salt`, `.pending`, `.lock`,
all provider `.kek` files, the SQLite `secrets.db`+`-wal`+`-shm`), plus every
**new** top-level `os.TempDir()` entry this process produced (bounded delta, so
other sessions' shared-tmp is never scanned), for each tracked value in these
encodings: **raw, hex-lower, hex-upper, base64 std/url/rawstd/rawurl, and a
16-byte raw truncation window**. A tracked value found in any file other than its
allow-path is an **AT-REST LEAK** and fails the fuzzer.

**Part B oracle (memory).** After `Shutdown`:
- **Authoritative, machine-checked:** `EncryptionService.dek` must report wiped
  (`IsDEKWiped()`), i.e. INV-ENCRYPTION-24. A `false` here fails the fuzzer.
- **Exploratory only (never fails the fuzzer):** `runtime.GC()` then
  `debug.WriteHeapDump`, scan the dump for any tracked DEK/KEK 16-byte window.
  Reported as HARDENING data — see §3/§6 for why a positive is not a defect and,
  importantly, why *this harness's* number is an ARTIFACT.

---

## 3. Oracles — and what each does NOT verify

### A1 — "raw DEK bytes rest nowhere on disk"
- **Verifies:** the random per-generation DEK never appears, in any of the 7
  encodings or a 16-byte window, in any key-dir file, the SQLite DB/WAL/SHM, or a
  temp file our process created.
- **Does NOT verify:** files the product writes *outside* the key dir and DB that
  this harness doesn't drive (e.g. an operator-run `admin backup` archive, remote
  storage blobs, cloud-KMS wrapped-KEK blobs); the kernel page cache / FS
  journal; swap; files other processes copy out. It scans file *contents* via
  `ReadFile`, not cached pages or freed disk blocks.

### A2 — "KEK bytes rest only in the operator's own key file"
- **Verifies:** a file-provider KEK appears only in its provider `.kek` file
  (allow-path), never in `dek.key` (wrapped-DEK ciphertext), `kek.salt`, the DB,
  `.pending`/`.lock`, or temp.
- **Does NOT verify:** passphrase-derived KEKs (the legacy, non-production path —
  deliberately not exercised); KMS/TPM/Shamir-sourced KEKs; that the provider
  file's *permissions* are correct (that is INV-STORAGE-29/30's job); anything
  about the KEK's lifetime in RAM (that's Part B).

### A3 — "secret values rest only as ciphertext" (bonus; overlaps existing targets)
- **Verifies:** a planted secret value never appears in plaintext at rest.
- **Does NOT verify:** anything the two existing secret-value targets already
  cover better (responses, logs, metrics, all DB cells) — included only because
  it costs nothing and strengthens the key-dir/temp coverage.

### B1 — "EncryptionService.dek is wiped on Shutdown" (INV-ENCRYPTION-24)
- **Verifies:** the *specific named backing array* `es.dek` is all-zero after
  `Shutdown`, every exec. This is the authoritative memory claim and it HOLDS.
- **Does NOT verify:** any other copy of the DEK bytes. `GetDEK()` returns a fresh
  `make`+`copy` (keymanager_io.go:16); PBKDF2/HKDF intermediates; the `dek` local
  in `Initialize`; GC-relocated copies; bytes that transited an immutable
  `string`. INV-ENCRYPTION-25's own "Not covered" list already acknowledges these.

### B2 — post-Shutdown heap residue (EXPLORATORY / HARDENING — never an oracle)
- **What it measures:** how many tracked DEK/KEK values still have a 16-byte run
  present in a heap dump after `Shutdown`+GC. Deterministically **4 of 4** here.
- **Why it is NOT a defect:** Go gives no guarantee that garbage is zeroed before
  sweep, GC may relocate/duplicate a slice, strings are immutable, finalizers run
  at GC's discretion, and `WriteHeapDump`'s coverage of unreachable-but-unswept
  memory is a runtime implementation detail. A positive is expected absent a
  documented zeroization claim for that exact copy — and the only such claim
  (B1) is checked exactly and holds.
- **CRITICAL honesty caveat — this harness's number is an ARTIFACT:** the scanner
  holds its own live copies of the needle bytes (`w.tracked`) in the *same* heap
  it dumps. So "4 of 4 present" is substantially the test finding *its own*
  references, and this construction **cannot distinguish a product-side residue
  from the harness holding the needle.** It therefore proves nothing about the
  product's memory hygiene beyond B1. A sound product-side memory oracle would
  need the needle to live in a *different* address space than the key being
  scanned — see §9 (subprocess + `/proc/<pid>/mem`, feasible for the KEK which a
  parent can supply but a child's random DEK it cannot).

---

## 4. Red/green proof (`atrest_memory_canary_selftest_test.go`)

A guard nobody has watched fail is not a guard. Each oracle was watched failing
on a planted leak and passing clean. All pass, **deterministically across 3
replays** (`-count=3`, 18/18):

| Self-test | Plants | Asserts |
|---|---|---|
| `TestAtRestOracle_DetectsPlantedDEKOnDisk` | `hex(DEK)` into a file in the key dir (an accidental debug-log of key material) | clean world has 0 findings; after plant the DEK-on-disk leak **fires** |
| `TestAtRestOracle_DetectsPlantedKEKOutsideAllowPath` | `hex(KEK)` into a stray file ≠ its provider file | KEK in its OWN provider file is NOT flagged (allow-path works); copy elsewhere **fires** |
| `TestAtRestOracle_CleanLifecycleHasNoFindings` | — | a full mixed lifecycle (encrypt/rotate/rewrap) leaves 0 at-rest findings (green control) |
| `TestMemoryOracle_DEKWipeCheckIsNotVacuous` | — | `IsDEKWiped()` is **false** while live and **true** after Shutdown (the check is load-bearing, not vacuous) |
| `TestMemoryHeapScanner_DetectsLiveKey` | — | the heap scanner finds the live DEK/KEK before Shutdown (detector is sensitive) — found 2 live values |
| `TestMemoryHardening_PostShutdownHeapResidue` | — | records the HARDENING residue number (4/4) with the artifact caveat |

The plants live only in test code and are never reached by the fuzzer or by
production code; they were in place for the proof and remain only as the
permanent, machine-checked red/green harness (the repo's own preferred pattern,
cf. `scripts/fuzzing/configspace/*oracle_selftest*`). No production file was
edited for the red proof.

---

## 5. Fuzzing campaign

Env (every run): `nice -n 10`, `GOMAXPROCS=2`, `-parallel 2`,
`GOCACHE=/mnt/data/wave4/gocache`, `GOMODCACHE=/mnt/data/wave4/gomod`,
`TMPDIR=/mnt/data/wave4/tmp`, `GOFLAGS=` (to avoid a machine-wide `-trimpath`).

| Chunk | fuzztime | execs | corpus (interesting) | result |
|---|---|---|---|---|
| smoke | 40 s | 8 | 6 | PASS |
| measure | 90 s | — | 19 | PASS |
| 1 | 540 s | 21 | 19 | **PASS** |
| 2 | 540 s | 42 | 31 | **PASS** |
| 3 | 540 s | 52 | 42 | **PASS** |
| 4 | 540 s | 62 | 52 | **PASS** |

Real fuzz wall time counted: **4 × 540 s = 2160 s (36 min)** in the four chunks
(plus ~130 s smoke/measure). All foreground, back-to-back, no background tasks.

**Throughput is deliberately low (~9–26 s/exec)** and this is honest: each exec
runs real heavy key-lifecycle operations — DEK sweeps that re-encrypt all rows,
provider rewraps that take an exclusive cross-process file lock, plus a
world-stopping heap dump — across up to 24 ops. It is a forensic lifecycle
fuzzer, not a microsecond parser fuzzer. The coverage-guided engine **saturated
quickly**: new-interesting per chunk declined 13→12→11→10 and the op-sequence
shape space (3 op kinds, bounded length) is genuinely small, so low exec counts
still cover the meaningful states. (Swapping a hand-rolled byte search for
`bytes.Index` after chunk 1 roughly doubled throughput — a harness fix, not an
oracle weakening.)

---

## 6. Findings (classified honestly)

**No VULNERABILITY / SECURITY-DEFECT / DEFECT found.** The oracles fired only on
planted defects, never on real Keyorix code.

| # | Observation | Classification |
|---|---|---|
| F1 | No DEK/KEK/secret bytes rest on disk out of place across 2160 s of lifecycle fuzzing + 3× clean-control replays. `dek.key` holds only the wrapped (ciphertext) DEK; `kek.salt` holds only the random salt; a file KEK rests only in its own provider file. ADR-004's "never raw KEK on disk" **held**. | **No finding** (negative result, oracle validated red/green) |
| F2 | `EncryptionService.dek` reported wiped after every `Shutdown` (INV-ENCRYPTION-24) — every fuzz exec and 3/3 replays. | **No finding** (documented claim confirmed) |
| F3 | Whole-heap scan finds 4/4 tracked DEK/KEK values after Shutdown+GC. | **ARTIFACT** — dominated by the harness's own live needle copies (`w.tracked`); cannot distinguish product residue from the test holding the needle (see §3 B2). Not evidence of a product leak. |
| F4 | `GetDEK()` returns a fresh `make`+`copy` of the DEK that callers receive unwiped; such copies are not covered by the wipeBytes claim. | **EXPECTED-DIFFERENCE** — already acknowledged in INV-ENCRYPTION-25's explicit "Not covered" scope ("key bytes that reach a variable without a call", copies). Not a new defect; noted for completeness. |

**Deleted-row remnants (task asked for this, classified separately and
honestly):** `RotateDEKWithSweep` re-encrypts rows in place; old ciphertext
versions and SQLite freelist pages / WAL frames can retain *ciphertext* of
superseded secret versions until VACUUM. This fuzzer tracks **key material and
plaintext**, and found **no plaintext** in any such remnant — superseded data at
rest is ciphertext, which is the product's documented stance (envelope
encryption, ADR-004). Freelist/WAL ciphertext remnants are therefore
**EXPECTED-DIFFERENCE**, not a leak; a VACUUM-timing hardening question (when
ciphertext of deleted versions is physically reclaimed) is out of scope for a
*plaintext/key-material* oracle and is noted, not claimed.

---

## 7. Reachability trace

The oracle operates on the exact artifacts a live `keyorix-server` produces:
- **Production constructor path.** `encryption.NewService(cfg, baseDir)` →
  `Service.Initialize` → `buildKeyProvider` (from config) → `keyManager.Initialize`.
  This is the one production constructor (`keymanager_lifecycle.go`), and the
  **file key provider** the fuzzer configures is a real production
  `key_provider.type: file` (ADR-038, `buildSingleProvider` case `"file"`).
- **Production operations.** `EncryptSecretWithAAD`, `RotateDEKWithSweep`
  (ADR-010, the `admin encryption rotate-dek` path) and `RewrapDEKWithProvider`
  (ADR-041, the `admin encryption migrate-provider` path) are the real runtime/CLI
  key operations, invoked here exactly as a server/CLI invokes them.
- **Production at-rest artifacts.** `dek.key`, `kek.salt`, `.pending`/`.lock`
  siblings and the SQLite store are the literal files the server writes to the
  key dir and data dir at runtime.
Thus a leak the oracle *would* flag would be reachable by a live caller — the
negative result (no leak) is a statement about the production at-rest surface,
not a lab-only artifact. The one exercised code path that is NOT live is the
legacy passphrase KEK derivation, which the fuzzer deliberately avoids.

---

## 8. Minimisation / replay

No findings to minimise or replay against the product. Oracle *stability* was
confirmed instead: the red/green self-tests (including both planted leaks) and
the HARDENING probe pass **deterministically over 3 consecutive runs**
(`-count=3`, 18/18), and all four 540 s fuzz chunks over a persistent,
growing corpus completed with zero failures — i.e. the clean-world oracle was
re-exercised across 185 distinct lifecycle inputs without a false positive.

---

## 9. Limitations — what these oracles CANNOT see (per the task)

- **Swap / hibernation image** — not inspected; a key paged to swap is invisible here.
- **Kernel page cache & filesystem buffers / journal** — we read file *contents*
  via `ReadFile`, not cached pages or the FS journal.
- **Core dumps** written by the OS on a crash outside our harness.
- **Operator backups outside the product** (`cp data.db …`, snapshots, `admin
  backup` archives) — the fuzzer does not drive `admin backup`, so backup
  archives and the backup-manifest key's at-rest handling are NOT covered.
- **Cloud-KMS / TPM / Shamir KEK sources** — only the file provider is exercised;
  KMS-wrapped-KEK blobs and TPM sealed blobs at rest are out of scope (TPM blob
  secrecy has its own guard, INV-ENCRYPTION-27).
- **Side channels** — timing, cache, compression-ratio leaks are not in scope.
- **Memory, honestly (the big one):** the post-Shutdown heap scan as built is an
  ARTIFACT (the harness holds the needle in the same heap, §3 B2). It cannot
  prove a product-side memory residue. The only sound memory claim here is the
  narrow, documented `IsDEKWiped` (B1), which holds. A real product-side memory
  oracle would require the needle to live in a different address space than the
  scanned key — a **subprocess design**: a child holds the keys, shuts down, and
  the parent scans the child's `/proc/<pid>/mem` for a KEK the *parent* supplied
  (feasible for a file KEK; not for the child's random DEK, which the parent never
  learns). That is the recommended follow-up; it is noted, not claimed as done.
- **Go runtime copies we cannot name** — GC relocation/duplication, immutable
  strings, finalizer timing. Stated per-oracle above.

---

## 10. Issue-ready proposals (no production change made here)

1. **(Hardening, low) Subprocess memory-residue oracle.** Add a
   `/proc/<pid>/mem`-based check that a child process, after `Shutdown`, retains
   no file-provider KEK the parent configured — the one memory-residue question
   this harness honestly cannot answer in-process. Classify any positive as
   HARDENING unless a zeroization claim is extended to cover the relevant copy.
2. **(Hardening, low) `GetDEK()` copy lifetime.** INV-ENCRYPTION-25 explicitly
   does not cover `GetDEK()`'s returned copies. If callers are expected to wipe
   them, document that contract and add a caller-side guard; otherwise record the
   accepted residue explicitly (it is currently implicit in a "Not covered" line).
3. **(Hardening, low) Extend the existing disk canary targets to `-shm` and the
   key dir.** `server/http/canary_sweep_core_test.go` skips `.shm` and does not
   scan the encryption key directory. For *key material* specifically, folding the
   key-dir scan into that target would consolidate at-rest coverage.

None of these is a security defect; all are optional hardening, filed so the
omissions read as considered rather than overlooked.
