# MGV1 — Vault→Keyorix migration fidelity & safety

**Branch:** `fuzz/mgv1-vault-migration-fidelity` (append-only, not pushed).
**Status:** oracles built, red/green proven, registered; fuzz chunks in progress (see §6).

## 0. Report location / environment constraints (read first)
- `/mnt/data/wave4/out/` is **not writable** from this sandboxed session (hard filesystem
  boundary at `/mnt/data/wave4/mgv1`; writes/reads outside it are denied by the harness).
  Per the RUNTIME-RULES fallback ("if out is not writable, keep the report committed on the
  branch at `.scratch/mgv1-REPORT.md`"), this report lives at `.scratch/mgv1-REPORT.md` and
  is force-added to the commit (`.scratch/` is otherwise gitignored).
- **Go caches** could not use `/mnt/data/wave4/gocache|gomod|tmp` (same boundary); the host
  profile already points `GOCACHE=/mnt/data/wave4/gocache`, `GOMODCACHE=/mnt/data/wave4/gomod`
  and `go` subprocesses (unlike the Bash file tools) can write there, so no `/root` cache was
  used — the resource rule's intent is met.
- **`nice -n 10`, env-var prefixes and shell operators (`|`,`>`,`;`,`&&`) are auto-denied** by
  the session permission layer (only bare allowlisted commands run). Consequence:
  - CPU is bounded via `runtime.GOMAXPROCS(2)` set from an `init()` in the test files (runs in
    the coordinator **and** every `go test -fuzz` worker process) plus `-parallel 2`, instead
    of a `GOMAXPROCS=2`/`nice` wrapper. `nice` could not be applied.
  - Test output could not be redirected to files; it is read from the tool result directly.
- **Temperature:** `cat /sys/class/hwmon/hwmon2/temp1_input` is **blocked** (outside the
  worktree boundary) — temperature could not be polled at all. Mitigation relied solely on
  `GOMAXPROCS=2` + `-parallel 2` (≤2 cores) and modest, bounded workloads.
- **Module layout:** `migrate/` is a separate Go module excluded from the root `go.work`
  (`use .`). To build/test it I added a gitignored `migrate/go.work` (`use .`) scoping the
  workspace to the migrate module; the external fuzz rig uses `GOWORK=off; cd migrate` (per
  the existing target confs). `migrate/go.work` is **not** committed.

## 1. Most-reasonable reading of the task
"The importer" = the migrate tool's write path:
`vaultsource.Client.Walk` → `cmd.buildVaultPlanEntries`/`sanitizeSecretName` →
`plan.BuildPlan` → `plan.Apply` → `target.API.Create/UpdateValue`.
"Keyorix export" = reading the secrets back from a `target.API`, modelled by an in-memory
fake that mirrors the real HTTP client's **observable** semantics (per-(project,environment)
name uniqueness; atomic create-with-metadata = one HTTP POST; lookup/metadata/value reads).
The existing `FuzzVaultRoundTrip`/`FuzzParseVaultContent` cover only the **CLI YAML**
`writeVault`/`parseVault` string round-trip — not the migrate-tool pipeline, which had no
round-trip or convergence oracle. This task targets that pipeline.

## 2. Verify-first: what already existed (extended, not duplicated)
Existing migrate fuzz targets (`scripts/fuzzing/targets.d/`): `FuzzSanitizeSecretName`
(name derivation), `FuzzVaultSourceHostileWalk` (hostile **transport** for `Walk` — O1..O9),
`FuzzSplitJSONObject`, `FuzzAWSSourceHostileEndpoint`, `FuzzHealthscanHostileVault`,
`FuzzParsePolicyHCL`; CLI: `FuzzVaultRoundTrip`, `FuzzParseVaultContent`.
None covers the **Walk → plan → apply → export** fidelity, idempotent convergence under
partial write failure, or namespace-escape through the whole import. The two new targets are
additive and were written to not re-test transport safety (owned by `FuzzVaultSourceHostileWalk`).

## 3. The two fuzz targets / three oracles
Files (all `package cmd`, `migrate/cmd/`): `mgv1_support_test.go` (generator, faithful httptest
Vault, in-memory fake target), `mgv1_roundtrip_fuzz_test.go`, `mgv1_convergence_fuzz_test.go`,
`mgv1_redgreen_test.go`.

### Design choice that makes the oracles strong: conservation, not mirroring
The round-trip oracle does **not** re-implement `readLeaf`/`buildVaultPlanEntries` name/field
rules (a mirror would hide the same bug on both sides). It asserts **counts** and **value-set
membership**, which a wrong re-implementation cannot satisfy:
- all field values are globally-unique strings → value→leaf is exact;
- live-importable count = (# non-empty-key, non-empty-value fields after last-wins dedup) —
  independent of the single-"value" special case.

### O-RT (round-trip + hostile) — `FuzzVaultImportRoundTrip`
Generates a Vault KV v1/v2 export (nested paths, per-leaf version, custom_metadata, soft-
deleted/destroyed/empty/absent states, binary/multiline/unicode/bidi/NUL/long/duplicate-key
**field keys and values**, odd mount names, single-"value" and multi-field leaves), serves it
over a faithful httptest Vault, runs the real pipeline into the fake target, reads it back:
- **O-RT1 WALK-CONSERVATION** `len(entries) == liveImportableCount` (no silent drop/dup at parse; covers duplicate-JSON-key last-wins).
- **O-RT2 PIPELINE-CONSERVATION** `liveImportableCount == len(target) + failedCreates + buildSkips` (exact accounting Walk→target).
- **O-RT3 VALUE-MEMBERSHIP** every target value ∈ planted live values; target values distinct (no invention, no resurrection of soft-deleted data, no duplication).
- **O-RT4 NAMESPACE-SAFETY** every target secret name has no `/`,`\`,NUL,control and is non-empty (hostile key cannot escape the namespace).
- **O-RT5 VERSION/METADATA-FIDELITY** each created secret records `migrate.source`, `migrate.source-id`, and for KV v2 the exact `source-version`, `source-created-at`, and `vault.<custom>` metadata (omitted for KV v1).
- **O-RT6 REPORTED-NOT-DROPPED** every soft-deleted/destroyed/empty leaf appears in Walk `Skipped`.
- **O-RT7 NO-LEAK** value canary never in a Walk error, Skipped.Reason, build-skip reason, Apply error, or captured slog output.
- **O1/O2/O4** (panic/hang/alloc) via the shared `hostile.Harness.Run` around `Walk`.

### O-PARTIAL (convergence) — `FuzzVaultImportConvergence`
Imports a generated tree while failing each write seam (`Create`/`UpdateValue`) **before** a
commit (nothing written) or **after** an atomic commit (row+metadata written, client sees an
error — the realistic "committed server-side, response lost" HTTP partial failure), then
re-runs cleanly (operator retry):
- **O-PF1 NO-LOST-NAMES** after retry the target name set equals a clean import's.
- **O-PF2 VALID-WINNER** each surviving secret's value is a planted live value for that name (never empty/garbage/soft-deleted).
- **O-PF3 NO-DUPLICATES** target values distinct; one row per name.
- **O-PF4 FIXED-POINT** a further clean run changes nothing (idempotent convergence).

### Resource meters enabled, and why
- **O-RT**: shared `hostile.Harness.Run` meters the `Walk` **network** call: O1 panic,
  O2 hang (3 s deadline ×10 pristine), O4 bounded-alloc (256 MiB), O7 leak scan of error+logs;
  `Credentials` set for the token leak check. `Harness.Finish` (O3 goroutine/FD, O8 request-
  ceiling, O9 redirect) is **intentionally not called**: the metered call drives a *separate*
  in-process httptest Vault, so those transport-aggregate oracles are vacuous (O8/O9) or
  cross-server false-positive-prone (O3); Walk's transport hygiene is covered by
  `FuzzVaultSourceHostileWalk`. `Run`'s own O2/O4/O7 violations are surfaced explicitly.
- **O-PARTIAL**: in-memory after one clean Walk → no network/disk/sleep to meter; enabled
  **inline** memory-alloc ceiling (256 MiB), a 20 s hang deadline, and native go-test panic
  detection.

## 4. Red/green proofs (`mgv1_redgreen_test.go`, all PASS)
Each oracle assertion is shown to fire on the exact defect class it guards (RED) and hold on
the real pipeline (GREEN). Because this is an unattended session with no coordinator to approve
a throwaway production edit (CLAUDE.md rule), the planted defects live in test doubles — a
faithful stand-in for the real regression:
- **Conservation**: a store that silently drops one `Create` breaks the O-RT2 identity (RED); real pipeline conserves (GREEN).
- **Membership**: a store that invents an extra secret yields a value outside the live set (RED); real values all in-set (GREEN).
- **Namespace**: the detector fires on `a/b`,`a\b`,`a\x00b`,`x\ty`,`""` (RED); `sanitizeSecretName` output for hostile keys is always safe (GREEN).
- **Reported-deleted**: a report set with the deleted leaf removed fails the check (RED); real Walk reports soft-deleted + empty leaves (GREEN).
- **Convergence**: a faulted import with **no** retry loses a name (RED); fault + clean retry converges to the golden name set and is a fixed point (GREEN).

## 5. What each oracle does NOT verify
- **O-RT value coercion:** field values are always JSON **strings** (so value conservation is
  exact). Non-string KV values (number/bool/nested object/array → `fmt "%v"` coercion in
  `readLeaf`) are NOT exercised by the conservation oracle. *(LEFTOVER L1.)*
- **O-RT path hostility is in the KEYS, not the Vault PATH.** Path *segments* are kept
  routable (no `/`, NUL, `.`/`..`) so the fake server routes faithfully; `../`/NUL/bidi/control
  live in field **keys** (which drive `sanitizeSecretName`). Traversal/escaping in the Vault
  **URL path** itself is a transport concern owned by `FuzzVaultSourceHostileWalk`, not re-tested here.
- **O-RT does not drive `runVault`/CLI flag parsing, Preflight, the real HTTP `target.Client`,
  or a real Keyorix server.** The fake target models observable semantics only; a divergence
  between the fake and the real server's uniqueness/atomicity is out of scope. *(LEFTOVER L2.)*
- **O-RT does not assert on a Walk error** (treats it as fail-closed + no-leak and returns) —
  a legal shape that errors is not flagged as a drop. *(LEFTOVER L3.)*
- **O-RT does not test values > `DefaultMaxSecretSize` (64 KiB)** — kept small to stay off the
  value-too-large branch (`checkValueSize` is unit-tested separately). *(LEFTOVER L4.)*
- **O-PARTIAL models `Create` as an ATOMIC row+metadata write** (faithful to the single HTTP
  POST). A hypothetical **non-atomic** server write (secret row persisted but metadata lost)
  would strand idempotency (a retry would `Conflict` and require `--force`); this oracle does
  NOT exercise it because it needs server-side fault injection, not client-side. *(LEFTOVER L5 — highest-value.)*
- **O-PARTIAL faults only run 1**, retries are clean; it does not model a crash *during* a
  retry, nor concurrent importers racing, nor `--force` paths. *(LEFTOVER L6.)*
- **Neither oracle exercises AppRole login, namespaces, TLS, or the mount-version cache under
  concurrency.** *(covered elsewhere / LEFTOVER L7.)*
- **Temperature was never readable**, so thermal throttling could not be observed.

## 6. Fuzz results (real wall time only)
Shakeout (green, pre-chunk): `FuzzVaultImportRoundTrip` 40 s / ~34k execs;
`FuzzVaultImportConvergence` 40 s / ~15.7k execs. Two first-contact HARNESS bugs found & fixed
(fake-server root-list trailing-slash; a `#`-in-path over-truncation in O-RT6) — oracle logic
unchanged. Chunk log (4×540 s each target):

| target | chunk | wall | execs | result |
|--------|-------|------|-------|--------|
| _pending_ | | | | |

## 7. Classified findings
_None yet._ Both oracles are GREEN on all inputs explored so far (shakeout + chunks). No
VULNERABILITY/DEFECT/CANDIDATE. The two harness bugs were ARTIFACTs (test-harness only), fixed
at first contact per the rules; the oracle was not weakened.

## 8. Ranked LEFTOVERS (suggested minutes on the vCD hosts)
1. **L5 — non-atomic create/metadata partial write (server-side).** Highest value: build a
   server-side fault harness (real `target.Client` against a Keyorix test server whose secret
   write commits the row but drops metadata) and assert idempotent re-convergence. ~90 min.
2. **L1 — non-string KV value coercion.** Extend O-RT to number/bool/object/array values with
   a faithful independent `fmt "%v"` oracle (or assert "reported, not silently mangled"). ~40 min.
3. **L2 — real `target.Client` differential.** Run the round-trip generator through the real
   HTTP target against a live Keyorix (pg-gated) and diff against the fake. ~60 min.
4. **L6 — crash-during-retry / concurrent importers / `--force`.** Extend convergence to multi-
   run fault schedules and two racing imports; assert single-writer-wins + no dup. ~60 min.
5. **L4 — value-size boundary** (64 KiB / 1 MiB) end-to-end through the pipeline. ~20 min.
6. **L3 — Walk-error taxonomy**: assert that a legal shape never errors (distinguish fail-
   closed from a fidelity loss). ~30 min.
7. **L7 — AppRole/namespace/TLS/mount-cache-concurrency** import paths. ~45 min.
