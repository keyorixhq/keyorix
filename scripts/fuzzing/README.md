# Fuzzing (self-hosted rig + CI)

Keyorix's `func Fuzz*` targets (`internal/crypto`, `internal/core`,
`internal/rotation`, `internal/notary`, …) run continuously on a dedicated
self-hosted box. **The rig runs one standardized runner — the external
`fuzz-harness` `fuzz-runner.sh`** — the same runner Keyorix, DashDiag, and the
third-party-libs rigs all use, despite being different projects.

## The rig runner (fuzz-harness)

The runner, its per-project `fuzz.conf`, the crash **report sink** (`REPORT_MODE`
= `local` / `private` / `pr` / `issue`, defaulting to **`private`** so an
unfixed own-code vuln is never disclosed before the fix — crashers push to the
private `fuzz-corpus` repo, not a public issue/PR), dynamic target discovery,
exec-rate-scaled slice reweighting, and the re-verify-before-alert guard all
live in **`keyorixhq/fuzz-harness`** (`fuzz-runner.sh` + `examples/keyorix.conf`).
The rig deploys a standalone copy of the runner and a Keyorix `fuzz.conf`; the
systemd unit's `ExecStart` points at `fuzz-runner.sh`.

> Historical note: an earlier in-repo `scripts/fuzzing/` rig
> (`run-rotation.sh` + `runlog.sh` + `notify-on-crash.sh` + `sync-corpus.sh`)
> opened and fed a public `fuzz rig: failing-run logs` tracking issue (#1846,
> now closed), posting every failing run's log as a comment — a disclosure
> anti-pattern for a security product (raw crash logs on a public repo). It was
> superseded by the shared fuzz-harness runner and removed.

## What remains in this directory

- **`targets.d/`** — one file per fuzz target (`<pkg-slug>__<FuzzName>.conf`),
  the hand-maintained canonical list of this repo's fuzz targets. Add a target
  by adding a new file here — never by editing a shared file, which is what
  made every fuzz-target PR conflict with every other one before this split.
  See `targets.d/README.md` for the format. The CI `fuzz-targets` drift-guard
  (`.github/workflows/ci.yml`) fails a PR if a real `func FuzzXxx` is missing
  from it or a declared target no longer exists in the tree. The rig discovers
  targets dynamically; this list is the human cross-check that nothing
  silently drops out of coverage.
- **`targets.conf`** — GENERATED from `targets.d/*.conf` by
  `gen-targets-conf.sh`; exists only because the external `fuzz-harness` rig
  repo still reads this flat file directly (see `targets.d/README.md`). Never
  edit it by hand — `gen-targets-conf.sh --check` fails CI if it drifts.
- **`targets.d/BUDGET.tsv`** — per-target rig priority (high/medium/low),
  orthogonal to each target's own per-invocation fuzztime. Validate with
  `validate-budget.sh`. See `docs/fuzzing/continuous-rig.md` for the design
  this supports (pve01 continuous rig, STEP 1 only — STEP 2 is blocked on
  PHASE0, see that doc's own banner).
- **`race-pass.sh`** — runs the fuzz corpus under `-race` (needs cgo; dev/CI
  only: it is not a rig job). Backs the data-race closure (#1870). The rig itself
  (vcd-keyorix-fuzz) builds with cgo, which the TPM simulator targets need.
- **`harness-acceptance.sh`** — reach-check + coverage-delta gate for *in-wall*
  harnesses (see below).
- **`DISCLOSURE-TRIAGE.md`** — the crash-feasibility gate a third-party-library
  finding must pass before it becomes a disclosure or an article sentence.

Fuzzing catches ledger (finds, lessons, disclosure history): `keyorixhq/fuzz-corpus` `docs/fuzzing-catches-ledger.md`.

## Adding a FuzzStorageFaultOperations operation (server/faultops)

**New operations go in their own file, `server/faultops/ops_<area>_test.go`,
registered from an `init()`** — never appended to `opcatalog_test.go`'s
`opCatalog` literal or `inventory_overrides_test.go`'s `operationOverrides`
literal. Those are single shared tables: every two op-adding PRs conflicted on
them and had to be serialised through the merge queue.

```go
func init() {
	registerOps("saml", operation{Key: "REST POST /auth/saml/acs", Setup: ..., Execute: ...})
	registerOverrides("saml", map[string]overrideEntry{
		"REST POST /auth/saml/acs": {StatusFuzzed, "opCatalog — ops_saml_test.go"},
	})
}
```

`server/faultops/registry_test.go` documents the merge rules: registered ops
are appended after every legacy op (so legacy seed indices never shift), in
(area, registration order); a registered override never overwrites an
existing entry. `TestRegisteredCatalog_NoDuplicateKeys` fails on a duplicate
op key across legacy + registered ops and on any override collision, and the
existing `TestOperationCatalogKeysAreRegistered` applies to registered ops
exactly as to legacy ones (a registered op still needs a `StatusFuzzed`
override, and vice versa). Do not edit `fuzz_storage_fault_operations_test.go`
or `inventory_overrides_test.go` to add an op.

## Harness quality gates (beyond never-panic)

A never-panic harness proves nothing about a security boundary, and an *in-wall*
harness — one that pours the fuzzer past a signature/JSON wall by seeding from a
valid fixture — can run millions of execs while silently **dry**, every mutation
dying at the wall. Two gates keep that honest; both align with the published
state of the art (OSS-Fuzz-Gen coverage metrics, QuartetFuzz's reach checks,
FalseCrashReducer's feasibility triage).

- **Reach + coverage-delta** (`harness-acceptance.sh`). For each in-wall harness
  it measures coverage of the specific *post-wall* functions and requires it to
  clear a floor — and, where a byte-level sibling exists, to exceed it (the code
  the sibling can't reach is the whole point). Run on a rig/CI clone (needs a
  working `go build`), fast/deterministic by default (seed corpus), `--fuzz Ns`
  for a deeper measure. A `FAIL<floor` means the harness never reached its target
  code and is effectively dry — fix the fixture/seeds before trusting it.

- **Rediscovery / regression.** Every harness that encodes a *security* invariant
  keeps a labeled reproducer of the bug class it exists to catch, plus a
  deterministic regression test asserting the current code handles it. Exemplar:
  the SAML XML-epilogue signature-bypass — `internal/saml/provider_epilogue_test.go`
  (`TestParseResponse_RejectsXMLEpilogue` + `TestParseResponse_AllowsTrailingWhitespace`)
  turns the one catch into a standing rediscovery check. For third-party findings
  the reproducer stays private (rig `fuzz-corpus`); see the research module's own
  `rediscovery_test.go`.

## Oracle health (planted-defect suite)

A fuzzer that has gone blind is silent, and silence reads as "nothing left to find".
`oracle-health/oracle-health.sh` re-runs, on demand, the red-proof every harness had
once by hand: for each entry it takes a throwaway copy of the tree, runs the harness
on its seed corpus unmodified (the **control**, must be green), applies the entry's
**planted-defect patch**, replays the same corpus (deterministic, no fuzzing time)
and requires a FAIL that contains the entry's **marker** text. Exit 1 if a control is
red or a harness stays green on its plant. The only older automatic check of this
kind is the authzdiff self-test (`ci.yml`, job `authzdiff-plants`); it is listed as
the entry `authzdiff-plants` and not re-implemented.

```
scripts/fuzzing/oracle-health/oracle-health.sh [--list] [--only id,id] [--heavy] [--strict]
                                              [--ref REF] [--workdir DIR] [--tsv FILE] [--keep]
```

Verdicts: `DETECTED` (healthy), `MISSED` (the harness is blind to its plant: a
finding, file an issue, do not fix the plant), `CONTROL-RED`, `WRONG-MARKER` (failed
for another reason than the intended oracle), `PLANT-STALE` (the patch no longer
applies: re-base it), `PLANT-BROKEN` (the plant does not build), `SKIP` (no Postgres,
heavy entry, harness skipped itself: shown, never counted as a pass; `--strict` makes
it exit 3), `KNOWN-BLIND` (a filed finding, kept visible; flips to `BLIND-FIXED`,
which fails, the day the harness sees the plant). The runner never edits the checkout
it runs from and removes its trees on exit. It is meant for the nightly host
(pve01); there is deliberately no workflow for it.

**An entry is two files in `oracle-health/entries.d/`** (no shared table):
`<id>.conf` and `<id>.patch` (a unified diff, product or harness code, the SMALLEST
change that violates the invariant). The conf is `KEY=VALUE` lines, never evaluated
by a shell: `PKG`, `RUN` (the `go test -run` pattern: the seed or replay input),
`MARKERS` (` || `-separated fixed strings, all must appear in the failing output),
`MODULE_DIR` (`migrate` for that module), `NEEDS` (`none`, `pg`, `pg-superuser`),
`TARGET` + `REPLAY_GEN` (a script that writes extra corpus files into
`testdata/fuzz/<TARGET>/` of the copy, for an input too big to commit),
`PATCH` (share a patch between entries), `KNOWN_BLIND` (issue), `HEAVY=1`,
`KIND=selftest` + `CMD` (run an existing self-test as-is) and `VERIFIED` (free text:
when and how it was seen red). `entries.d/*.conf` are the registry; `--list` prints it.

**Adding an entry**: pick the invariant from the harness's own doc comment, write the
plant, run `go test` on the seed to see red, `git diff <file> > entries.d/<id>.patch`,
write the conf, run `oracle-health.sh --only <id>`. If the seed corpus is green on the
plant, the harness is blind (or the plant is not the invariant): replay a specific
input, and if only a generated input trips it, say so in the conf and open an issue.
If it cannot be planted deterministically in about 90 s, it is not an entry: list it
as a leftover with the reason. Two ways a plant turns out not to be one: it removes a
layer that another layer repeats (`internal/backupfmt` checks an entry name in three
places, so the plant drops all three), or it breaks the harness's own positive control
(a verifier that hashes a prefix rejects the genuine file too). A green result on such
a plant says nothing about the harness: try a sweep of generated inputs first, and only
call the harness blind when a plant that does violate the invariant stays green.
`KIND=selftest` entries wrap a planted-defect test that already lives in the package
(the defect is a stand-in inside the test, not a product patch): they show the family in
the registry and run the red-proof on the nightly host, nothing more. A green self-test
is `DETECTED` only when every `MARKERS` string (name each planted-defect test) is in
the log; without it it is `WRONG-MARKER`, and a green run in which any test logged
`--- SKIP` is `SKIP`, so a self-test whose inputs are missing cannot count as a
red-proof. Example: the Wycheproof AEAD/Ed25519/RSA plants need the git-ignored
vectors, so they are the HEAVY entry `wycheproof-planted-vectors`, which fetches them.

**Other repositories**: `--root DIR` points the runner at another git checkout (its own
`go.mod`, patches apply to that tree) and `--entries DIR` at another registry. The
DashDiag entries live in `oracle-health/dashdiag.d/`; run them with
`oracle-health.sh --root <dashdiag clone> --entries scripts/fuzzing/oracle-health/dashdiag.d`
(relative paths are resolved before the runner changes directory).
A harness behind a `//go:build linux` tag cannot run on a Mac: such an entry needs the
pve01 or e2e host.

Pure parts are tested by `bats oracle-health/tests`
(stubbed `go`). **Maintenance**: `PLANT-STALE` after a refactor means re-cut the patch;
`pg-upgrade-unlock-stop` depends on the number of write statements of the newest
upgrade source (the unlock is statement N+1): when it reports MISSED after a
migration step is added, probe `FuzzUpgradePGInterrupted` with the newest source index
and stops around the old window and move the window in its `.replay.sh`.

## CI layers

- **Weekly / per-PR**: see `.github/workflows/` (`fuzz*.yml`) — bounded
  regression fuzzing seeded from the committed corpus; deep discovery is the rig.
- **Drift guard**: `fuzz-targets` job — keeps `targets.d/` honest against the
  tree, and `targets.conf` honest against `targets.d/`.
