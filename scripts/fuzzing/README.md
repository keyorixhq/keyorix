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

- **`targets.conf`** — the hand-maintained canonical list of this repo's fuzz
  targets. The CI `fuzz-targets` drift-guard (`.github/workflows/ci.yml`) fails
  a PR if a real `func FuzzXxx` is missing from it or a declared target no
  longer exists in the tree. The rig discovers targets dynamically; this list
  is the human cross-check that nothing silently drops out of coverage.
- **`race-pass.sh`** — runs the fuzz corpus under `-race` (needs cgo; dev/CI
  only, since the rigs are `CGO_ENABLED=0`). Backs the data-race closure (#1870).
- **`harness-acceptance.sh`** — reach-check + coverage-delta gate for *in-wall*
  harnesses (see below).
- **`DISCLOSURE-TRIAGE.md`** — the crash-feasibility gate a third-party-library
  finding must pass before it becomes a disclosure or an article sentence.

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

## CI layers

- **Weekly / per-PR**: see `.github/workflows/` (`fuzz*.yml`) — bounded
  regression fuzzing seeded from the committed corpus; deep discovery is the rig.
- **Drift guard**: `fuzz-targets` job — keeps `targets.conf` honest against the tree.
