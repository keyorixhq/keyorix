# autofuzzgen — SAST-guided fuzz-harness lead generator

Decides **where** to point sound fuzz oracles, systematically, using static data-flow instead of
a human's memory. It does **not** find bugs itself; it closes the "we only fuzzed what we thought
of" gap and makes new-target creation cheap. Generated harnesses are **leads** — reviewed and
red-proofed like any hand-written harness, never auto-merged.

Versioned home for the tool that used to live in `.scratch/autofuzzgen.go` (gitignored). Carries a
`//go:build ignore` tag so it stays out of the module build; run it by naming the file.

## The pieces

1. **`.github/codeql/manual-queries/FuzzHarnessTargets.ql`** — the selector. A taint query that lists
   `source → sink` tuples where remotely-controlled input (`RemoteFlowSource`) reaches a dangerous
   sink, each tagged with a **sink kind**: `parser`, `authz`, `crypto`, `format`. The row message is
   `FUZZ-TARGET kind=<kind> fn=<enclosing-func> …`. It lives in `.github/codeql/manual-queries` and is run MANUALLY — it is deliberately NOT in the CI code-scanning pack, because it emits leads, not defects (running it in CI would flood the security dashboard with hundreds of non-actionable alerts).

2. **`main.go`** — the emitter. Two modes:
   - `-tuples <file.json>` (**SAST-guided, preferred**): consumes the query's tuples and emits one
     harness skeleton per lead, with the invariant family chosen by sink kind. Each skeleton has an
     auditable header naming the `source → sink` path it was chosen for.
   - `-root <dir>` (**signature-scan, fallback**): the original weak selector — every fuzzable
     exported func → a never-panic `FuzzAuto_<name>`. For quick sweeps with no taint list.

## Sink kind → invariant family

| sink kind | emitted oracle family |
|-----------|-----------------------|
| `parser`  | bounded-work + never-panic (decode time/alloc bounded vs input size) |
| `alloc`   | bounded-work (allocation bounded by, and validated against, the input) |
| `authz`   | fail-closed differential (an unauthorized principal must be denied) |
| `crypto`  | tamper / round-trip / key-commitment (the `FuzzAEADTamperRoundTrip` shape) |
| `format`  | injection (no control char, formula prefix `= + - @`, or forged audit/log line) |

## Triage loop

```
# 1. Run the query to a target list MANUALLY against a Go database (it is not part of the CI scan):
codeql database analyze <db> .github/codeql/manual-queries/FuzzHarnessTargets.ql --format=csv --output=targets.csv
#    …then project the result rows to the tuple JSON autofuzzgen consumes
#    (fields: package, dir, func, sinkKind, entryParam, source, sink).

# 2. Emit skeletons, ranked by sink kind:
go run scripts/fuzzing/autofuzzgen/main.go -tuples targets.json -out /tmp/afg

# 3. For each skeleton (emitted as .txt on purpose): review the source→sink path, fill the oracle
#    for its invariant family, red-proof it (weaken the code under test → the oracle must fire),
#    rename to <pkg>_<name>_fuzz_test.go in the target package.

# 4. Add a scripts/fuzzing/targets.conf row so the rig discovers it; open a PR (DCO -s, no attribution).
```

The model is a **lead generator**, never gating: an LLM's "looks wrong" never gates a finding, and
a generated harness is only trusted after a human red-proofs its oracle.

## Discipline

- The query is versioned in-repo but deliberately NOT run in CI (it lists leads, not defects, so it never creates code-scanning alerts); its selection is auditable (every skeleton records
  the `source → sink` path).
- Assert only the non-false-positing direction (deny / bounded / equality / reject), per the
  invariant-fuzzing playbook.
- Every landed target gets a `targets.conf` row and is scoped to keyorix's actual call path.
