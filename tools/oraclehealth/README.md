# oraclehealth

A fuzzer that never fails proves nothing. `oraclehealth` measures whether a Go
fuzz target's **oracle** can actually catch defects: it plants small mutants in
the code under test, runs the fuzz target against each mutant for a fixed time
budget, and records whether the mutant was **KILLED** (the oracle caught it) or
**SURVIVED** (an oracle hole). A high survival rate means the fuzzer is running
but not really checking anything.

It is **stdlib-only** and imports no project-internal packages, so it runs on
any Go module checkout — Keyorix packages or an external library.

## How it works

1. **Mutate** (`mutate.go`). The code under test is parsed with `go/ast` and a
   set of security-relevant mutation operators is applied, one at a time:

   | operator | change | the defect it models |
   |----------|--------|----------------------|
   | `cmp-*`  | `<`↔`<=`, `>`↔`>=`, `==`↔`!=` | off-by-one / inverted bound |
   | `logic-and-to-or`, `logic-or-to-and` | `&&`↔`\|\|` | widened/narrowed predicate |
   | `negate-cond` | `if c` → `if !(c)` | inverted guard |
   | `drop-error-guard` | `if … { return err }` → `{}` | dropped early-exit/error check |
   | `bound-const` | integer literal → `v+1`, `0` | moved/disabled threshold |
   | `skip-constant-compare` | `bytes.Equal(a,b)`→`true`, `subtle.ConstantTimeCompare(a,b)`→`1`, `hmac.Equal(a,b)`→`true` | skipped authentication / tamper check |

   Only non-test, non-`// Code generated … DO NOT EDIT.` files are mutated.
   A function allow-list (`-funcs`) restricts mutation to the code the target
   actually exercises, so the kill-rate is not diluted by out-of-scope files.

2. **Isolate** (`copy.go`). The module is copied once into a scratch directory
   (skipping `.git`, `node_modules`). **The real checkout is never edited** — each
   mutant is written into the copy, run, then the file is restored before the next.

3. **Run & classify** (`runner.go`). For each mutant the package is recompiled and
   the named fuzz target is run as `go test -run=^$ -fuzz=^Target$ -fuzztime=<N>`
   under `nice` with `-parallel=2` / `GOMAXPROCS=2`. `-run=^$` means **only** the
   fuzz oracle runs — ordinary unit tests are skipped, so a KILL is attributable to
   the fuzz oracle and nothing else. Verdicts:

   - **KILLED** — the target failed (seed corpus or a generated input caught it).
   - **SURVIVED** — the target stayed green for the whole budget: an oracle hole.
   - **EQUIVALENT-SUSPECTED** — (with `-equiv`) survived *and* the mutated line is
     never executed by the package's own unit suite, so the mutant is plausibly
     behaviour-equivalent / dead rather than a true hole.
   - **TIMEOUT** — the run exceeded its wall budget without a verdict.
   - **BUILD-FAIL** — the mutant did not compile; discarded, never counted as killed.

   Any crasher the fuzzer writes to `testdata/fuzz/<Target>/` during one mutant run
   is removed before the next, so mutants are measured independently.

   Before mutating, the **baseline** (unmutated) target is run; a non-green
   baseline aborts that target (a kill would be meaningless).

## Usage

```
go run ./tools/oraclehealth \
    -src .                               # module root to copy (or -module <prepared copy>)
    -work /path/to/scratch/copy          # where to copy it (reusable across runs)
    -pkg internal/netutil                # package under test, module-relative
    -targets FuzzIPv4EmbeddingSSRFParity # comma-separated fuzz target names
    -funcs IsPrivateOrLinkLocal,embeddedIPv4   # optional function allow-list
    -fuzztime 15s -max 10 -seed 1 \
    -out run.json
```

Copy once, reuse across targets in the same module:

```
go run ./tools/oraclehealth -src . -work $TMP/copy -pkg internal/netutil -targets FuzzA ...
go run ./tools/oraclehealth -module $TMP/copy       -pkg internal/backupfmt -targets FuzzB ...
```

For an external library, point `-src` at its checkout (copied to scratch; the
cache is never modified) and name its own `Fuzz*` target.

Output: a Markdown table on stdout plus, with `-out`, a JSON report
(`target, mutants, killed, survived, kill_rate, survivors[]` with `file:line`
and the exact mutation).

## What the kill-rate does and does not mean

- A **survivor** is not automatically a bug. It is one of: an **oracle hole** (the
  target should assert something it doesn't — the fix is a seed or a stronger
  assertion), an **equivalent mutant** (the change cannot alter observable
  behaviour), or **dead/unreachable code**. `oraclehealth` flags survivors; a human
  decides which, and that judgement belongs in the run's write-up.
- A **high kill-rate** means the oracle is sensitive to the mutations *tried on the
  functions tried* — not that the target is complete. Mutation testing can only
  refute "this oracle is weak"; it cannot prove "this oracle is strong".

## The equivalent/dead allowlist

A survivor is not always a hole: it can be an **equivalent** mutant (the change
cannot alter observable behaviour) or **dead** code the target never reaches. Re-
reporting those on every run buries the real holes. `-allowlist <file.tsv>`
reclassifies a known survivor as **ALLOWLISTED** and drops it from the kill-rate
denominator (same treatment as `BUILD-FAIL`), so the rate measures genuine oracle
holes only.

The committed list is `oracle-health-allowlist.tsv`. Columns (tab-separated):

```
target   file   func   op   orig   new   class   reason
```

- `class` is `equivalent` or `dead` (anything else is a load error).
- `reason` must name the code that makes the mutant unobservable — an empty reason
  is a load error. This is the honesty contract: an allowlist entry is a claim, and
  the claim has to point at the masking mechanism.
- The match key is `(target, file, func, op, orig, new)` with whitespace collapsed,
  **not** the line number. An entry keeps matching when the construct moves to a new
  line, and stops matching — failing safe, re-reporting the survivor — only when the
  mutated construct itself changes. A multi-line guard body is written on one line in
  the TSV; the collapse makes it match the real (indented, multi-line) source.

Keep it small and honest: every entry is a survivor a human has traced to a specific
masking mechanism, not a convenient silence.

## Repeatable run + baseline regression check

`scripts/fuzzing/oracle-health.sh` makes the measurement repeatable. It runs the tool
over the fixed target list in `scripts/fuzzing/oracle-health-baseline.tsv` (which is
both the run manifest — target, package, funcs, budget — and the per-target kill-rate
floor), each target against this package's allowlist, then compares via `-compare` and
**exits non-zero** if any target's kill-rate is below `kill_rate - tolerance`, or if a
baseline target is missing from the run.

```
scripts/fuzzing/oracle-health.sh            # run + compare (exit 1 on regression)
scripts/fuzzing/oracle-health.sh --record   # re-measure and rewrite the baseline rates
```

- **Runtime (pve01, `nice -n 10`, `GOMAXPROCS=2`, `-parallel 2`, serial mutants):** the
  three targets at `fuzztime=15s / max=10` plus the one module copy measured **~137 s
  (~2.3 min)** wall with a warm build cache — killed mutants fail on the seed corpus in
  a second or two, so only the allowlisted/surviving mutants spend the full budget. A
  cold cache adds the one-time package+dependency compile (upper bound ~10 min). Either
  way it fits comfortably in one nightly slot.
- **Not wired into CI** on purpose: it recompiles a package per mutant and fuzzes each,
  far too heavy for the per-PR path. Run it nightly or on demand. The comparison logic
  is unit-tested (`baseline_test.go`: a baseline above the measured value fails, equal
  passes); `oracle-health.sh` itself is the nightly driver.

## The tool's own red/green proof

`mutate_test.go` + `testdata/toy/` are the committed proof that the tool measures
what it claims. The `toy` module has one function (`Max`) and two oracles over it:
`FuzzWeak` (asserts only that the result is one of the inputs) and `FuzzStrong`
(checks against an independent reference). The behaviour-changing `negate-cond`
mutant (which turns `Max` into `min`) **must** be reported **SURVIVED** by the weak
oracle and **KILLED** by the strong one. `TestOracleHealth_RedProof` asserts exactly
that asymmetry; if the tool could not tell the two oracles apart, that test fails.
`TestCollectMutations_ToyOperators` is a fast, fuzz-free check of the mutator itself.
