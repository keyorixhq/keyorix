# js1 — Total Independent Fuzzing of santhosh-tekuri/jsonschema/v6

**Report location note:** The runtime-designated output path
`/mnt/data/wave4/out/js1-REPORT.md` is NOT writable from this sandboxed
session (writes outside the working directory are blocked). Per the runtime
rules' fallback, this report is kept committed on the branch at
`.scratch/js1-REPORT.md`.

**Temperature note:** `/sys/class/hwmon/hwmon2/temp1_input` is not readable
from this sandbox (path outside working dir is blocked by the tool guard).
All runs therefore rely on `nice -n 10`, `GOMAXPROCS=2` and `-parallel 2` to
bound load, as the rules permit.

Date: 2026-11-16. Branch: `fuzz/total-js1`. Module:
`github.com/santhosh-tekuri/jsonschema/v6`, go 1.27.4, offline (vendored deps,
`go.work` workspace with `./` and `./cmd/jv`).

## 1. Reading of the task

"Total independent fuzzing" = fuzz the whole *exported* API surface of the
library as a black box, not just the paths Keyorix/DashDiag happen to call.
Deliverable is upstream-ready: fuzz targets in the library's own style
(external `jsonschema_test` package, same as `example_test.go`), seed corpora,
minimised reproducers, and a ready-to-send issue/PR per real finding. No
production code changes except as separate, optional fix commits with
regression tests. I added targets in a single new file `fuzz_test.go` next to
the existing tests; there were no pre-existing `Fuzz*` functions in the library
(the only `func Fuzz` in the tree is in `vendor/.../dlclark/regexp2`, which is a
vendored dependency and out of scope).

The library's public entry points that consume untrusted input are:
`UnmarshalJSON(io.Reader)`, `Compiler.AddResource(url, any)` +
`Compiler.Compile(string)`, and `Schema.Validate(any)`, plus the option
methods (`DefaultDraft`, `AssertFormat`, `AssertContent`, `AssertVocabs`,
`UseRegexpEngine`, `UseLoader`, `Register*`) and the built-in format validators
(`format.go`) reachable through a `{"format":X}` schema. These are the fuzz
surface.

## 2. API coverage table

Legend for "fuzzed": Y = covered by a target in `fuzz_test.go`; N = not
(reason given). Oracle codes: A=no panic/hang/fatal, C=round-trip/idempotence,
D=determinism/no-mutation, O=output builders don't panic & marshal.

| Symbol | Input type | before | after | oracle |
|---|---|---|---|---|
| `UnmarshalJSON(io.Reader)` | bytes | N | Y (FuzzUnmarshalJSON) | A,C |
| `Compiler.AddResource(string, any)` | url + parsed doc | N | Y (FuzzCompile/FuzzValidate) | A |
| `Compiler.Compile(string)` | schema doc | N | Y (FuzzCompile/FuzzValidate) | A |
| `Compiler.MustCompile(string)` | schema doc | N | N — thin panic-wrapper over Compile (covered) | — |
| `Compiler.DefaultDraft(*Draft)` | option | N | Y (control byte, all 5 drafts) | A |
| `Compiler.AssertFormat()` | option | N | Y (control byte / FuzzFormats) | A |
| `Compiler.AssertContent()` | option | N | Y (control byte) | A |
| `Compiler.AssertVocabs()` | option | N | Y (control byte) | A |
| `Schema.Validate(any)` | instance | N | Y (FuzzValidate/FuzzFormats) | A,D |
| built-in formats (18) + regex | string | N | Y (FuzzFormats) | A,D |
| `ValidationError.Error/GoString` | — | N | Y (exerciseOutputs) | A,O |
| `ValidationError.FlagOutput/BasicOutput/DetailedOutput` | — | N | Y (exerciseOutputs) | A,O |
| `ValidationError.Localized*` | *message.Printer | N | N — localisation wrappers; see leftovers | — |
| `Compiler.RegisterFormat/ContentEncoding/ContentMediaType/Vocabulary` | config structs | N | N — require caller-supplied funcs; see leftovers | — |
| `Compiler.UseRegexpEngine(RegexpEngine)` | engine | N | N — default go engine exercised via `pattern`; custom regexp2 engine = leftover | — |
| `Compiler.UseLoader(URLLoader)` | loader | N | N — network/file loader; FileLoader.ToFile = leftover | — |
| `FileLoader.Load/ToFile`, `SchemeURLLoader.Load` | url string | N | N — filesystem/url; leftover | — |
| `Types.Add/IsEmpty/String/ToStrings` | string | N | N — small helpers; leftover | — |
| `LocalizableError(string, ...any)` | format | N | N — fmt wrapper; leftover | — |
| `CompilerContext`/`ValidatorContext`/`Vocabulary`/`SchemaExt` | custom-vocab API | N | N — require caller-supplied vocab impl; leftover | — |
| error types `*Error` | — | N | N — plain data/`Error()` string; low risk | — |

## 3. Targets and oracles (what each does NOT verify)

- **FuzzUnmarshalJSON** — arbitrary bytes into `UnmarshalJSON`. Oracle A + C
  (encode/decode/encode idempotence via `encoding/json`). Does NOT verify exact
  acceptance-agreement with `encoding/json` (UnmarshalJSON *is* a
  `json.Decoder` wrapper plus a trailing-data check, so agreement holds by
  construction except for trailing bytes), nor numeric canonicalisation beyond
  `json.Number`.
- **FuzzCompile** — arbitrary schema document + option matrix (control byte
  selecting draft and the three Assert* toggles). Oracle A. Does NOT verify
  semantic correctness of the compiled schema, nor bounded work.
- **FuzzValidate** — arbitrary schema + arbitrary instance + option matrix;
  compiles then validates. Oracle A + D (idempotent verdict, no input
  mutation) + O (output builders). Does NOT verify the *correctness* of the
  valid/invalid verdict (no reference implementation consulted), nor bounded
  work.
- **FuzzFormats** — arbitrary string validated against every built-in
  `{"format":X}` schema with assertion on. Oracle A + D. Does NOT verify the
  accept/reject decision against each format's RFC (no differential oracle).

**Red/green proof:** a scratch `redgreen_test.go` planted a defect for each
non-trivial guard (round-trip, mutation, determinism); all three produced
`--- FAIL` as required, then the file was removed (never committed). The
seed-corpus run (`go test -run Fuzz`) is green.

## 4. Findings

### Finding 1 — Unbounded recursion in `Schema.Validate` → fatal stack overflow on deeply-nested instances (HARDENING / potential DoS)

**Classification:** HARDENING (defense-in-depth); becomes a DoS **DEFECT** for
callers that validate data decoded by a non-depth-capped decoder (YAML, bson,
hand-built `any`). It is NOT reachable through the library's own JSON parser.

**What happens.** `Schema.Validate(any)` recurses structurally into the
instance (and sub-schemas) with no depth limit. On a sufficiently deeply
nested instance it exhausts the goroutine stack and the Go runtime aborts the
**process** with `fatal error: stack overflow`. This is unrecoverable — a
`defer/recover` cannot catch it — so any in-process `recover`-based guard a
caller might install is useless.

Observed (Go 1.27.4, 1 GB default max stack), schema
`{"$id":"mem://r","type":"array","items":{"$ref":"mem://r"}}`, instance = arrays
nested to depth D:

```
D=1000    OK
D=10000   OK
D=100000  OK
D=500000  fatal error: stack overflow   (process aborted)
```

**Reachability / honest scoping.** The library's own `UnmarshalJSON` is backed
by `encoding/json`, which caps nesting at 10000 ("exceeded max depth"), verified:

```
jsondepth=10000 err=<nil>
jsondepth=20000 err=exceeded max depth
```

So an attacker who can only supply **JSON bytes that the caller decodes with
`UnmarshalJSON`** cannot reach the overflow (≤10000 is safe). The exposure is
through the **public `Validate(any)` API** when the instance comes from a
decoder without a depth cap. This is realistic: OpenAPI / Kubernetes / config
tooling routinely validates **YAML**-sourced `map[string]any` (go-yaml has no
nesting limit) against a JSON Schema. The compiler path has the same shape for
hand-built schema documents passed to `AddResource(url, any)`, though schemas
are usually trusted.

The library already guards `$ref` **cycles** (`validator.go` `checkCycle`), but
not instance-data **depth**.

**Minimal reproducer (ready-to-send Go test):**

```go
func TestDeepInstanceStackOverflow(t *testing.T) {
	doc, _ := jsonschema.UnmarshalJSON(strings.NewReader(
		`{"$id":"mem://r","type":"array","items":{"$ref":"mem://r"}}`))
	c := jsonschema.NewCompiler()
	_ = c.AddResource("mem://r", doc)
	sch, _ := c.Compile("mem://r")

	var v any = []any{}
	for i := 0; i < 500000; i++ { // depth not reachable via UnmarshalJSON, but reachable via YAML/custom any
		v = []any{v}
	}
	_ = sch.Validate(v) // fatal error: stack overflow — process aborts
}
```

**Impact.** Denial of service (whole-process crash, not a catchable error) for
services that validate externally-sourced, non-JSON-decoded data of
attacker-controlled depth.

**Suggested fix (proposal; not committed as a production change per runtime
rules).** Introduce a configurable maximum validation/compilation depth with a
sane default (mirroring `encoding/json`'s 10000), and return a normal
`*ValidationError` / compile error when exceeded instead of recursing. Minimal
shape: thread a depth counter through `validator.validate` (and the compiler's
`compileValue`) and emit a new `ErrorKind` (e.g. `MaxDepthExceeded`) past the
limit. This keeps behaviour unchanged for all realistic inputs while turning an
unrecoverable crash into a catchable error. A regression test would assert that
`Validate` on a depth-`N+1` instance returns an error rather than crashing.

**Duplicate check:** not performed against the upstream issue tracker — this
environment has no network. The maintainer should search open/closed issues for
"stack overflow" / "recursion depth" before filing.

### Non-findings (checked, clean)

- **Concurrent `Schema.Validate` on a shared compiled schema**: run under
  `-race -count=3`, 16 goroutines × 2000 validations over mixed instances
  (with `patternProperties`, `if/then`, `uniqueItems`, `DetailedOutput`): **no
  data race, no fatal**. Confirms compiled schemas are safe for concurrent use.
- **Idempotence / no-mutation**: `Validate` never mutated its instance and
  always returned a stable verdict across ~15M executions.
- **Output builders** (`FlagOutput`/`BasicOutput`/`DetailedOutput`/`Error`/
  `GoString`) never panicked and always json-marshalled on invalid results.

## 5. Negative results (quantified)

All runs: `GOMAXPROCS=2`, `-parallel=2`, `nice -n 10`, Go 1.27.4, offline.
No crashers were produced by any target (no files written to
`testdata/fuzz/`). Per-target foreground wall time (each chunk = 540 s):

| Target | chunks × 540s | ~wall | approx execs | new crashers |
|---|---|---|---|---|
| FuzzValidate | 4 | ~36 min | ~15M (3.8M first chunk) | 0 |
| FuzzCompile | 2 | ~18 min | ~7M | 0 |
| FuzzFormats | 2 | ~18 min | ~4M | 0 |
| FuzzUnmarshalJSON | 2 | ~18 min | ~5M | 0 |
| **total** | **10** | **~90 min** | **~31M** | **0** |

Interpretation: across ~31M executions covering the compile+validate pipeline,
the JSON decoder, the full draft × Assert* option matrix, and all 18 built-in
formats + regex, the only defect surfaced was Finding 1 (reached by direct
API probing, not by byte-level fuzzing, because the byte path is depth-capped).
"No finding" for the fuzzers is thus quantified at ~31M execs / ~90 min.

## 6. Ranked leftovers (suggested minutes for vCD hosts)

1. **(RESOLVED into Finding 1)** Deep-recursion stack overflow via
   `Schema.Validate` on a hand-built deeply-nested `any` — investigated and
   confirmed; see §4 Finding 1. Remaining sub-work (~15 min): bisect the exact
   overflow depth per platform / GOMAXPROCS to quote a precise threshold.
2. **Custom regexp engine (regexp2, vendored)** via `UseRegexpEngine` +
   `pattern`/`patternProperties` — ReDoS surface differs from Go `regexp`
   (backtracking). ~20 min.
3. **Custom vocabulary / `SchemaExt` / `ValidatorContext` API** — fuzz a
   user-supplied vocab that calls `ctx.Duplicates/Equals/Validate`. ~30 min.
4. **`FileLoader.ToFile` / `SchemeURLLoader.Load` / `absolute()` URL parsing**
   — fuzz URL strings for panics in path/url handling (Windows drive logic).
   ~20 min.
5. **`Localized*Output` with a real `message.Printer`** — ~15 min.
6. **Bounded-work oracle (alloc/time super-linearity)** — add an
   AllocsPerRun/MemStats harness on doubling-size inputs for Compile and
   Validate. ~30 min.

## Appendix: environment / commands

Fuzz chunks run as:
`env GOCACHE=... GOMODCACHE=... TMPDIR=... GOMAXPROCS=2 nice -n 10 go test
-run=^$ -fuzz=FuzzX -fuzztime=540s -parallel=2 .`
