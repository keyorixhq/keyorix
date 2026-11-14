# sinkmap — sink-guided fuzz targeting

`sinkmap` lists dangerous **sink** call sites in the root module, classifies
each one, and ranks the ones not yet exercised by a fuzz target. It answers a
single operational question: *where should the next fuzz harness point?*

It is a **targeting** tool, not a scanner: a row never asserts a bug. It is
fully offline and deterministic — `go/parser` + `go/ast` only, no network, no
external SAST service, no timestamps, no models.

## Sink kinds

| kind | matched call shapes |
|------|---------------------|
| `exec` | `os/exec.Command`/`CommandContext` (flagged shell-ish when the program is `sh`/`bash` with `-c`) |
| `sql` | `Exec`/`Query`/`QueryRow`(`Context`)/`Prepare` with a **non-literal** query string (stronger note when built by `fmt.Sprintf`) |
| `net-out` | `http.NewRequest*` with a variable URL, `http.Get/Post/Head/PostForm`, `net.Dial*`, and `.Do(req)` (likely `http.Client.Do`) |
| `fs-path` | `os`/`ioutil` path funcs (`Open`,`Create`,`OpenFile`,`ReadFile`,`WriteFile`,`Rename`,`RemoveAll`,…) and `filepath.Join` with a variable component |
| `deserialize` | `json`/`yaml`/`xml` `Unmarshal` |
| `template-regexp` | `regexp.Compile*`/`MustCompile*` and `.Parse`/`ParseFiles`/`ParseGlob` with a variable argument |
| `crypto-compare` | `==`/`!=` on an operand named like a credential (`token`,`secret`,`mac`,`hmac`,`hash`,`password`,`signature`,…) |

## Per-sink columns

- **enclosing_func** — the nearest enclosing function (`pkg.Func` or `pkg.(Recv).Method`).
- **api_reachable** — a name-based static call graph connects an exported
  function in an entry package (`server/http`, `server/grpc`,
  `server/middleware`, `internal/backupfmt`, `internal/config`) to the
  enclosing function. The CLI is a separate module (`cli/go.mod`) and out of
  scope; the archive loader + config parser stand in for the parser-entry class.
- **fuzz_covered** — the enclosing function is within **two** call hops
  downstream of a `FuzzXxx` target.
- **product** — `false` for dev/CI tooling under `scripts/` and `tools/`.

## Usage

```
go run ./scripts/fuzzing/sinkmap -tsv scripts/fuzzing/sinkmap/SINKS.tsv -md out.md
go run ./scripts/fuzzing/sinkmap -check     # fail if SINKS.tsv is stale
go run ./scripts/fuzzing/sinkmap -stdout    # print the Markdown summary
```

`SINKS.tsv` is the committed machine-readable table; `-check` fails if it has
drifted from a fresh scan.

## What it does NOT verify

The call graph resolves package-qualified calls precisely but falls back to
**name-based** resolution for method calls on values (no `go/types`), so:

- `api_reachable=yes` is a conservative **over**-approximation (good for a
  targeting tool — it widens the candidate set rather than hiding a gap).
- `fuzz_covered=yes` can therefore be **over-claimed**, which means the true
  *uncovered* set is a **superset** of what is listed uncovered. Top
  candidates must be hand-verified before any claim is made about them.
- It never proves a sink is reachable with attacker-*controlled* data, only
  that a syntactic path exists.
- Type-dependent distinctions are not resolved: the `http.Client.Do` receiver,
  the `Unmarshal` target type (`interface{}` vs a concrete struct), and
  `[]byte`-vs-`string` in a compare. The matcher states this in the Detail
  column instead of guessing.
- Sinks in package-level `var` initialisers (outside any function body) are
  not listed.
