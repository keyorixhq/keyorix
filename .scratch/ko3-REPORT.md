# KO3 — kin-openapi FULL-DOCUMENT loader fuzzing

**Report location.** `/mnt/data/wave4/out/` is not writable from this sandbox (writes
outside the working tree are blocked, same as KO1). Per the runtime fallback rule this
report lives at `.scratch/ko3-REPORT.md`, committed on branch
`fuzz/ko3-kinopenapi-loader` (`.scratch` is gitignored → added with `git add -f`).

**Temperature.** `/sys/class/hwmon/hwmon2/temp1_input` is not readable from this sandbox
(path outside the working dir is blocked even read-only). Thermal safeguard is instead
`nice -n 10`, `GOMAXPROCS=2`, `-parallel 2` on every build and fuzz run.

**Most-reasonable-reading (stated, no questions asked).** KO3 is leftover #1 from the KO1
report: a fuzzer for the kin-openapi FULL-DOCUMENT loader (`openapi3.Loader`:
`LoadFromData` / `ResolveRefsIn` / `doc.Validate`), distinct from the existing
`FuzzOpenAPISchemaBoundedWork` which decodes STANDALONE schemas and never resolves `$ref`.
The new surface is: recursive / circular `$ref` graphs, deep nesting, many refs, external
refs under `IsExternalRefsAllowed=false`, extension fields, duplicate/colliding names. I do
NOT touch production code.

---

## Reachability (traced; honest)

In EVERY live Keyorix caller the document loaded by `openapi3.Loader` is the trusted,
committed `server/http/handlers/openapi.yaml`, embedded at build time (`//go:embed`,
`server/http/handlers/swagger.go`) and loaded once per process:

- `server/http/handlers/contracttest/spec.go:43-48` — `NewLoader().LoadFromFile(path)` +
  `doc.Validate`, production code but called ONLY from test code (`AssertOpenAPIResponse`),
  path hardcoded to the committed `openapi.yaml`.
- `server/http/openapi_stateful_fuzz_test.go`, `server/http/handlers/*_test.go`,
  `contracttest/{harness,checks_internal}_test.go` — all `_test.go`; bytes are either the
  trusted `openapi.yaml` or test-authored synthetic specs.
- No CLI `migrate`, SDK-gen, or request-time path loads a user-supplied spec.
  `cli/internal/migrate` migrates config files (no openapi3). `/openapi.yaml` is served
  GET-only from the build-time embed; there is no POST/PUT that ingests a spec.
- No call to `ResolveRefsIn` or `openapi3gen` anywhere in the tree.

**Verdict: attacker-controlled bytes never reach the full-document loader in production.**
So every finding here is a LIBRARY property — classified HARDENING / CANDIDATE and labelled
**not attacker-reachable** unless a concrete live path is traced. The target exists to catch
a dependency-bump regression in the loader robustness the trusted callers assume (a
recursion panic, an amplification, a serialization drift, or — most security-relevant — a
regression that lets `IsExternalRefsAllowed=false` fail open into a file read / SSRF).

Confirmed library security contract (kin-openapi v0.153.0, empirically probed):
`IsExternalRefsAllowed` is enforced **only when `ReadFromURIFunc` is nil**; a custom
`ReadFromURIFunc` bypasses the flag and owns the access policy. With the default loader
(`NewLoader()`, nil func, flag false) an external `$ref` is **refused before any read**
(`encountered disallowed external reference`). Keyorix uses exactly this default.

---

## Deliverables

(status filled in as work lands — see Result summary)

| Target | Fuzz func | Config | Oracles |
|---|---|---|---|
| Document loader bounded-work / round-trip | `FuzzOpenAPIDocumentLoader` | B: custom refusing `ReadFromURIFunc` (drives ref machinery, zero IO) | O-LOAD-1/2/3/5 |
| External-ref air-gap | `FuzzOpenAPILoaderNoExternalRead` | A: default loader, `IsExternalRefsAllowed=false` (Keyorix-faithful) | O-LOAD-1/2/4 |
| (interleaved, existing) standalone schema | `FuzzOpenAPISchemaBoundedWork` | — | O-KIN-1/2/3 |

---

## Oracles (what each does / does NOT verify)

- **O-LOAD-1 no panic** — `LoadFromData` → `ResolveRefsIn` → `Validate` →
  `MarshalJSON` must not panic on any document (recorded natively).
- **O-LOAD-2 bounded work** — the whole load pipeline runs inside `fuzzutil.Guard`
  (3 s hang/amplification watchdog, FATAL) and is metered by `resguard`
  (alloc_bytes/mallocs FATAL vs a calibrated ceiling; wall/cpu advisory), plus an
  O-LOAD-2b superlinear-wall ceiling below the Guard deadline.
- **O-LOAD-3 load→marshal→load idempotence** — for a document the loader accepts,
  `MarshalJSON` → `LoadFromData` → `MarshalJSON` is byte-stable. FATAL.
- **O-LOAD-4 external refs never read when disallowed** — under the Keyorix-faithful
  default (nil func, flag false), injected hostile external refs (a loopback httptest
  server with a hit counter, a `file://` canary, and a `169.254.169.254` SSRF canary)
  are NEVER read: hostile-server hits == 0, NetMeter non-loopback dials == 0, and the
  injected external SchemaRefs remain unresolved (`.Value == nil`). FATAL.
- **O-LOAD-5 resolved-vs-JSON-round-trip differential** — the loader-resolved document
  marshals identically to the same document after a plain `json` round trip (ref
  resolution is marshal-transparent). FATAL.

### What the oracles do NOT verify
*(finalised in the last report pass; placeholder)*

---

## Result summary

*(filled in after the fuzz chunks run)*

---

## LEFTOVERS

*(ranked list filled in at the end)*
