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
See the dedicated **"What the oracles do NOT verify"** section below (after Findings).

---

## Result summary (final)

**No findings on the two KO3 loader targets (no VULNERABILITY / CANDIDATE / DEFECT).**
One **ARTIFACT** (a too-tight calibration false-trip) surfaced on the *interleaved,
pre-existing* `FuzzOpenAPISchemaBoundedWork` target — not a library or Keyorix defect; see
Findings. All runs `GOMAXPROCS=2`, `-parallel 2`, `nice -n 10`.

| # | Target | execs | Crashers | Verdict |
|---|---|---|---|---|
| 1 | FuzzOpenAPIDocumentLoader | 489,562 | 0 | PASS |
| 2 | FuzzOpenAPILoaderNoExternalRead | ~200k | 0 | PASS |
| 3 | FuzzOpenAPIDocumentLoader | 362,702 | 0 | PASS |
| 4 | FuzzOpenAPILoaderNoExternalRead | 404,229 | 0 | PASS |
| 5 | FuzzOpenAPISchemaBoundedWork (interleaved) | 2,293,277 | 0 | PASS |
| 6 | FuzzOpenAPIDocumentLoader | 258,437 | 0 | PASS |
| 7 | FuzzOpenAPILoaderNoExternalRead | 213,380 | 0 | PASS |
| 8 | FuzzOpenAPIDocumentLoader | 414,291 | 0 | PASS |
| 9 | FuzzOpenAPILoaderNoExternalRead | 93,852 | 0 | PASS |
| 10 | FuzzOpenAPIDocumentLoader | 176,390 | 0 | PASS |
| 11 | FuzzOpenAPILoaderNoExternalRead | 166,081 | 0 | PASS |
| 12 | FuzzOpenAPIDocumentLoader | 176,709 | 0 | PASS |
| 13 | FuzzOpenAPILoaderNoExternalRead | 198,011 | 0 | PASS |
| 14 | FuzzOpenAPIDocumentLoader | 342,402 | 0 | PASS |
| 15 | FuzzOpenAPISchemaBoundedWork (interleaved) | 759,803 | 1 (ARTIFACT) | FAIL→artifact |
| 16 | FuzzOpenAPIDocumentLoader | 282,765 | 0 | PASS |
| 17 | FuzzOpenAPILoaderNoExternalRead | 275,461 | 0 | PASS |
| 18 | FuzzOpenAPIDocumentLoader | 250,441 | 0 | PASS |
| 19 | FuzzOpenAPILoaderNoExternalRead | 228,465 | 0 | PASS |
| 20 | FuzzOpenAPIDocumentLoader | 536,857 | 0 | PASS |
| 21 | FuzzOpenAPILoaderNoExternalRead | 1,116,096 | 0 | PASS |
| 22 | FuzzOpenAPIDocumentLoader | 630,306 | 0 | PASS |

**Measured real fuzz wall time ≈ 197 min** (21 full 540 s chunks + chunk 15's 450 s
before it saved the artifact): FuzzOpenAPIDocumentLoader 11×541 s ≈ 99 min,
FuzzOpenAPILoaderNoExternalRead 9×541 s ≈ 81 min (= **180 min on the two KO3 targets**),
FuzzOpenAPISchemaBoundedWork 541 s + 450 s ≈ 17 min interleaved. Smoke runs (2×30 s) not
counted.

The document-loader target runs fewer execs/sec than the schema target because
`LoadFromData` resolves the whole ref graph (much heavier per input); the `0/sec` tail on
some chunks is the Go engine minimising the large corpus under `GOMAXPROCS=2` — an
ARTIFACT (same as KO1), not a per-input library cost.

---

## Findings

### F1 — ARTIFACT: mallocs-ceiling false-trip on the (pre-existing) schema target

**Not a KO3-target finding, not a library defect, not Keyorix-reachable.** Surfaced when
chunk 15 interleaved the existing KO1 `FuzzOpenAPISchemaBoundedWork` target.

- **Input** (minimised by the engine to 786 effective bytes, preserved at
  `.scratch/ko3-artifact-schema-mallocs-crasher.txt`): a 64-deep nested `allOf` chain
  `{"allOf":[{"allOf":[…{"type":"obect"}…]}]}` — the SAME shape as the committed seed
  `nestedAllOf(64)`, with instance `{}`.
- **Signal:** `RESGUARD kin_visitjson: input=786 bytes mallocs≈1106–1122 budget=1070
  amp=1.0x`, elapsed ≈ 1 ms. Deterministic across 3 replays.
- **Why ARTIFACT, not DEFECT:** `amp=1.0x` and ≈ 1 ms mean the work is LINEAR in input
  size — no amplification, no hang. The `mallocs` slope in
  `testdata/resguard-kinopenapi.json` (`per_byte=0.32`, giving ceiling
  `4·(16+0.32·786)=1070`) was calibrated on malloc-light Keyorix-shaped schemas; a
  composition-dense but still linear deep-`allOf` schema allocates ≈ 1.4 mallocs/byte, so
  it overshoots a ceiling built for ≈ 0.32/byte by ≈ 4 %. An amplification oracle must by
  definition NOT fire on a 1.0× linear input — this is a calibration gap in the KO1
  harness, exposed (not caused) by KO3.
- **Scope decision:** the KO1 schema budget is a **separate deliverable with a deliberate
  design choice** (`benignKinCosts` intentionally excludes the deep-nesting probes so the
  budget would "flag" them — but a deep-`allOf` chain is linear, not an explosion, so
  flagging it is spurious). I did **not** silently edit KO1's committed budget inside the
  KO3 branch. The false-positive crasher was **removed from `testdata/fuzz/`** (so
  `go test` stays green) and preserved in `.scratch/`. Issue-ready proposal in LEFTOVERS #1.
- **Why the two KO3 loader targets did NOT hit the analogous trip:** their budget
  (`resguard-kinloader.json`) was calibrated with composition/ref-dense shapes in the
  benign set (`deepAllOfInComponent(32)`, `manyRefsFanout(32)`, `recursiveSelfRef`,
  `mutualRecursion`, `pathItemRefs`), so the slope already reflects ref-dense-but-linear
  allocation. 180 min of fuzzing produced zero loader trips.

### Loader targets

**None.** No panic (O-LOAD-1), no bounded-work breach (O-LOAD-2/2b), no idempotence drift
(O-LOAD-3), no external read under `IsExternalRefsAllowed=false` (O-LOAD-4), no
resolved-vs-round-trip differential (O-LOAD-5), over ≈ 5.8 M document-loader execs and
≈ 2.9 M air-gap execs. The kin-openapi v0.153.0 loader is robust on recursive / circular /
deep / high-fan-out `$ref` graphs within the 16 KiB bound, and the
`IsExternalRefsAllowed=false` default held against every fuzzed document shape — no file
read, no dial, no SSRF. No production change is proposed.

---

## What the oracles do NOT verify

- **O-LOAD-1/2 (no panic / bounded work)** — nothing about documents > 16 KiB, and not a
  true superlinear bug that only manifests above that bound or slower than ≈ 2.5 s. Not
  behaviour under the race detector (runs were native; Guard scales its deadline under
  `-race` but these chunks did not use it). The alloc/mallocs ceiling is a *slope* model;
  a defect that stays within `factor·(floor+perByte·N)` is invisible (by design — that is
  the "no amplification" definition).
- **O-LOAD-3 (idempotence)** — only kin's own `MarshalJSON` fixed point, NOT semantic
  document equality; two differently-ordered-but-equivalent documents are not compared,
  and a document kin *rejects* is not exercised past the rejection.
- **O-LOAD-4 (external-ref air-gap)** — verifies the **default** posture (nil
  `ReadFromURIFunc`, flag false) that Keyorix uses. It does **NOT** verify the safety of a
  *custom* `ReadFromURIFunc` policy: kin v0.153.0 bypasses the flag entirely when a custom
  func is set, so a hand-rolled reader that forwards to `DefaultReadFromURI` WOULD read
  files / SSRF even with the flag false — that is the library's documented foot-gun, and
  it is out of scope here because Keyorix sets no custom func. It also does not verify
  `LoadFromFile` / `LoadFromURI` *base-path* resolution (the harness drives `LoadFromData`
  with no base location), nor refs smuggled through `JoinFunc` (unused by Keyorix). File
  reads are detected via `SchemaRef.Value`/the disallowed-ref error and the net air-gap;
  there is no OS-level open() hook, so a read that left `.Value==nil` AND bypassed the
  transport would be invisible (no such path exists under the flag, confirmed by the
  red/green).
- **O-LOAD-5 (differential)** — compares the loader-resolved marshal to a *plain-json*
  round-trip marshal of the same `*T`; it does not compare against an independent OpenAPI
  parser, and it cannot see a divergence that both paths share.
- **Across all oracles** — nothing with an **attacker-controlled document in a live
  Keyorix caller**, because none exists (the whole reachability caveat). Every finding
  would be LIBRARY hardening. Not tested: YAML-specific loader paths (the harness feeds
  JSON, which is a strict YAML subset kin accepts via the same decoder), OpenAPI 3.1-only
  constructs beyond what the seeds carry, and `IncludeOrigin=true` (off here).

---

## LEFTOVERS (ranked; suggested effort)

1. **Re-calibrate the KO1 `FuzzOpenAPISchemaBoundedWork` mallocs budget (or move it to a
   true-amplification mode) — 30 min.** Issue-ready: a deep-`allOf` chain is LINEAR in
   bytes (amp=1.0×), so the current `mallocs` slope (calibrated only on malloc-light
   schemas, `per_byte=0.32`) false-trips it. Fix options: (a) add one composition-dense
   but benign shape to `benignKinCosts` and regenerate `resguard-kinopenapi.json`; or
   (b) switch the `mallocs` meter to `UseAbsolute`/raise `factor` so the oracle fires only
   on genuine super-linear amplification (amp ≫ factor), which is what it is *named* for.
   Do this in a KO1 follow-up, not folded into KO3. Evidence:
   `.scratch/ko3-artifact-schema-mallocs-crasher.txt`.
2. **`ReadFromURIFunc`-custom-policy air-gap target — 60 min.** The real foot-gun in
   kin v0.153.0 is that a *custom* `ReadFromURIFunc` bypasses `IsExternalRefsAllowed`. A
   target that installs a *forwarding-to-DefaultReadFromURI* reader (the insecure pattern)
   and asserts it DOES read — then a *correctly-allowlisting* reader and asserts it does
   NOT — would pin the library contract and give Keyorix a red/green guard the day anyone
   adds a custom reader. Currently HARDENING (Keyorix sets no custom func).
3. **`LoadFromFile` / `LoadFromURI` base-path + relative-`$ref` fuzzing with a real
   on-disk multi-file spec tree — 90 min.** This harness drives `LoadFromData` (no base
   location), so relative external refs (`$ref: "./common.yaml#/..."`) and `JoinFunc`
   path-joining are untested. A staging-dir harness with a canary file *outside* the tree
   and `IsExternalRefsAllowed=true` would fuzz the path-traversal surface (`$ref:
   "../../../etc/passwd"`) that the disallowed-false default never reaches.
4. **YAML-document loader pass — 45 min.** Keyorix's real spec is YAML; this harness feeds
   JSON (a YAML subset). A YAML-bytes target (anchors/aliases `&a *a`, which are a
   recursion/amplification vector the JSON path cannot express — the "billion laughs"
   analogue) is a distinct surface worth a short metered pass.
5. **Lift the 16 KiB bound and `GOMAXPROCS` on a dedicated host, corpus reset — 60 min.**
   Same leftover KO1 noted: re-check for a superlinear loader bug that only appears above
   16 KiB or slower than 2.5 s, clearing the corpus first to avoid engine-minimisation
   stalls.
6. **`doc.Validate` as a *first-class* oracle — 45 min.** Here `Validate`'s verdict is not
   asserted (a hostile doc may be legitimately invalid); a differential of `Validate`
   against an independent OpenAPI validator (or a round-trip-then-revalidate stability
   check) would turn it from "must not panic" into a conformance oracle.

---

## Reproduce

```
cd /mnt/data/wave4/ko3
env GOCACHE=/mnt/data/wave4/gocache GOMODCACHE=/mnt/data/wave4/gomod TMPDIR=/mnt/data/wave4/tmp \
  GOFLAGS= GOMAXPROCS=2 nice -n 10 go test ./fuzz/thirdparty/kinopenapi/ -count=1   # guards + red/green
env ... go test ./fuzz/thirdparty/kinopenapi/ -run '^$' -fuzz '^FuzzOpenAPIDocumentLoader$'      -fuzztime 540s -parallel 2
env ... go test ./fuzz/thirdparty/kinopenapi/ -run '^$' -fuzz '^FuzzOpenAPILoaderNoExternalRead$' -fuzztime 540s -parallel 2
env ... RESGUARD_CALIBRATE=1 go test ./fuzz/thirdparty/kinopenapi/ -run TestLoaderCalibrate       # regenerate the loader budget
```

---

## LEFTOVERS

*(ranked list filled in at the end)*
