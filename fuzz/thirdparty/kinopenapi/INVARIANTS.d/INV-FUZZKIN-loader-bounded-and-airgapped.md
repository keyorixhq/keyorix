- **INV-FUZZKIN-loader-bounded-and-airgapped** kin-openapi's FULL-DOCUMENT loader —
  `openapi3.Loader.LoadFromData` (parse + `$ref` resolve) → `doc.Validate` →
  `MarshalJSON` — must, on any document within the harness bound (<= 16 KiB), (1) not
  panic or stack-overflow on recursive / circular / mutually-recursive / deep-chain
  internal `$ref` graphs, deep `allOf` nesting, large ref fan-out, extension (`x-*`)
  fields, or duplicate/colliding component names; (2) do bounded work (no hang, no
  alloc/mallocs amplification above the calibrated `testdata/resguard-kinloader.json`
  ceiling, no >2.5 s wall); (3) round-trip idempotently — a document the loader accepts
  satisfies `MarshalJSON`→`LoadFromData`→`MarshalJSON` byte-stability AND marshals
  identically to the same `*T` after a plain `json` round trip (ref resolution is
  marshal-transparent); and (4) — the security-relevant one — under the Keyorix-faithful
  DEFAULT loader (`NewLoader()`, nil `ReadFromURIFunc`, `IsExternalRefsAllowed=false`)
  NEVER read an external reference: no fuzzed document shape makes it contact a hostile
  loopback HTTP server, dial any address, or resolve a `file://` / SSRF `$ref`
  (`SchemaRef.Value` stays nil). Why: Keyorix only ever feeds this loader the trusted
  committed `server/http/handlers/openapi.yaml` (build-time `//go:embed`), never
  attacker-controlled bytes, so this is LIBRARY HARDENING (not attacker-reachable) — but
  a dependency bump that introduced a recursion panic, a ref amplification, a
  serialization drift, or (most important) a regression letting `IsExternalRefsAllowed=
  false` fail open into a local file read / SSRF would silently weaken `contracttest`,
  the OpenAPI stateful fuzzer, and anyone who later loads a less-trusted spec. kin
  v0.153.0 enforces the flag ONLY when `ReadFromURIFunc` is nil; a custom func bypasses
  it and owns policy (confirmed empirically). Guard: `FuzzOpenAPIDocumentLoader`
  (O-LOAD-1/2/2b/3/5, Config B custom refusing reader) and
  `FuzzOpenAPILoaderNoExternalRead` (O-LOAD-1/2/4, Config A default loader + NetMeter
  air-gap + hostile httptest server) with deterministic replay `TestLoaderSeeds_NoPanic`;
  the budget and marshal detectors are red/green-proven in `TestLoaderOracles_RedGreen`,
  the air-gap detector in `TestLoaderExternalRef_RedGreen` (flag=false GREEN / flag=true
  RED), and `TestLoaderHarness_NotVacuous` proves the loader actually resolves internal
  refs (a dangling ref is rejected). Does NOT verify: semantic document equality (only
  kin's own marshal fixed point); correctness of the resolved schemas; behaviour above
  16 KiB; anything with an attacker-controlled DOCUMENT in a LIVE caller (none exists);
  the SAFETY of a custom `ReadFromURIFunc` policy other than a fully-refusing one (Config
  B refuses all; a selectively-allowing policy is out of scope).
