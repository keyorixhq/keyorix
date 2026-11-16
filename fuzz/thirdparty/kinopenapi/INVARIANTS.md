# fuzz/thirdparty/kinopenapi invariants

Read this before changing the kin-openapi (`github.com/getkin/kin-openapi`) openapi3
Schema bounded-work harness. This package is test-only (`kinhostile`). kin-openapi is
the schema engine Keyorix reaches through `server/http/handlers/contracttest`, the
`server/http` OpenAPI stateful fuzzer, and `internal/egressguard`.

REACHABILITY: in every LIVE caller the SCHEMA is the trusted committed
`server/http/handlers/openapi.yaml` and the INSTANCE is a handler's own response or a
test body — never a raw attacker-controlled schema+instance. A finding here is a
LIBRARY property (composition explosion, deep-recursion panic, round-trip drift),
classified HARDENING/CANDIDATE and labelled not-attacker-reachable unless a concrete
live call path is traced. This harness exists to catch a dependency bump that regresses
the library's robustness on the inputs Keyorix does feed it.

Format: `INV-FUZZKIN-NN <rule>. Why: <source>. Guard: <test> | UNGUARDED (#issue)`.

New invariants go in `INVARIANTS.d/INV-FUZZKIN-<kebab-slug>.md` (one per file).

## Oracles
Standalone SCHEMA target (`schema_boundedwork_fuzz_test.go`):
- O-KIN-1 no panic, O-KIN-2 bounded work (fuzzutil.Guard + resguard alloc/mallocs
  ceiling + O-KIN-2b superlinear wall), O-KIN-3 schema MarshalJSON idempotence. See the
  package doc comment for what each does and does NOT verify.

FULL-DOCUMENT loader targets (KO3, `loader_*_test.go`):
- O-LOAD-1 no panic, O-LOAD-2 bounded work (Guard + resguard + O-LOAD-2b superlinear
  wall), O-LOAD-3 load→marshal→load idempotence, O-LOAD-4 external refs never read when
  disallowed (NetMeter air-gap + hostile httptest server + file/SSRF canaries, Config A
  default loader), O-LOAD-5 resolved-vs-plain-json-round-trip marshal differential. The
  loader resolves `$ref` (recursive/circular/deep/fan-out), which the standalone-schema
  target never does. See `INV-FUZZKIN-loader-bounded-and-airgapped` and the
  `loader_boundedwork_fuzz_test.go` / `loader_noexternalread_fuzz_test.go` doc comments
  for what each does and does NOT verify.
