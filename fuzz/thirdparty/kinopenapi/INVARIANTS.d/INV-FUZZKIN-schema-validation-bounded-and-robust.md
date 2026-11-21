- **INV-FUZZKIN-schema-validation-bounded-and-robust** kin-openapi's standalone
  `openapi3.Schema` pipeline — `UnmarshalJSON` → `VisitJSON` → `MarshalJSON` — must not
  panic, hang, or do grossly superlinear work on a hostile schema + instance pair within
  the harness bounds (schema and instance each <= 8 KiB), covering deep allOf/anyOf/oneOf
  nesting, `pattern` (RE2, no catastrophic ReDoS), `format`, `additionalProperties` and
  deep/large instances; and any schema kin ACCEPTS must re-serialise idempotently
  (`MarshalJSON` → `UnmarshalJSON` → `MarshalJSON` byte-stable). Why: Keyorix only ever
  feeds this engine the trusted openapi.yaml plus handler-generated instances, so this is
  LIBRARY HARDENING (not attacker-reachable) — but a dependency bump that introduced a
  recursion panic, an amplification, or a serialization drift would silently weaken
  `contracttest` / the OpenAPI stateful fuzzer / `internal/egressguard`, which assume the
  engine is robust. Guard: `FuzzOpenAPISchemaBoundedWork` oracles O-KIN-1/2/2b/3 and the
  deterministic replay `TestKinSeeds_NoPanicRoundTrip` (`fuzz/thirdparty/kinopenapi`);
  the budget and round-trip detection are red/green-proven in `TestKinOracles_RedGreen`,
  and `TestKinHarness_NotVacuous` proves VisitJSON actually discriminates valid from
  invalid instances. Does NOT verify: semantic schema equality (only kin's own marshal
  fixed point), cross-document `$ref` resolution (standalone-schema decode does not
  resolve refs), format-assertion correctness (default VisitJSON does not enforce
  formats unless registered), or anything with an attacker-controlled SCHEMA (none exists
  in a live caller).
