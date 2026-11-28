- **INV-FUZZCLOUD-oapiruntime-types-no-panic** `github.com/oapi-codegen/runtime/types`
  (v1.9.0, the version root, `cli/go.mod` and `migrate/go.mod` all require)
  never panics or hangs on attacker-controlled bytes: `(*types.Email).UnmarshalJSON`,
  `(*types.Date).UnmarshalJSON`, `(*types.Date).UnmarshalText`,
  `(*types.Duration).UnmarshalJSON`, `(*types.Duration).UnmarshalText`, and
  `(*types.File).UnmarshalJSON` return an error (or nil) for any input of up to 64KB
  (an input cap, not an allocation measurement). Additionally, for `Email` and `Date`,
  a successful `UnmarshalJSON` followed by `MarshalJSON` and a second `UnmarshalJSON`
  of the re-marshaled output produces the same value, EXCEPT for the known upstream
  deviation #4797: `Email.UnmarshalJSON` stores the unquoted local part of a quoted
  address, so `"a b"@example.com` is accepted but `MarshalJSON` rejects it,
  `"a@b"@x.com` is stored as `a@b@x.com`, and `" 0"@0` is stored as ` 0@0` and
  re-parses as `0@0`. The oracle tolerates exactly that class
  (`emailNeedsQuotedLocalPart`); any other marshal failure or divergence after a
  successful unmarshal is a violation. Reachability: only `Email` is reached from
  shipped code (five fields in `cli/internal/apiclient/types.gen.go`: a hostile
  server's response body is decoded by `json.Unmarshal`, which calls
  `(*types.Email).UnmarshalJSON`); `Date`, `Duration` and `File` are library-hardening
  targets with no Keyorix call site.
  Does NOT cover `types.UUID` (not imported in `types.gen.go`), timing or
  constant-time properties, semantic correctness of the parsed values, or round-trip
  of quoted Email local parts (#4797). Why: the `types` subpackage is the attacker-
  reachable surface (not `StyleParamWithLocation`, which is outbound-only). Guard:
  `FuzzOapiRuntimeEmail`, `FuzzOapiRuntimeDate`, `FuzzOapiRuntimeDuration`,
  `FuzzOapiRuntimeFile` (`fuzz/thirdparty/oapiruntime/oapi_runtime_types_fuzz_test.go`);
  oracles red/green-validated by `TestOraclePanic_RedGreen`, `TestOracleHang_RedGreen`,
  `TestOracleIdempotence_RedGreen` and `TestOracleEmailMarshalFailure_RedGreen`
  (`oapiruntime_oracle_validation_test.go`, which drive the same
  `emailRoundTripViolation` / `dateRoundTripViolation` / `runOp` the fuzz bodies call);
  the upstream deviation is pinned by `repro_email_quoted_localpart_test.go`, which
  fails when upstream fixes it; version lockstep with `cli` and `migrate` by
  `TestRuntimeVersionMatchesShippedModules`.
