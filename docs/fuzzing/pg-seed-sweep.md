# Fuzzer strings written raw into Postgres: sweep of the fuzz harnesses (2026-11-27)

PG-SEED-SWEEP-1, follow-up of fuzz-corpus#194 / KFZ-2026-179 / keyorix#4754.

## The defect class

PostgreSQL refuses invalid UTF-8 and NUL (0x00) in a `text` column (SQLSTATE 22021);
SQLite stores both. A harness that seeds a fuzzer-supplied string through its
world's DB fails the iteration at setup, before the code under test runs. That is a
false positive, and the first one was closed as "flaky" (KFZ-2026-160) before the
cause was found: `FuzzFaultInjectedOperations` seeded `"\xad"`.

Shared fix: `fuzzworld.PGText` (`internal/testutil/fuzzworld/pgtext.go`), used for
values the harness writes as its own setup. The alternatives already in the tree,
for fuzzer strings that are the input under test or that need exact bytes, are a skip
(`diffValidString`, `like_escape_injection`) or a named expected difference
(`isPGTextEncodingReject`).

## How the list was derived, and what it cannot see

1. Every `func Fuzz*(` in a `_test.go` file (`rg -l 'func Fuzz\w+\('`: 362 files at
   71fa98fe1, a few of them test fixtures that only contain the text).
2. Files and packages that can reach Postgres: a reference to `fuzzworld.`,
   `OpenPostgres`, `pgdsn.`, `pgcanary.`, `postgres.Open` or `KEYORIX_TEST_PG_DSN`,
   searched per file and then per package (a world built in `world_test.go` is
   used by fuzz files that never name Postgres).
3. For each fuzz target in those packages, the `f.Fuzz` signature (string,
   `[]byte`, and byte-program parameters) and the path from each parameter to a DB
   write, read by hand: `string(<param>)` conversions, `Sprintf("%s"`, decoders that
   turn bytes into names, and `ToValidUTF8` / `utf8.Valid` / `22021` guards.

Call forms the search knows: the Postgres references in step 2; `f.Fuzz(func(t
*testing.T, ...)` bodies of functions named `Fuzz*`; helpers called from them
within the package.

What it cannot see:

- A fuzz target reached through a name that is not `Fuzz*` or a helper that builds a
  `testing.F` itself.
- A Postgres connection opened through a form not listed in step 2 (a package's own
  `openPG`-style helper that does not use `pgdsn`/`fuzzworld`/`KEYORIX_TEST_PG_DSN`).
- A string that reaches a DB indirectly through product code in a way the reading
  missed. Byte-program targets were read for how they build strings, not traced
  through every product call.
- Other repositories (`fuzz-harness`, `fuzz-corpus`) and the continuous rig's own
  wrappers.
- Product-input paths (see "Adjacent class"), by scope.

## Verdicts

Exposed: **none beyond the one #4754 fixed.** That one now uses the shared helper.

| Target | Fuzzer value | Verdict |
|---|---|---|
| `FuzzFaultInjectedOperations` (internal/encryption) | `oldPassIn`, `newPassIn`, `secretVal` into canary strings stored in secret rows | **was exposed**; fixed (#4754), now `fuzzworld.PGText`; seed `pg-invalid-utf8-seed-string` |
| `FuzzKDFEnumerationOracle` (internal/core) | `absentName` into lockout accounting; `candidatePW` only hashed | normalised: `identity.NewFoldedName` refuses NUL / invalid UTF-8 and the harness substitutes a sentinel (guarded by `TestKDFEnumerationOracle_AbsentNameGateRefusesPGRefusedBytes`); seeds added, green on Postgres |
| `FuzzDEKSweepCrashConsistency` (internal/encryption) | `valPrefix` encrypted into `EncryptedValue` (`[]byte`, bytea); `pass` is a KEK passphrase, never stored | bytea-safe; existing seed `"\x00\x01"`, `"\xff\xfe"` green on Postgres |
| `FuzzStorageIfaceDifferential`, `FuzzStorageIfaceMetamorphicSQLite`, `FuzzStorageBackendDifferentialV2` (internal/storage/store) | `s1`, `s2` into the name pool | filtered: skip on NUL / invalid UTF-8 / >512 B (`diffValidString`) |
| `FuzzLikeEscapeInjection` (internal/storage/store) | `s`, `c` | filtered: skip |
| `FuzzGormListTenantIsolation` (internal/storage/store) | `payload` as a query filter, not seeded | query path; PG refusal classified by `isPGTextEncodingReject` |
| `FuzzGormListSQLShape` (internal/storage/store) | `raw` | DryRun, nothing sent to the server |
| `FuzzCredentialLookupRaw_MatchesGORM` (internal/storage/store) | `hash` | SQLite only |
| `FuzzConnectRefScopingGRPC` (server/http) | `ref` as a request value | query path; invalid UTF-8 skipped, NUL probed on Postgres, green |
| `FuzzPostgresRotateRecordingDriver` (internal/rotation) | `refSuffix`, `value` | recording fake, no server |
| `FuzzCrossDialect`, `FuzzGormInjectionStructure`, `FuzzNoREC`, `FuzzTLP` (internal/storage/sqllogicfuzz) | bytes select from a fixed alphabet / are bound in DryRun | input already normalised |
| `FuzzCoreOperationSequence`, `FuzzSecretLifecycleModel`, `FuzzCrossReplicaOps`, `FuzzCrossReplicaInvariants`, `FuzzScheduleInterleavings`, `FuzzCoreSecretOpsCanaryLeak` (internal/core) | byte programs: ops, indexes, `[]byte` values, canary text from a fixed alphabet | normalised / bytea; the hostile canary wrapper is valid UTF-8 without NUL |
| `FuzzCorePGCanaryLeak` (internal/core) `variant()` | planted NUL / invalid UTF-8 on purpose, to read the Postgres error | by design (oracle provokes 22021 and checks it does not echo the canary); the bytes are fixed, not fuzzer-supplied |
| server/http byte-program targets (`api_sequence`, `concurrent_linearizable`, `multitenant*`, `openapi_stateful`, `grpc_rest_authz_parity`, `existence_cost`) | op / principal selectors; names from `Sprintf` with integers | normalised: no fuzzer string is written |
| server/faultops, server/authzdiff, server/pgfault, server/admin byte programs | op catalog indexes, `Sprintf` plaintext with integers | normalised |
| `fuzz/thirdparty/pools` (pgxpool, gormtx) | `fmt.Sprintf("k%d")` keys and values | normalised |
| internal/storage upgrade fuzzers | bytes pick indexes and one of three fixed name variants (`ugNameVariant`) | normalised |
| scripts/e2e/mp1 | `Sprintf` names and values | normalised (needs the e2e cluster) |

## Adjacent class, out of scope here

Several targets send the fuzzer's bytes as a product input (request bodies in
`canary_sweep` and `request_echo*`, gRPC messages in `protoreflect`, metadata in
`edge_auth_metadata`). A Postgres refusal there is a product observable, not a
harness defect: the question is whether the product answers 4xx or 5xx. They are not
normalised, on purpose, and must not be: `request_echo_pg_canary` exists to probe
exactly this. Any finding there goes to fuzz-corpus first.

## What normalising does not verify

`PGText` hides invalid-byte and NUL inputs from PG seeding. A product bug that only
fires when such a string is stored is not exercised through a normalised seed.
`FuzzFaultInjectedOperations` therefore says nothing about a passphrase or secret
value made of invalid bytes on Postgres.

## Oracle health

`scripts/fuzzing/oracle-health` has no entry for `FuzzFaultInjectedOperations`, and
the target has no planted-defect self-test to point an entry at (its only test is the
seed-reach guard `TestFuzzFaultInjectedOperationsSeedsReachEveryOpAndSeam`). Adding
one is a planted fault in the harness plus an entry, not a few lines; not done here.
