# Dep-Fuzz Gaps

<!-- Point-in-time analysis written by hand (2026-11-19); not generated and not checked.
     The enforced record of open gaps is docs/fuzz/dep-fuzz.d/ (one fragment per
     module), checked by scripts/fuzzing/depmatrix. -->

This document covers every REACH=UNTRUSTED, FUZZ=NONE row in the dependency
matrix, ranked by risk, plus notes on the WRAPPED-covered deps whose oracle may
be a no-panic check only. It also explicitly addresses the required modules from
the original task spec.

## UNTRUSTED + NONE gaps (3)

These are the only rows where a dependency is reachable from untrusted input
AND has no fuzz coverage at all.

---

### 1. `github.com/oapi-codegen/runtime` — HIGH priority

| Field | Value |
|-------|-------|
| Importers | 3 (`cli/cmd`, `cli/internal/apiclient`, `migrate/internal/apiclient`) |
| go.mod | `cli/go.mod` |
| Risk | A hostile server can send malformed HTTP responses; the CLI and migrate tool parse them through this library. Covered by the existing hostile-server CLI fuzzer only transitively. |

**Call path**: `cli/cmd → cli/internal/apiclient → oapi-codegen/runtime → response body decode`

The runtime library handles HTTP response parsing (status codes, body
desoding, content-type negotiation) for the generated OpenAPI client. Any
server-side response — including those from a compromised or adversarial
Keyorix instance — flows through this. `fuzz/cl1-cli-hostile-server` covers
the CLI against a hostile HTTP server but its current harness drives the
transport layer, not the generated client response-parsing specifically.

**Suggested target**: add a `FuzzOpenAPIRuntimeResponseParse` harness in
`fuzz/thirdparty/` that feeds arbitrary `http.Response` bodies into
`oapi-codegen/runtime`'s response-decoding path.

---

### 2. `github.com/aws/aws-sdk-go-v2/service/iam` — MEDIUM priority

| Field | Value |
|-------|-------|
| Importers | 1 (`internal/rotation`) |
| go.mod | `go.mod` |
| Risk | IAM responses decoded from AWS API calls during secret rotation. Attacker needs MITM on AWS endpoint or a compromised AWS account to influence parsing. |

**Call path**: `internal/rotation/awsiam.go → github.com/aws/aws-sdk-go-v2/service/iam`

The IAM dep is used for dynamic-secret rotation (creating/deleting AWS IAM
users). JSON parsing of IAM API responses is handled inside the AWS SDK itself;
this dep provides the IAM-specific request/response types. Direct exploitation
requires either MITM on the AWS endpoint or a compromised AWS account — not
the typical attacker model for a FUZZ gap. The `fuzz/thirdparty/aws` target
covers the broader AWS SDK; this IAM-specific dep is a narrow extension.

**Suggested target**: extend `fuzz/thirdparty/aws` or add a
`FuzzIAMResponseDecoding` harness that feeds crafted IAM `ListUsers`/
`CreateUser` response bodies to the SDK's response decoder.

---

### 3. `golang.org/x/sync` — LOW priority

| Field | Value |
|-------|-------|
| Importers | 1 (`internal/oidcverify`) |
| go.mod | `go.mod` |
| Risk | Used as `singleflight.Group` to deduplicate concurrent JWKS fetches. Sync primitives do not parse external data. |

**Call path**: `internal/oidcverify/oidc_jwks.go → golang.org/x/sync/singleflight`

`singleflight` is a concurrency-deduplication primitive; its exported
API takes a string key and a function. No untrusted input is passed to
`singleflight`'s parsing code — there is none. UNTRUSTED+NONE here is a
correct classification (the package is reachable from an UNTRUSTED path)
but the security risk is negligible: the dep has no parser surface. No fuzz
target is warranted.

---

## Required checklist from spec

The following modules were explicitly required to appear in the matrix.
All are present; none are UNTRUSTED+NONE unless noted above.

| Module | REACH | FUZZ | Note |
|--------|-------|------|------|
| `google.golang.org/protobuf` | UNTRUSTED | DIRECT | gRPC wire, proto parsing |
| `google.golang.org/grpc` | UNTRUSTED | DIRECT | gRPC transport |
| `cloud.google.com/go/secretmanager` | UNTRUSTED | DIRECT | GCP SM client |
| `cloud.google.com/go/kms` | UNTRUSTED | DIRECT | GCP KMS client |
| `google.golang.org/api` | UNTRUSTED | DIRECT | GCP API client |
| `github.com/googleapis/gax-go/v2` | UNTRUSTED | DIRECT | GCP gRPC retry/transport layer |
| `github.com/google/go-tpm-tools` | TOOLING | DIRECT | TPM tools; test-only importer (fuzz harness) |
| `github.com/prometheus/client_golang` | UNTRUSTED | DIRECT | Metrics; note: no untrusted input at call sites |
| `golang.org/x/net` | TOOLING | DIRECT | Test-only; production path uses net stdlib |
| `golang.org/x/crypto` | UNTRUSTED | DIRECT | bcrypt, SSH, HKDF |
| `gorm.io/driver/postgres` | UNTRUSTED | DIRECT | Postgres driver via gorm |
| `gorm.io/driver/sqlite` | TRUSTED-ONLY | DIRECT | SQLite (test/migration only) |
| `github.com/nicksnyder/go-i18n/v2` | TRUSTED-ONLY | DIRECT | i18n message file parsing |
| `github.com/wneessen/go-mail` | TRUSTED-ONLY | DIRECT | Email delivery |

---

## UNTRUSTED + WRAPPED (oracle quality note)

These deps are covered only via WRAPPED paths — a Fuzz function exercises an
own-module package that calls the dep. The oracle in the driving fuzz test may
be no-panic-only, which is weaker than a differential oracle.

| Module | Wrapped via | Oracle notes |
|--------|-------------|-------------|
| `github.com/Azure/azure-sdk-for-go/sdk/azidentity` | `internal/dynamic` | Clock-jump test; no-panic oracle |
| `github.com/aws/aws-sdk-go-v2/config` | `internal/dynamic` | Clock-jump test; no-panic oracle |
| `github.com/prometheus/client_model` | `server/middleware` | API-sequence fuzzer; no-panic oracle |
| `golang.org/x/term` | `internal/crypto` | Fault-injected ops; no-panic oracle |
| `golang.org/x/time` | `server/middleware` | API-sequence fuzzer; no-panic oracle |
| `google.golang.org/genproto/googleapis/rpc` | `server/grpc/services` | Storage-fault fuzzer; no-panic oracle |

None of these wrapped deps are UNTRUSTED+NONE, so they are not gaps. The
no-panic oracle limitation is noted here for completeness; a stronger
differential oracle would improve coverage quality but is not tracked as a
gap by this matrix.

---

See [DEP-FUZZ-MATRIX.md](DEP-FUZZ-MATRIX.md) for the full matrix.
See [DEP-FUZZ-MATRIX-README.md](DEP-FUZZ-MATRIX-README.md) for class definitions.
