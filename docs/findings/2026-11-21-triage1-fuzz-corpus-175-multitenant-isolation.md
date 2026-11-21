# FINDING: FuzzMultiTenantIsolationGRPC — cross-tenant read seed correctly denied; no isolation violation

**Date:** 2026-11-21 (triage1 session)
**Corpus issue:** keyorixhq/fuzz-corpus #175
**Harness:** `server/http/multitenant_isolation_grpc_fuzz_test.go` / `FuzzMultiTenantIsolationGRPC`
**Component:** harness oracle coverage (not production code)
**Status:** No crash. All corpus seeds pass on current main including the positive controls.
**Classification: ARTIFACT** — the named seed exercises a cross-tenant-read denial that the oracle
is designed to catch; it passes, confirming the oracle fires correctly on the scenario it protects
against.

---

## Summary

The fuzz-corpus issue points to the seed:

```
server/http/testdata/fuzz/FuzzMultiTenantIsolationGRPC/seed_read_value_cross_tenant
  []byte("\x08")
```

Decoded against the harness's byte-program encoding:
- Byte `0x08 = 0b00001000`
- `b & 1 = 0` → actor is alice
- `(b >> 3) & 1 = 1` → target is the OTHER tenant (bob's secret)
- `(b >> 1) & 3 = 0` → operation: read VALUE (gRPC `GetSecretValue` + REST parity check)

Alice attempts to read bob's secret value via gRPC. The oracle asserts:

```go
// multitenant_isolation_grpc_fuzz_test.go:219
if grpcOK {
    t.Fatalf("[%s] ISOLATION(gRPC): cross-tenant GetSecretValue of id %d succeeded", ...)
}
```

`grpcOK` is false (correctly denied). The seed passes, confirming the gRPC isolation oracle fires
on the cross-tenant case as intended. The REST/gRPC parity check also passes (both deny).

The seed is named `seed_read_value_cross_tenant`, making its purpose explicit: it is a positive
oracle probe confirming the isolation check is non-vacuous, not a report of a violation.

---

## Oracle coverage (what FuzzMultiTenantIsolationGRPC checks)

For each operation byte:
- **ISOLATION(gRPC):** A cross-tenant `GetSecretValue` via gRPC must be denied; the value must not
  appear in the gRPC response.
- **REST/gRPC PARITY VIOLATION:** The allow/deny decision for the same (actor, target secret) must
  be identical on REST and gRPC; when both allow, returned plaintext must match (VALUE PARITY).
- **ENUMERATION(gRPC):** An actor's own-scope list must not contain the other tenant's secret name.
- **EXISTENCE ORACLE(gRPC):** `GetSecret` for a real cross-tenant id must return the same error code
  as a never-existed fake id (ADR-096 403-for-both).
- **POSITIVE CONTROLS:** Each principal must be able to read their own secret via gRPC; a harness
  that denies everything could not pass these.

All existing corpus seeds, including `seed_read_value_cross_tenant` and the parametric seeds
(`\x00`, `\x08`, `\x0a`, `\x04`, `\x09\x0b\x0c`, `\x06`), pass on current main.

---

## What this finding does NOT verify

- Whether the REST-only by-name metadata lookup (operation case 3, no gRPC RPC exists for it) has
  parity coverage — this is a documented gap in the harness file header.
- Whether the gRPC LIST `PermissionDenied`-vs-REST-200-with-filtered-rows asymmetry (also documented
  in the file header as a pre-existing, non-confidentiality status-code difference) is acceptable
  from an audit perspective.
- Whether concurrent mutations (grants/revokes) during a multi-byte program can produce transient
  isolation violations between operations — `FuzzConcurrentOpsLinearizable` covers the concurrent
  linearizability shape; this harness does not interleave mutations.
