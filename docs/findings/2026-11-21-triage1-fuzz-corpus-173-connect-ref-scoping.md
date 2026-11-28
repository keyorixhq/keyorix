# FINDING: FuzzConnectRefScopingGRPC — invalid-UTF-8 seed skipped by documented harness scope limit; no crash

**Date:** 2026-11-21 (triage1 session)
**Corpus issue:** keyorixhq/fuzz-corpus #173
**Harness:** `server/http/connect_ref_scoping_grpc_fuzz_test.go` / `FuzzConnectRefScopingGRPC`
**Component:** harness scope (not production code)
**Status:** No crash. All corpus seeds pass on current main.
**Classification: ARTIFACT** — the seed documents a documented harness scope limit, not a
production defect or oracle gap.

---

## Summary

The fuzz-corpus issue points to the seed:

```
server/http/testdata/fuzz/FuzzConnectRefScopingGRPC/8c4de8bc8d271a5d
  string("allowed/prefix/\xff")
```

`\xff` is invalid UTF-8. The harness's `runCRSIteration` function explicitly skips invalid-UTF-8
refs:

```go
// connect_ref_scoping_grpc_fuzz_test.go:263
if !utf8.ValidString(ref) {
    return
}
```

The harness comment explains the scope limit:

> An invalid-UTF-8 ref is not representable identically on both transports —
> `encoding/json.Marshal` silently replaces invalid sequences with U+FFFD (REST never sees the
> real bytes), while the gRPC/protobuf wire format rejects invalid UTF-8 in a string field
> outright (the RPC itself fails before ReadSecret ever runs). Neither behavior is a
> scope-escape or a parity bug — it's the two transports disagreeing about what a "ref" even IS
> once it isn't valid text, not about who may read it.

The seed was added to the corpus to confirm this skip fires correctly (not to document a crash).
It passes on current main.

---

## Oracle coverage (what FuzzConnectRefScopingGRPC checks)

For each fuzzed `ref` (valid UTF-8 only):

1. **NO-GRANT BYPASS:** A connect.read holder with no matching ConnectRefGrant must be denied on
   BOTH REST and gRPC transports, regardless of ref content.
2. **OVER-GRANT / TRAVERSAL:** When the ref is NOT segment-contained in `"allowed/prefix"` (checked
   by `crsRefWithinPrefixIndependent`, an independent oracle) OR contains a `"."` / `".."` segment
   (`crsHasDotSegmentIndependent`, also independent), BOTH transports must deny the read.
3. **REST/gRPC PARITY:** The allow/deny decision for the same (actor, connector, ref) must be
   identical on both transports; when both allow, the returned plaintext must match.
4. **POSITIVE CONTROL:** An in-scope ref is allowed on both transports.

No oracle fired on any existing seed in this session.

---

## What this finding does NOT verify

- Whether the independent oracle `crsRefWithinPrefixIndependent` is strictly equivalent to
  `ports.RefWithinPrefix` (the production implementation) for all valid UTF-8 strings — the
  harness explicitly uses a different implementation to catch divergences, but their equivalence
  for edge cases (empty segments, trailing slashes) is assumed, not proven here.
- Whether the `crsFakeConnector` (which always returns a fixed value) masks any real connector
  behaviour that could affect the RBAC decision.
- Whether gRPC's protobuf-level rejection of invalid UTF-8 (before `ReadSecret` runs) is itself a
  security-relevant behaviour that should be oracle-checked rather than skipped.
