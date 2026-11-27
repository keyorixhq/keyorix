# FINDING: FuzzJSONSchemaRefDifferential — `$dynamicRef` schema triggers false divergence; fixed before triage

**Date:** 2026-11-21 (triage1 session)
**Corpus issue:** keyorixhq/fuzz-corpus #157
**Harness:** `internal/libconformance/jsonschema_ref_differential_fuzz_test.go` / `FuzzJSONSchemaRefDifferential`
**Component:** `kinRefDocument` helper (harness-only); kin-openapi oracle (Oracle D)
**Status:** **Fixed** — resolved by commit `152d1a41b` already on main before this session.
**Classification: ARTIFACT** — oracle false positive caused by a known kin-openapi limitation
(`$dynamicRef`/`$dynamicAnchor` not supported); no production defect.

---

## Summary

`FuzzJSONSchemaRefDifferential` runs both kin-openapi and santhosh-tekuri/jsonschema/v6 against
the same schema+instance pair and asserts that validation results agree (excluding a known-gap
allowlist). The crasher input was a schema containing a bare `$dynamicRef` key:

```json
{"$dynamicRef": ""}
```

with instance `0`.

kin-openapi does not implement `$dynamicRef` / `$dynamicAnchor` (a draft-2020-12 feature). It
either silently ignores the key or mis-classifies the schema as an object constraint, producing a
different valid/invalid decision than santhosh-tekuri's implementation. The result is a spurious
divergence that the oracle fires on — not a real interoperability gap in production use.

---

## Corpus entry

The existing seed in the repo:
```
internal/libconformance/testdata/fuzz/FuzzJSONSchemaRefDifferential/444f7e6d974f1b79
  []byte("{\"$dynamicRef\":\"\"}")
  []byte("0")
```
was committed as part of commit `152d1a41b` to pin the new skip. It **passes** on current main.

---

## Fix

Commit `152d1a41b` (`test(libconformance): skip $dynamicRef/$dynamicAnchor schemas in kinRefDocument`):
`kinRefDocument` now returns a nil `*openapi3.Schema` (causing the calling oracle to skip) when the
raw schema JSON contains a `$dynamicRef` or `$dynamicAnchor` key. This is consistent with the
existing allowlist pattern for other known-gap behaviours (openapi-ref-sibling-ignored, etc.).

The commit is a confirmed ancestor of HEAD.

---

## What this finding does NOT verify

- Whether santhosh-tekuri handles `$dynamicRef`/`$dynamicAnchor` correctly per the
  draft-2020-12 spec (the oracle skips rather than asserting correctness here).
- Whether kin-openapi's `$ref`/`$defs` handling agrees with the spec on the full set of
  `$dynamicRef`-adjacent schemas it does attempt to process.
