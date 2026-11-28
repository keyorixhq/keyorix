# FINDING: FuzzGoMailRenderRoundTrip — two oracle O3 false positives; both fixed before triage

**Date:** 2026-11-21 (triage1 session)
**Corpus issue:** keyorixhq/fuzz-corpus #156
**Harness:** `internal/libconformance/gomail_render_fuzz_test.go` / `FuzzGoMailRenderRoundTrip`
**Component:** oracle O3 (Subject header encoded-word check), harness
**Status:** **Fixed** — both crashers were resolved by commits already on main before this session.
**Classification: ARTIFACT** — oracle false positives, not production defects. No production
code change was required; the fix was entirely in the harness oracle.

---

## Summary

The fuzz-corpus issue reported two crashers, both triggering oracle O3 of
`FuzzGoMailRenderRoundTrip`. O3 asserts that rendered emails are free of raw RFC 2047 encoded-word
sequences (`=?charset?encoding?text?=`) in the Subject header — an encoding correctness check
intended to catch cases where go-mail emits a half-encoded subject.

The two crasher shapes were:
1. A Subject that is itself a *malformed* encoded-word (`=??q? ?=`, `=??B??=`): go-mail passes it
   through unchanged; O3 saw it as a raw encoded-word in the output and fired.
2. A Subject containing a stale-CR sequence (`\r\x1f\n`): go-mail emits quoted-printable encoding
   that includes `=0D` (CR) as a soft line-break artefact; O3 saw the intermediate form and fired.

Neither shape implied a real SMTP framing or injection defect.

---

## Corpus seeds added in this session

Two seeds were added to document the two shapes:

```
internal/libconformance/testdata/fuzz/FuzzGoMailRenderRoundTrip/faaa790bef48816e
  string("<0@0>"), string("=??B??="), string("0")
  — malformed encoded-word lookalike in subject

internal/libconformance/testdata/fuzz/FuzzGoMailRenderRoundTrip/e76e262291d311f9
  string("0@0"), string("0"), string("\r\x1f\n")
  — stale-CR sequence in subject body
```

Both **pass** on current main (confirmed by test run in this session). The existing seed
`d6d7c4dcf79c7338` (a similar previously-fixed case) also passes.

---

## Fix history

| Crasher shape | Fixed by commit | Mechanism |
|---|---|---|
| Malformed encoded-word in Subject (`=??q? ?=`) | `1a50ddfb5` (`test(libconformance): fix FuzzGoMailRenderRoundTrip oracle O3 for malformed encoded words`) and `13d3fafc4` (`test(fuzz): go-mail subject oracle skips encoded-word lookalikes before decoding`) | Added `xmailEncodedWordLookalike` regex exception; O3 skips if the input subject already looks like an encoded word |
| Stale-CR QP artefact (`\r\x1f\n`) | `1a50ddfb5` and the `qpStaleCRLineBreaks` model in the same PR | Added `TestQPFindingStaleCR` to pin the behaviour; oracle updated to account for the QP writer's known stale-CR bug |

Both fixes are confirmed ancestors of HEAD. The crashers described in issue #156 do not reproduce
on current main.

---

## What this finding does NOT verify

- Whether go-mail's RFC 2047 encoding is correct for all valid non-ASCII subjects (O3 only checks
  the encoded-word shape in the output, not full RFC 2047 conformance).
- Whether the stale-CR QP behaviour can produce SMTP framing defects in a real MTA (the oracle pins
  the existing behaviour; it does not assert that behaviour is safe end-to-end).
