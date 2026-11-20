# FINDING: <Short title — what broke and where>

**Date:** YYYY-MM-DD
**Component:** `pkg/path` (`SpecificFile.go` — `FunctionName`)
**Status:** Open | Fixed (PR #NNN, branch `branch-name`) | Contained, no code change needed
**Regression test:** `TestFunctionName` (`path/to/package`) — OR — N/A — <reason>
**KFZ id:** KFZ-NNN (omit this field entirely if no external fuzz-corpus cross-reference)
**Severity:** Critical | High (impact / likelihood) | Medium | Low | Informational

## Summary

One paragraph. What is broken, who can trigger it, what the worst-case consequence is.

## Reproduction

Steps to reproduce deterministically. If the finding came from a fuzzer, include the
seed corpus path and how to replay it. If a deterministic unit test exists, cite it
here and in **Regression test** above.

## Fix

What was changed and why. If the finding is not yet fixed, leave this section out or
add a "Proposed fix" subsection with the approach.

## Severity

Detailed severity reasoning if the one-line above is not obvious: who can trigger it,
what preconditions are required, what the worst-case outcome is, and why the rating is
not higher or lower.

---

<!-- HOW TO USE THIS TEMPLATE

**Regression test** is REQUIRED. Two forms:

  `TestFunctionName` (`path/to/package`)

    Use when a deterministic test proves the bug is fixed and will stay fixed.
    path/to/package is the Go package's directory relative to the repo root
    (e.g. `server/http`, `internal/core`, `internal/encryption`). The function
    name must match a `func TestFunctionName(` or `func FuzzFunctionName(` in
    that package. The checker TestFindingRegressionTests_NamedTestsExist
    (internal/docsdrift) verifies this — it confirms the function exists in the
    stated package; it does NOT verify the test passes or covers the specific bug.
    That is CI's job.

  N/A — <reason>

    Use when no deterministic test applies: a third-party-library containment
    with no Keyorix code change (the SAML nil-deref finding is an example), a
    docs-only or process finding, or a finding whose test requires a Postgres
    race that cannot be encoded deterministically. State the reason explicitly.

**KFZ id** is OPTIONAL. Include it only for findings that originated in, or were
cross-filed to, the private fuzz-corpus registry (keyorix-private). Omit the
field entirely for internal Keyorix findings (the common case).

Sections other than Summary are freeform — add, rename, or omit based on what
the finding actually needs. The only machine-checked line is **Regression test**.

The filename convention is: docs/findings/YYYY-MM-DD-FINDING-<slug>.md
-->
