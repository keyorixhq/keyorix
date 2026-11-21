# FINDING: FuzzDSNHostsCoverDriverHosts — double-bracket host form `[[…]]` escapes ParseDSNHosts normalisation

**Date:** 2026-11-21 (triage1 session)
**Corpus issue:** keyorixhq/fuzz-corpus #153
**Harness:** `internal/dynamic/dsn_driver_differential_fuzz_test.go` / `FuzzDSNHostsCoverDriverHosts`
**Component:** `internal/core/dsn/dsn.go` — `ParseDSNHosts`, `SplitDSNHostList`
**Status:** **OPEN — held for Andrei's security review before any fix or disclosure** (issue's own text).
**Classification: CANDIDATE** — real differential, nil impact for the specific minimised input;
broader double-bracket variant space unexamined; classification may change after the variant sweep.
**Severity: Undetermined** — see "Blast radius" below.

---

## Summary

`ParseDSNHosts("host=[[]]")` returns `["[]"]`.
pgconn's own host parser stores the raw string `"[[]]"` in `cfg.Host`.
The harness's `covered` function (`stripBrackets` applied to both sides) produces
`"[]"` (from ParseDSNHosts) vs `""` (from `stripBrackets("[]")`), which are not equal.
`t.Fatalf` fires.

The seed corpus entry added in this session:
```
internal/dynamic/testdata/fuzz/FuzzDSNHostsCoverDriverHosts/f0520501354fcac9
```
Input: `string("host=[[]]")`

---

## Code trace

`ParseDSNHosts("host=[[]]")` → `ParseDSNHostsFromKeyValue`:

1. `keywordValuePairsStrict` → map `{"host": "[[]]"}`.
2. `SplitDSNHostList("[[]]")`:
   - `net.SplitHostPort("[[]]")` fails (not `[host]:port` form; first `]` at position 2 is followed by `]` not `:`).
   - Has prefix `[`, suffix `]`, len > 2 → strips outer brackets → `"[]"`.
   - Returns `["[]"]`.

pgconn (`github.com/jackc/pgconn`) stores `cfg.Host = "[[]]"` literally (pgconn's parser does no bracket-normalisation for this form).

Harness `covered` check:
- `want = stripBrackets("[[]]") = "[]"` (strips one pair of outer brackets)
- `g = stripBrackets("[]") = ""` (strips the second pair)
- `"" ≠ "[]"` → crash.

This confirms the differential: `ParseDSNHosts` sees `[[]]` as the IPv6-bracket notation wrapping the string `[]`, while the harness's oracle (and by extension pgconn) see it as two levels of brackets.

---

## Blast radius

**Specific input `host=[[]]` has no live SSRF path.**

1. `net.JoinHostPort("[[]]", "5432")` → `"[[]]:5432"`.
2. `net.SplitHostPort("[[]]:5432")`: starts with `[`, finds first `]` at position 2, next char is `]` not `:` → error. Go's net stack cannot dial `[[]]`.
3. `validateAdminDSNHost` (`internal/dynamic/`) calls `net.LookupHost` on the parsed host before persisting a DSN. `net.LookupHost("[]")` returns an error → DSN registration is rejected at API time.
4. Double-bracket wraps of real IPs (e.g. `[[169.254.169.254]]`) follow the same parse failure path; none are dialable.

**Undone work:** Whether any double-bracket form `[[X]]` where `X` is itself a valid IPv6 literal (e.g. `[[::1]]`) could reach `validateAdminDSNHost` in a form it passes, and then be dialled by pgconn while bypassing the SSRF blocklist, has not been fully traced. This is the remaining variant space that warrants Andrei's review.

---

## What this finding does NOT verify

- Whether any `[[X]]` form where `X` is a live address can bypass `validateAdminDSNHost`'s SSRF check.
- Whether MySQL or MongoDB connstring parsers (also covered by the harness) accept `[[X]]` forms differently.
- Whether `RevokeTarget` (`internal/core/dsn/revoke_target.go`, which also calls `ParseDSNHosts`) is reachable with an already-persisted `[[X]]`-form DSN.

---

## Proposed fix (proposal only — no code)

`SplitDSNHostList` should recognise that `[[X]]` is not a valid IPv6-literal bracket form and return the raw string unchanged (or return an error), rather than strip one bracket level and produce `[X]`. The fix should be accompanied by a table-test covering `[[]]`, `[[::1]]`, `[[localhost]]`, and mixed host-list forms, and the existing `FuzzDSNHostsCoverDriverHosts` seed set should be extended to prevent regression.

---

## Action required

**Hold for Andrei's review per issue #153's own text.** Do not write, land, or disclose a fix until the full double-bracket variant sweep is done and Andrei has signed off.
