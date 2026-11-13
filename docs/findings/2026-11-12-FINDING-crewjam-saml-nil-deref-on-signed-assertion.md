# FINDING: crewjam/saml nil-pointer dereference on a validly signed assertion with a wide sibling fragment

**Date:** 2026-11-12
**Component:** third-party `github.com/crewjam/saml` (`ServiceProvider.ParseXMLResponse`),
reached from `internal/saml/provider.go` (`Provider.ParseResponse` →
`parseResponseRecovered`).
**Status:** **Contained, no Keyorix code change needed.** Production already turns the
panic into an ordinary refusal. Upstream report pending.
**Severity: Informational** (library robustness; no authentication bypass, no panic
reaches the HTTP layer).

## Summary

`FuzzSAMLXMLGrammar` (`internal/saml/parse_response_xml_grammar_fuzz_test.go`, oracle
(d)) drives a validly signed assertion with a grammar-generated sibling fragment
through the BARE library (`ServiceProvider.ParseXMLResponse`). For one input the bare
library panics:

```
runtime error: invalid memory address or nil pointer dereference
```

Library version in this tree: `crewjam/saml v0.5.2` (`go.mod`).

## Input

Fuzz bytes `[]byte("0C0002X")`, decoded by `grammar.DecodeSAMLFragment` to shape 0
and a fragment of the form `<r><e/><e/>…<e/></r>` (a flat run of many
empty elements under one root, placed as a sibling in the assertion's Subject
region). The input is committed as a seed:
`internal/saml/testdata/fuzz/FuzzSAMLXMLGrammar/244115ddf69e2481`.

## Why this is contained

`Provider.ParseResponse` never calls the bare library directly:

1. `validatePostedResponseHasNoEpilogue` and `strictAssertionShape` refuse malformed or
   oversized responses first. For this input the refusal comes from that stage
   (`saml: response has more than 1000 elements`), so the library is not reached.
2. Whatever does reach the library goes through `parseResponseRecovered`, whose
   `recover()` converts any panic inside `ParseResponse` into an error that is
   logged and returned to the caller as the fixed `errInvalidSAMLResponse`.

Note that this specific input is stopped by (1), so the committed seed proves the
guarded entry refuses it, not that the `recover()` in (2) fired. (2) is the backstop
for inputs that get past (1).

## Fuzz oracle change

Oracle (d) used to fail the fuzz on ANY bare-library panic. It now counts and logs it
(`samlLibraryPanics`, `t.Logf`) and instead requires that the guarded
`Provider.ParseResponse` returned an error for the same response. A guarded path that
accepted a response the library panicked on, or one that let a panic escape
(`fuzzutil.Guard`), still fails the fuzz.

## Follow-up

- Upstream report to crewjam/saml: pending (Andrei).
- If upstream fixes it, the oracle can go back to treating a bare-library panic as a
  failure.
