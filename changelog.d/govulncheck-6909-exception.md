### Security
- **`govulncheck` can now carry a documented, ID-scoped exception for a reachable finding with
  no upstream fix.** A bare `govulncheck ./...` had no exclusion mechanism, so the day
  `GO-2026-6909` (`crewjam/saml`, no fixed version) was published, `static-analysis` — and
  `build-and-test` behind it — went red for every PR and the merge queue with no way to land
  anything. `scripts/ci/check-govulncheck.sh` now decides pass/fail itself (`govulncheck -format
  json` always exits 0): any other reachable finding still fails exactly as before, and a
  reachable finding only passes when `docs/govulncheck-exceptions.d/<ID>.tsv` carries a dated row
  naming the confirmed mitigation and an expiry for re-review (`docs/govulncheck-exceptions.d/
  README.md`). Added the first (and so far only) row: `GO-2026-6909` — both halves of the
  advisory (the nil-`Issuer` panic in `validateAssertion`, and the namespace-blind
  `Subject.NameID`) are already mitigated at Keyorix's only SAML call site
  (`internal/saml/provider.go`'s `parseResponseRecovered` and `strictAssertionShape`), each with
  an existing, currently-passing test. `GO-2026-6865` (`klauspost/compress`, fixed in v1.20.2)
  needs no row — it is fixed by a dependency bump, not by this mechanism.
### Internal
- `scripts/ci/check-govulncheck.sh`'s own calibration (`check-govulncheck-test.sh`, run from the
  Go suite by `scripts/ci/govulncheck_exceptions_test.go`'s `TestGovulncheckCheckScript`) proves
  it fails on a reachable, non-allowlisted finding (including a near-miss ID and `govulncheck`
  itself failing) and passes on a clean run, a non-reachable-only finding, and a reachable finding
  that is allowlisted. `TestGovulncheckExceptionsMitigationTestsExist` fails if a row names a
  mitigation test that doesn't actually exist; `TestGovulncheckExceptionsNotExpired` is the
  nightly-evaluated expiry half (`docs/guard-rollout-contract.md` rule 1 — no calendar at PR
  time), picked up automatically by `scripts/guard-expiry-report.sh`.
