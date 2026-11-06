# docs/govulncheck-exceptions.d/ — one govulncheck exception per file

`.github/workflows/ci.yml`'s `static-analysis` job and
`.github/workflows/govulncheck-scheduled.yml` both run
`scripts/ci/check-govulncheck.sh` instead of a bare `govulncheck ./...`
(NEEDS ANDREI note, `reports/SESSION-REVFIX-3972-4.md`, 2026-11-06: `-format
json` has no exclusion mechanism of its own, so this repo needed its own
ID-scoped allowlist before any PR could land again). Every other reachable
finding still fails the build exactly as before — this directory only ever
narrows the gate, never widens it.

## Why a finding needs a row here at all

govulncheck has no "waive this" flag. A reachable finding (the OSV database
lists a vulnerable symbol our code's call graph actually reaches — see
`scripts/ci/check-govulncheck.sh`'s own header for exactly what "reachable"
means) blocks `static-analysis`, and through it `build-and-test`, for every
PR and the merge queue, until either:

- the dependency is bumped past the fixed version (the real fix — do that
  instead of adding a row here), or
- there is no fixed version yet, and the finding is independently confirmed
  not exploitable as this codebase actually calls it.

A row here is only for the second case, and only once that confirmation has
happened. It is a documented, dated, ID-scoped risk acceptance, not a
suppression — it says "we checked, here is why it doesn't apply, here is
when we check again," and nothing else about govulncheck's behavior changes.

## Row format

One `<OSV-ID>.tsv` file per vulnerability, one tab-separated row:

```
osv_id<TAB>module<TAB>expires<TAB>mitigation_tests<TAB>note
```

- `osv_id` — the exact ID from vuln.go.dev (e.g. `GO-2026-6909`), matched
  verbatim against `govulncheck`'s own `finding.osv` field. No prefix match,
  no wildcard: a different advisory against the same module still blocks.
- `module` — the vulnerable Go module path, for a human scanning the
  directory listing; not read by the checker.
- `expires` — `YYYY-MM-DD`. Forces a periodic re-check (read the fields
  below again: is the finding still reachable the same way, has the
  dependency shipped a fix, does the mitigation still hold). At PR time only
  the format is checked (`scripts/ci/govulncheck_exceptions_test.go`'s
  `TestGovulncheckExceptionsNotExpired` — same `docs/guard-rollout-contract.md`
  rule 1 as every other dated exemption in this repo: an expiry going red at
  midnight for every open PR is exactly the 18 Oct queue stall that rule
  exists to prevent). The nightly job (`scripts/guard-expiry-report.sh`,
  which discovers this test the same way it discovers every other
  `Test*NotExpired`) evaluates the date for real, warns 7 days ahead, and
  keeps one issue open. `scripts/ci/check-govulncheck.sh` itself never reads
  this column — it only matches IDs — so an expired row still silently keeps
  passing the PR gate; the nightly issue is what actually gets a human to
  look at it. When it fires: re-run `govulncheck -format json ./...`,
  confirm whether this ID is still reachable and whether the module has a
  fixed version yet. If it's fixed, bump the dependency and delete this file
  in the same PR. If not, renew with a fresh `expires` and, if anything
  changed, an updated `note`.
- `mitigation_tests` — comma-separated Go test names (no package path) that
  prove the mitigation this row's `note` describes. Each one must actually
  exist (`TestGovulncheckExceptionsMitigationTestsExist` greps the repo for
  `^func <name>\(`) — a mitigation that's merely asserted in this file's
  prose and not backed by a real, currently-passing test is exactly the
  "assert it" tier this repo's engineering practices treat as the weakest
  one; a row that genuinely has no test to point to must say so in `note`
  instead of naming one that doesn't exist. Leave empty (a literal `-`) only
  when the row's case is "not reachable in any deployment shape" rather than
  "reachable but mitigated" — explain which in `note`.
- `note` — why this specific finding doesn't apply as deployed, with enough
  detail (file:line references are good) that the expiry re-check doesn't
  have to re-derive the reasoning from scratch. Cite the advisory's own
  summary if it helps; don't just say "safe."

## Adding or renewing a row

Add (or replace) `<OSV-ID>.tsv` here and commit just that file — same
one-file-per-claim split as `docs/security-closures.d/` and
`docs/guard-rollout.d/`, for the same reason: two exception PRs for two
different advisories never touch the same line. This is a `.github/workflows/`-
*adjacent* change in effect (it changes what the gate accepts, even though the
file itself lives under `docs/`) and needs Andrei's explicit sign-off before
it's relied on, same as any `.github/workflows/ci.yml` change — see
`CLAUDE.md`.

Never add a row for a finding you haven't independently confirmed
unreachable-as-deployed. Never widen a row to cover more than the one ID it
names. If a finding can be fixed by bumping the dependency, bump the
dependency in its own PR instead of writing a row — a row is for when that
isn't available yet, not a substitute for it.
