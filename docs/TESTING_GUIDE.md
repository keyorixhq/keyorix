# Testing Guide

This file documents test suites that don't already have their own obvious
home (`docs/TESTING_FRAMEWORK.md` for unit-test helpers/mocks,
`docs/TESTING_BEST_PRACTICES.md` for general conventions). Sections are
added as they're built, not written speculatively ahead of the code.

## Customer journeys (`scripts/e2e/journeys/`)

Six end-to-end tests, each driving the real `keyorix-server` binary, the
real `keyorix` CLI binary, and (for N4) the real `keyorix-migrate` binary —
never mocks — through a realistic customer scenario on a freshly
bootstrapped install. Distinct from `scripts/e2e`'s own smoke driver
(`make e2e-smoke`), which asserts "no 5xx anywhere" across every route on
an empty database; these assert the actual RESULT of a scenario: read-back
values, exact audit event counts, denial status codes, version history,
ciphertext identity across a key rotation.

| # | Journey | Test | Tier | Runtime (measured) |
|---|---|---|---|---|
| N1 | An application gets a secret | `TestJourney_AppGetsSecret` | fast | ~7-8s |
| N2 | Access control through the real server | `TestJourney_AccessControl` | fast | ~5-6s |
| N3 | The audit trail holds up | `TestJourney_AuditTrail` | fast | ~7-8s |
| N4 | Migrate from Vault/OpenBao | `TestJourney_VaultMigrate` | containers | ~13-19s |
| N5 | SSO login via Keycloak (OIDC) | `TestJourney_SSOLogin` | containers | ~16-56s |
| N6 | Disaster recovery (backup/restore/KEK rotation) | `TestJourney_DisasterRecovery` | fast | ~12-19s |

"Fast tier" (N1, N2, N3, N6) needs only SQLite and no containers — build
tag `e2e`, same as `scripts/e2e`'s own smoke driver, sharing its
`scripts/e2e/harness` boot/bootstrap package (one boot sequence, not two).
Run it in the merge-queue path:

```sh
make e2e-journeys
```

"Containers tier" (N4, N5) needs Docker — real Vault/OpenBao containers for
N4, a real Keycloak container for N5. These are on their OWN build tag,
`e2e_containers`, NOT `e2e` — `make e2e-journeys`/`go test -tags e2e ...`
never builds or runs them, regardless of whether the runner happens to have
Docker installed. Running them needs BOTH tags together (N4/N5 still depend
on `scripts/e2e/harness`, itself gated on `e2e` alone):

```sh
make e2e-journeys-containers
```

If Docker isn't available, N4/N5 skip cleanly (`t.Skip`) by default. A CI
job that has deliberately opted into the containers tier should set
`KEYORIX_E2E_CONTAINERS=1` — with that set, a missing Docker is a hard test
FAILURE instead of a silent skip, so the job can't report green having
tested nothing. `make e2e-journeys-containers` already sets this for you.

### What each journey actually asserts

- **N1** — a real admin session creates a project/secret/machine identity,
  grants a scoped role, issues a machine token; three independent readers
  (REST with the token, CLI with the token, the `keyorix-go` SDK) agree on
  the value; a rotation bumps the version; the token is revoked and all
  three readers are denied afterward with the state unchanged; a rollback
  proves the ORIGINAL value is still recoverable from version history (the
  one mechanism that decrypts a historical version).
- **N2** — two projects, four principals (admin, an editor, a viewer, an
  outsider with zero grants). Every denial is asserted with an EXACT REST
  status code (not "any non-2xx") and checked to leak nothing (no value, no
  other project's name) in the denied response body. Role removal denies
  the very next call with no re-login. A time-bound access grant expires on
  schedule.
- **N3** — re-runs N1+N2 against one shared install, then asserts the
  resulting audit trail: exact per-event-type counts (no duplicates, no
  silent drops), correct attribution of the async `secret.read` logging
  path, and an offline `admin verify-audit` round trip — a clean chain
  reports VALID, a directly-tampered copy (a modified row, or a deleted
  one) reports BROKEN with the right exit code.
- **N4** — seeds a real Vault/OpenBao KV v2 tree plus an ACL policy, runs
  `keyorix-migrate vault scan` then `vault import` (dry-run, then
  `--apply`) against a real `keyorix-server`, and confirms every seeded
  secret is readable with the correct latest value under its full
  source-path-derived name. Neither the dry-run nor the apply output leaks
  a seeded value.
- **N5** — boots a real Keycloak, drives the actual OIDC authorization-code
  flow (no browser automation needed — Keycloak's login form posts back to
  a plain HTML action), and confirms `GroupRoleMap` JIT-provisions the
  right role from the right Keycloak group. Three negative cases (a
  tampered `state`, a replayed code, a state fabricated from scratch) each
  assert a rejected callback with no session cookie set. Logout is asserted
  to return exactly 401 on a second call with the same (now-invalidated)
  session, not merely "not a 500."
- **N6** — takes a real `admin backup`, DELETES the source's actual
  database and key files (proving restore can't silently reuse a still-
  existing source), restores onto a completely separate fresh install, and
  confirms every secret version's actual value (not just a count) and a
  prior token revocation both survive. Rotates the master passphrase and
  confirms the encrypted ciphertext is byte-identical (only the wrapping
  changed), that the old passphrase can no longer boot the server, and that
  a backup taken BEFORE the rotation still restores under the old
  passphrase. Five negative cases (a tampered archive, a truncated archive,
  the wrong passphrase, a non-empty restore target, an older backup without
  `--allow-rollback`) are each asserted refused.

### Requirements

- `sqlite3` CLI on `PATH` (N3, N6 — used to directly inspect/tamper a raw
  DB file; both fail loudly, not silently, if it's missing).
- Docker (N4, N5 only) — real containers, no mocking of Vault/OpenBao/
  Keycloak's own behavior.
- Network access to pull the pinned container images on first run (Vault/
  OpenBao digests match `.github/workflows/ci.yml`'s `migrate` job matrix;
  Keycloak's digest was sourced fresh for N5, no prior reference existed in
  this repo).
