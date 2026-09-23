# FINDING: a real storage-read failure is silently treated as "not found" in two secret-version/name lookups

**Date:** 2026-09-23
**Component:** `internal/core/secrets_versions.go` (`storeNextSecretVersion`);
`internal/core/secrets.go` (`CreateSecret`'s duplicate-name pre-check);
`internal/core/storage/errors.go` (new sentinels `ErrSecretNotFound`,
`ErrSecretVersionNotFound` + helpers `IsSecretNotFound`, `IsSecretVersionNotFound`);
`internal/storage/store/local_secrets.go` (`GetSecretByName`, `GetLatestSecretVersion`
now wrap the new sentinels).
**Status:** Fixed, same PR as this finding doc (first-party policy).
**Severity:** Low — see "Why this is Low, not High" below; the harness's own
schema gap (fixed separately, see "Fuzz-harness caveat") made the observed
symptom look worse than the production-reachable one.

Found by `FuzzStorageFaultOperations` (`server/faultops`) during the 10-minute
validation burst for the unrelated `fix/create-ops-atomicity` PR — corpus
entry `1fefa95ddd2b26bb`, `fault=(method=GetLatestSecretVersion, NthCall=1,
kind=error)` on `REST PUT /api/v1/secrets/{id}`. `CreateSecret`'s sibling
(`secrets.go:119`) has the identical shape but was not itself fuzzer-reached
through this operation's fault-injection surface; it is covered here by a
deterministic unit test instead (`TestCreateSecret_DuplicateNameCheckReadErrorPropagates`,
`secrets_read_error_test.go`).

## Summary

`storeNextSecretVersion` resolves the next version number by reading the
current latest version and adding one:

```go
// pre-fix
latestVersion, err := c.storage.GetLatestSecretVersion(ctx, secret.ID)
nextVersionNumber := 1
if err == nil && latestVersion != nil {
    nextVersionNumber = latestVersion.VersionNumber + 1
}
```

This only special-cases the success path. Any non-nil `err` — whether the
secret genuinely has no versions yet, or the read itself failed for an
unrelated reason (a transient storage fault, a connection drop) — falls
through to the same `nextVersionNumber = 1` default. A real secret being
updated always already has at least version 1, so a read failure here always
produces a WRONG version number, not a merely-redundant one.

`CreateSecret`'s duplicate-name pre-check has the same shape:

```go
// pre-fix
existing, err := c.storage.GetSecretByName(ctx, normalizedName.String(), req.ProjectID, req.EnvironmentID)
if err == nil && existing != nil {
    return nil, fmt.Errorf("%s", i18n.T("ErrorSecretAlreadyExists", nil))
}
```

Any error other than "no such secret" silently reads as "no duplicate" —
the create proceeds under a name-uniqueness check that never actually ran.

## Reachability

Both call sites are on the ordinary secret-update/-create paths available to
any authenticated caller with permission: `PUT /api/v1/secrets/{id}` (and its
gRPC/CLI equivalents) for `storeNextSecretVersion` via `UpdateSecret` and
`RotateSecret`; `POST /api/v1/secrets/` for `CreateSecret`. Triggered by any
real storage hiccup on the read — not adversarial input.

## Reproduction (fuzzer trace, storeNextSecretVersion)

```
op="REST PUT /api/v1/secrets/{id}" fault=(method=GetLatestSecretVersion, NthCall=1, kind=error)
ORACLE (a) VIOLATION — reported SUCCESS but final state does not match the
fault-free reference run's state. Differing tables: [SecretVersion AuditEvent]
```

Minimized input: `server/faultops/testdata/fuzz/FuzzStorageFaultOperations/1fefa95ddd2b26bb`.
Replayed against pre-fix code (`go test ./server/faultops/ -run
'FuzzStorageFaultOperations/1fefa95ddd2b26bb' -v`): confirmed red. Against the
fixed code: confirmed green, and confirmed to flip back to red when the fix
to `storeNextSecretVersion` is reverted in isolation.

## Why this is Low, not High: the fuzz harness's own schema gap inflated the symptom

The fault-free reference run correctly computes `nextVersionNumber=2` (the
secret already has version 1 from creation). The faulted run's pre-fix code
computed `nextVersionNumber=1` and called `storeSecretVersion` at version 1 —
which SHOULD collide with the already-existing version-1 row under
`uniq_secret_versions_node_version` (`internal/storage.ensureSecretVersionIndex`),
producing a hard constraint-violation error that `isVersionConflict` would
then correctly classify as a lost race, triggering a retry — and the retry's
second `GetLatestSecretVersion` call (the fault is `NthCall=1` only) succeeds
normally, self-healing to the correct version 2.

That is what happens in production. It is NOT what happened in the fuzz
harness: `server/faultops/world_test.go`'s `newFaultWorld` builds its schema
via a bare `AutoMigrate` plus a hand-picked list of manually-mirrored partial
unique indexes that does not include `uniq_secret_versions_node_version` (nor
`uniq_secret_nodes_project_env_name_active`, the sibling this finding's
`CreateSecret` half would rely on for the same backstop). Without that index,
the harness's duplicate version-1 insert **silently succeeds**, producing the
`ORACLE (a) VIOLATION` observed above — the harness makes the bug look like
silent data corruption when the same fault, against a real deployment, is
actually a transient hard error that a caller-invisible retry loop absorbs.

Confirmed empirically: manually adding the missing index to the harness and
re-replaying flips this exact input from FAIL to PASS, with no other code
change. This divergence between the fuzz world's schema and the production
migration path is a known, separate, already-tracked issue —
**`fix/1947-fuzz-worlds-production-schema` (unpushed, local-only) already
replaces `world_test.go`'s hand-mirrored index list, along with three other
drifted fuzz-world builders (`internal/core`, `internal/encryption`,
`server/http`), with a shared `internal/testutil/fuzzworld` package that
bootstraps through the real production migration
(`internal/storage.MigrateExisting`) instead of a hand-picked list — strictly
more robust against future drift than a second manual list would have been.**
This PR does not touch any `*fuzzworld*`/`world_test.go` file; that overlap is
left entirely to #1947, landing separately.

None of this changes that the fix here is worth having on its own: even
though production's real index makes a single transient read failure
self-heal via retry, silently guessing "no versions yet" is still wrong
behavior — it just happens to usually get papered over by a second lucky
read. A caller-visible, deterministic "the update failed, retry it" beats a
retry loop's own default assumption being coincidentally corrected one attempt
later. And `CreateSecret`'s duplicate-name check has no such retry loop at
all — a read failure there was unconditionally silent, with no backstop.

## Fix

- `internal/core/storage/errors.go`: new sentinels `ErrSecretNotFound`,
  `ErrSecretVersionNotFound` and helpers `IsSecretNotFound`,
  `IsSecretVersionNotFound` — same convention as the existing
  `ErrUserNotFound`/`IsUserNotFound` pair. `IsSecretVersionNotFound` correctly
  returns `false` (not "confirmed absent") for `RemoteStorage.GetLatestSecretVersion`'s
  `ErrRemoteUnsupported` — unsupported is "unknown," never "confirmed absent."
- `internal/storage/store/local_secrets.go`: `GetSecretByName` and
  `GetLatestSecretVersion` now wrap their existing not-found returns with the
  new sentinels via `%w`, matching `local_users.go`'s established idiom. Both
  already correctly distinguished `gorm.ErrRecordNotFound` from a real
  retrieval failure — only the wrapping changed, not the branching.
- `internal/core/secrets_versions.go`: `storeNextSecretVersion` now branches
  three ways — real success, `storage.IsSecretVersionNotFound(err)` (version 1
  is correct), or any other error (return immediately, no default, no retry).
- `internal/core/secrets.go`: `CreateSecret`'s duplicate-name check now
  returns immediately on any error that is not `storage.IsSecretNotFound(err)`.

## Tests

- `server/faultops/testdata/fuzz/FuzzStorageFaultOperations/1fefa95ddd2b26bb`
  (fuzzer-found regression seed, committed).
- `internal/core/secrets_read_error_test.go` (deterministic, this PR):
  - `TestUpdateSecret_LatestVersionReadErrorPropagates` — a real
    `GetLatestSecretVersion` failure aborts `UpdateSecret` and leaves exactly
    one version row (no wrong-numbered write).
  - `TestCreateSecret_DuplicateNameCheckReadErrorPropagates` — a real
    `GetSecretByName` failure aborts `CreateSecret`; confirmed via the real
    (unstubbed) storage that no secret was created.
- `internal/core/service_test.go`: `TestKeyorixCore_CreateSecret`'s
  "successful secret creation" subtest had stubbed `GetSecretByName` to return
  `(nil, assert.AnError)` — a generic, non-not-found error — and asserted
  `CreateSecret` should proceed as if no duplicate existed. That fixture
  encoded the exact swallowed-error behavior this fix removes; per this
  repo's own "fix the fixture, don't weaken the assertion" rule, the mock now
  returns `storage.ErrSecretNotFound` instead of a generic error, so the test
  asserts the correct outcome for the correct reason.

## Red-proof

**Direction 1 (fuzzer seed):** reverting `secrets_versions.go`'s branch to the
pre-fix `if err == nil && latestVersion != nil` form and replaying
`1fefa95ddd2b26bb` reproduces the original `ORACLE (a) VIOLATION`.

**Direction 2 (deterministic tests):** reverting only the two behavioral call
sites in `secrets.go`/`secrets_versions.go` (keeping the `errors.go`/
`local_secrets.go` sentinel infrastructure, which the tests also depend on to
compile) makes both new tests fail with "An error is expected but got nil" —
confirming they exercise the fix, not an unrelated path.

Both directions confirmed restored to green after re-applying the fix, and
the full `internal/core` and `server/faultops` suites pass with no
regressions (`internal/storage/store` also run, needs `-timeout 20m`, a known
pre-existing harness limit unrelated to this fix).

## Semgrep rule: not in this PR

A draft rule matching this exact "checked only inside `if err == nil && ...`"
shape was prototyped (`.scratch-proposed-semgrep-rule.yml`, not committed) and
manually verified against `internal/core` — it would catch this finding's two
sites plus a handful of lower-severity/different-classification hits
(`versions.go:293` `RollbackSecret`, `audit_checkpoint.go:593`,
`dashboard.go:249`) that each need their own human judgment call. Left for a
separate follow-up PR: triage those hits, confirm it correctly excludes sites
already using an `IsXNotFound` guard, and land it warn-only with a baseline
file.

## Fuzz-world drift: reported, not fixed here

Per the above, `server/faultops/world_test.go` (and three sibling fuzz-world
builders: `internal/core/fuzzworld_test.go`, `internal/encryption/fuzzworld_test.go`,
`server/http/fuzzworld_test.go`) mirror production's manually-applied partial
unique indexes by hand instead of running the real migration, and had drifted
out of sync with `internal/storage/factory.go`'s current index set. This is
already being fixed on `fix/1947-fuzz-worlds-production-schema` (unpushed,
separate branch) via a shared `internal/testutil/fuzzworld` package built on
the real production migration path — not duplicated here.
