# G80 Phase 0 remediation notes

Internal record of the G80 finding and its Phase 0 fix — not customer-facing (no
production deployments exist; see the Severity correction below for why no security
advisory is warranted). This is the durable record of how the bug class was closed,
referenced from the wire-DTO code comment (`internal/storage/store/remote_secrets.go`).

## The bug

`storage.Storage.UpdateSecret` is implemented by both `LocalStorage` (a full GORM
`Save(secret)` — every field persists) and `RemoteStorage` (a narrow wire DTO). Before
this fix, `RemoteStorage`'s wire DTO (`secretUpdateWireRequest`) carried only `MaxReads`,
`Expiration`, and `ClearExpiration` — 3 of `models.SecretNode`'s ~28 persisted fields.
Any other field a caller mutated before calling `storage.UpdateSecret` was silently
dropped: the call returned success, but the hub's authoritative row was untouched.

## Call-site inventory (exhaustive, verified against the full working tree)

| File:line | Function | Field(s) mutated |
|---|---|---|
| `internal/core/secrets.go:297` | `UpdateSecret` (`applyUpdateSecretFields`) | `Type`, `Metadata`, `MaxReads`, `Expiration`/clear, (Phase 0 adds `Description`) |
| `internal/core/secrets.go:421` | `RotateSecret` (called via `RotateSecretOnDemand`) | `LastRotatedAt`, `UpdatedAt` |
| `internal/core/classification.go:86` | `ClassifySecret` | `Classification` |
| `internal/core/secret_ownership.go:89` | `TransferSecretOwnership` (public wrapper) / `transferOwnership` (shared primitive, also used by `ReassignOwnedSecrets`) | `OwnerID` |
| `internal/core/secret_move.go:94` | `MoveSecret` | `ParentID` |
| `internal/core/secret_bulk_rename.go:154` | `BulkRenameSecrets` | `Name` |
| `internal/core/secret_description.go:66` | `SetSecretDescription` | `Description` |
| `internal/core/rotation_executor.go:699` | `SetSecretAutoRotate` | `AutoRotate`, `RotationLength`, `RotationCharset`, `RotationBackend`, `RotationRef` |
| `internal/core/secret_extend_expiring.go:56` | `ExtendExpiringSecrets` | `Expiration` (already covered by the original 3-field DTO) |

No call site outside `internal/core` calls `storage.UpdateSecret` directly.

## Field classification

Every persisted field on `models.SecretNode` is classified in `updateSecretAllowlist`
(`server/http/handlers/secret_update_diff.go`) into one of three buckets:

- **Allowed** (plain `secrets.write`, no further gate): `Type`, `Description`,
  `MaxReads`, `Expiration`, `Metadata`.
- **Ignored** (hub-computed, client value never inspected): `UpdatedAt`.
- **Rejected** (server-owned, or gated by a check this endpoint cannot run):
  everything else — `ID`, `ProjectID`, `EnvironmentID`, `Name`, `IsSecret`,
  `ReadCount`, `Classification`, `Status`, `CreatedBy`, `OwnerID`, `IsShared`,
  `CreatedAt`, `LastRotatedAt`, `AutoRotate`, `RotationLength`, `RotationCharset`,
  `RotationBackend`, `RotationRef`, `CertNotAfter`, `DeletedAt`,
  `RetentionOverrideDays`, `ParentID`.

`LastRotatedAt` deserves a specific note: it looks like `UpdatedAt` (hub-computed,
client value shouldn't matter) but is deliberately classified **rejected**, not
ignored. `RotateSecret` leaves it unchanged on a byte-identical resubmission (#408 —
stamping it would falsely signal "recently rotated, low risk" for material that never
changed) and sets it to now on a real rotation. A generic field diff cannot distinguish
those two cases, and unconditionally stamping `now()` on any update through this
endpoint (e.g. a plain `Description` edit) would wrongly mark an unrelated secret as
just-rotated — reintroducing #408's exact failure mode. Recording a rotation needs its
own dedicated endpoint (tracked as follow-up work below), not a slot in the generic
allowlist.

## Audit-trail divergence (a distinct, more severe finding)

Every one of the five gated `internal/core` operations wrote its audit event
**unconditionally after `storage.UpdateSecret` returned a nil error**, with no check
that the field had actually persisted:

- `classification.go:91` — `LogSecretUpdatedWithDiff` with a before/after classification
  diff
- `secret_ownership.go:97` — `EventSecretOwnerTransferred`, including `{FromUserID,
  ToUserID}` in the audit detail
- `secret_move.go:104` — `EventSecretMoved`
- `secret_bulk_rename.go:158` — `LogSecretUpdatedWithDiff`, plus `report.Outcomes`
  marking the item `renamed`
- `rotation_executor.go:713` — `EventSecretAutoRotateConfig`, including
  rotation-backend binding details

Before this fix, in any code path that reached these functions through
`RemoteStorage`, the audit log would have recorded these changes as genuinely
happened — a classification downgrade, an ownership transfer, a rotation-backend
binding — when the hub's authoritative row was untouched. This is an affirmatively
false record, not merely a silent gap, and would have been the more serious finding of
the two had any of these operations been live-reachable (see below).

Phase 0 fixes this **as a structural consequence**, not via a separate code change:
every one of the five functions already checked `storage.UpdateSecret`'s error and
returned before writing its audit event. Making the write fail loudly (instead of
returning a false success) makes the existing `if err != nil { return }` guard do the
right thing automatically. `TestG80Phase0_ClassifySecret_RejectedInConnectedMode` and
`TestG80Phase0_SetSecretAutoRotate_RejectedInConnectedMode`
(`server/http/remote_storage_g80_secret_update_test.go`) assert this explicitly: a
rejected operation writes zero new audit events, for the two operations that can be
driven end-to-end (see the severity correction for why not all five could be).

## Severity correction

The original investigation (this document's own Step 1) characterized the bug as live:
"ownership transfers, moves, renames, classification changes, description edits and
rotation-backend bindings all return success to the operator while changing nothing on
the hub's authoritative row" in CLI connected mode. **This overstated live
exploitability.**

Tracing every real CLI command for the five gated operations found that **none of them
reach these `internal/core` functions via `RemoteStorage` at all.** `classify.go`,
`move.go`, `bulk_rename.go`, `reassign_owner.go`, `autorotate.go`, and `description.go`
(`internal/cli/secret/`) each check `common.NewRemoteClient()` first and, when
connected, make their own direct REST call (e.g. `PATCH /secrets/{id}/classification`)
— a code path entirely separate from `core.KeyorixCore` + `storage.Storage`.
`classify.go` has no embedded-mode fallback at all. A repo-wide search for real callers
of the five gated `internal/core` functions turns up only server-side HTTP/gRPC
handlers, which per ADR-083 (accepted) can never run against `RemoteStorage` (a server
cannot boot with `storage.type: remote`).

So the five gated operations were never reachable via `RemoteStorage.UpdateSecret` by
any code path that exists today. The only genuinely live path was
`internal/cli/secret/update.go`'s embedded-mode fallback (`storage.type: remote`
configured directly, no `keyorix connect`) — `core.UpdateSecret` →
`Type`/`MaxReads`/`Expiration`/`Metadata` (Phase 0 adds `Description`).

This does not make the fix unnecessary: `storage.Storage` is a documented interface
contract two implementations must both honor (ADR-083 explicitly preserves
`storage.type: remote` as "the CLI's actual, working use case"), and any current or
future caller constructing a `RemoteStorage`-backed core — a new CLI command, a script
embedding `internal/core` as a library, `examples/secret_crud/main.go`-style usage —
would hit the same class of bug. The `TestG80Phase0_ClassifySecret_*` /
`TestG80Phase0_SetSecretAutoRotate_*` end-to-end tests are deliberately framed as
guarding the contract for **future** callers, not as reproducing a live incident.

**Process lesson**: the original sweep enumerated call sites (every place a field is
mutated before `storage.UpdateSecret`) but never traced whether any of those call
sites is reachable from a real CLI entrypoint against `RemoteStorage`. Call-site
enumeration and reachability analysis are different questions — closing a bug class
requires both. Reachability analysis is now mandatory for findings in this campaign,
not just call-site enumeration.

## Two further pre-existing bugs surfaced while testing (separately tracked, not fixed here)

- **[#1511](https://github.com/keyorixhq/keyorix/issues/1511)** — 13 confirmed
  `RemoteStorage` wire calls have no matching `router.go` route at all (discovered via
  `CreateSecretVersion`, which meant on-demand rotation's value-persistence step fails
  with a hard 405 in connected mode, before ever reaching the `LastRotatedAt`
  question). Guarded going forward by
  `internal/storage/store/remote_wire_route_coverage_test.go`.
- **[#1512](https://github.com/keyorixhq/keyorix/issues/1512)** — ADR-083's
  `RemoteStorage.IsProjectMember` stub (`"not supported in remote storage"`) blocks
  `internal/core.CheckSecretPermission`'s owner fast-path, so even a secret's own owner
  cannot call `SetSecretDescription`, `TransferSecretOwnership`, or any other
  `EnforceSecretWritePermission`-gated function against a `RemoteStorage`-backed core.
  This is why `TransferSecretOwnership`, `MoveSecret`, `BulkRenameSecrets`, and
  `SetSecretDescription` could not be driven end-to-end in this fix's test suite —
  unrelated to G80, not fixed here.

## Follow-up work (not implemented in Phase 0)

One PR per gated operation, each with its own narrow `RemoteStorage` proxy method,
wire request, and dedicated hub endpoint that calls the same `internal/core` function
server-side so the authorization checks (SoD, `requireAdminAuthorityAt`, the G09
read-approval gate) run authoritatively at the hub — mirroring the existing
`TransitionSecretStatus` precedent. Suggested order, by how dangerously the current
silent no-op fails open (now moot for live risk per the severity correction above, but
still the right order for closing the latent/structural gap):

1. Classification (`ClassifySecret`)
2. Rotation config / backend binding (`SetSecretAutoRotate`) — and recording a
   rotation timestamp (`LastRotatedAt`), the same endpoint family
3. Ownership transfer (`TransferSecretOwnership`)
4. Move (`MoveSecret`)
5. Description (`SetSecretDescription`) — lowest priority; folding it into the generic
   allowlist (already done in Phase 0) may be sufficient permanently, since it has no
   authorization gate beyond plain `secrets.write`
6. Rename — research first whether a single-secret rename path exists outside
   `BulkRenameSecrets` before designing its wire shape

## G-series CI-triage campaign (C0–C5)

A separate, later effort against the same root problem class this document's "process
lesson" describes: a mechanism that handles a subset and stays silent about the rest.
This time the subset was CI coverage itself — three packages excluded from the go test
matrix since 2026-04-27 (`internal/core$`, `internal/cli$`, `server/http$`, plus
`internal/storage/remote`), one test's mock mismatch, and nobody watching for four
months. Living record of what's been found and fixed; update the relevant section as
each PR lands rather than appending a new one per PR.

### C0 / C0b — measuring the blind spot

`internal/core` (322 test files, dollar-anchored exclusion — `internal/core/storage` was
separately pinned into CI all along and never actually dark): **0 failures.** The
original excluding test, `TestListSecretsWithSharingInfo`
(`internal/core/sharing_indicators_test.go:176`), was rewritten by #1048 (2026-07-19,
ACL-grant surfacing) three months before this audit — verified directly with
`-run '^TestListSecretsWithSharingInfo$' -v`, not inferred from a clean package run. The
exclusion outlived the failure it was created for by about a month with nothing
surfacing that.

`internal/cli$` (dollar-anchored — only the 6-file top-level package was ever dark; the
~300 files under `internal/cli/...` have been in CI and green throughout, pinned across
`root-1/2/3`) and `internal/storage/remote` (4 files): both **0 failures.**

`server/http` (91 test files): **18 failures, 8 root causes**, triaged below.

### #1520 — re-enable `internal/core` in CI

First attempt folded `internal/core` into `root-4`'s catch-all leg: went red on the real
runner (605.014s against the leg's 600s budget) despite passing locally (369.6s,
`-race`, isolated). Fix: a dedicated `core` leg with a deliberately generous 1800s
timeout — a per-package timeout exists to catch hangs, not police a speed budget; tuning
to just past an observed duration risks the same intermittent-red outcome that let the
original exclusion look justified in hindsight.

**Isolating the leg did not measurably help**: 624.821s isolated vs. 605.014s contended.
If leg-level contention with other test binaries were the dominant cause, isolation
should have shown a real improvement — it didn't. The more likely explanation is that
GitHub's `ubuntu-latest` 2-core hosted runner is simply slower than the local
development machine for this race-heavy workload (~1.7x), independent of what else
shares the leg. **Record the cause as runner speed, not contention, in any future
writeup** — the contention narrative was the working hypothesis before this number, and
should not survive past it.

Follow-up, not urgent: #1523 (split the 323-test-file `internal/core` package — the
underlying symptom this timing problem is a symptom of).

### server/http — 18 failures, 8 root causes (triaged, C1–C4 below)

| Root cause | Tests | Disposition |
|---|---|---|
| Last-admin driver-token fixture (see C1 below) | 2 | C1 — fixture rebuilt |
| bcrypt fixture is 61 chars, `isPlausibleBcryptHash` requires 60 | 3 | C2 fix |
| CSV header assertion predates G25's added columns | 1 | C2 fix |
| Secret-dependency fixture uses nonexistent IDs 501/502 | 3 | C2 fix |
| `buildActiveSetupToken` never sets `SubjectUserID` | 5 | C2 fix |
| Risk-exception routes missing / method mismatch (#1511) | 4 | C3 quarantine |

### C1 — the last-global-admin invariant (fixed as a fixture bug, not a product bug)

**The invariant was never actually tested**, not stale. `createRBACDriverToken`
(removed; formerly `server/http/remote_storage_rbac_role_grants_test.go:33-57`) granted
its driver identity the `system_admin` role "purely to authenticate" the downstream
call. The server-side guard doesn't trust a wire-supplied admin-role set —
`RemoveGlobalAdminRoleGuardedProxy` (`server/http/handlers/rbac_role_grants_proxy.go:351`)
resolves its own list via `resolveInstallAdminRoleIDsProxy`, from
`breakGlassContainmentAdminRoleNames` (`server/http/handlers/break_glass_proxy.go:125`) —
`{"super_admin", "admin", "system_admin"}`, deliberately broadened by #G79 specifically
to stop a caller from undercounting admins via an incomplete wire-supplied set. So the
driver was itself a standing second admin from the moment it was created, in both
affected tests, before either test's first assertion ran. The code (guard, role-name
list) is correct; the test fixture was wrong.

Fix: swap the driver's authentication to `createNodeToken`
(`server/http/integration_test.go:109-130`, an existing helper already used by ~16 other
tests in this package) — a node-type machine credential, `ActorTypeMachine` with
`MachineIdentityType: core.MachineTypeNode`, never assigned any role. Verified at the
storage-query level, not inferred: `ListGlobalAdminAssignmentsForUpdate`
(`internal/storage/store/local_rbac.go:371-413`), which `RemoveGlobalAdminRoleGuarded`
calls to decide whether an admin survives, queries only `models.UserRole` and
`models.GroupRole` rows — no machine-identity table is referenced anywhere in that path,
so a node credential is structurally invisible to this guard regardless of what (if
anything) it might separately hold.

Shipped as three tests, not two: the original refusal test (now genuinely exercising a
single-admin state), a new standalone
`..._SucceedsWithSurvivingAdmin_RealServer` test (two real admins from the start,
assert removal succeeds — without it, a guard that always errored would still pass the
refusal test), and the existing concurrent-race test with an added explicit
"at least one global admin remains" assertion (`ListGlobalAdminAssignmentsForUpdate`'s
full result, not just the userA/userB-specific count already there).

Verified all three catch a broken guard, not just that they pass: temporarily forced the
guard to never refuse (both single-admin and concurrent-race tests correctly went red)
and separately forced it to always refuse (the new success test correctly went red).
Reverted both before this PR.

Separately investigated (out of scope for C1, not fixed): whether
`RequireNodeCredentialOrPermission`'s node-credential arm (`server/http/router.go:1069,1089`)
over-reaches elsewhere in the same `/system` route group. It does —
`AssignRoleWithExpiryProxy`/`AssignRoleToGroupWithExpiryProxy`
(`server/http/handlers/rbac_role_grants_proxy.go:97-135`) let a bare node credential
grant any role, including admin-tier ones, to any user or group, with no ceiling check
and no audit-log write on that path. Filed as #1524; not touched here.

### C2 / C3 / C4 / C5

Tracked in their own PRs as they land; this section gets filled in per PR, not ahead of
it.
