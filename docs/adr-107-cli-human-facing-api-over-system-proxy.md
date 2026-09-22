# ADR-107: CLI client mode should call the human-facing REST API, not raw-storage-proxy over `/system`

## Status

**Proposed.** This is a design document only — nothing in this ADR has been
implemented. It formalizes and extends a pattern that, per the investigation
below, is **already the dominant real-world CLI code path** — this ADR's
practical effect is closing off the narrower path that remains, not building
something new.

## Context

`fix/system-proxy-target-authority`'s own finding doc
(`docs/findings/2026-09-21-FINDING-system-proxy-target-authority.md`) found
11 `/api/v1/system` proxy routes gated only by the blanket `system.write`
permission when their real, human-facing REST equivalents require a
narrower, differently-scoped permission. Each of the 10 fixed findings
required hand-deriving the correct authority check a second time, at the
proxy layer, because the raw-storage-proxy design means every `/system`
route reimplements whatever authority check its human-facing HTTP sibling
already has. This is exactly the class of defect this repo's own CLAUDE.md
warns about under "prefer the machine-checked over the asserted": a
hand-written artefact (the proxy's own authority check) duplicating a truth
already stated elsewhere (the human-facing route's check) does not stay
correct — it decays silently until someone finds the gap by hand, which is
what this whole campaign was.

ADR-083 (Accepted) already established that `storage.type: remote` — the
config that backs `RemoteStorage`, the Go client implementing
`storage.Storage` by calling `/system/*` routes over HTTP — is a CLI/client
mode only; no downstream server topology can exist
(`validateRemoteStorageNotServer`, `internal/config/config.go`). ADR-102
(Proposed, still open) separately found `system.write` reaches 148 routes —
essentially the entire administrative surface — and left open whether that
capability is intentionally break-glass-broad or a scoping defect. This ADR
does not resolve ADR-102's question; it proposes removing CLI as a reason
the `/system` surface needs to exist at all for the routes this applies to,
which narrows whatever ADR-102 eventually decides onto a smaller remaining
surface.

### What this branch's own caller inventory found, and what a deeper trace found underneath it

This branch's Step 2 caller inventory (informal, conversational) traced
`core.KeyorixCore` method call chains and concluded 4 of the 10 fixed routes
have a real CLI caller: `UpdateUserIfActiveStateMatchesProxy` (F5, via CLI
`user update`), `CreateGroupProxy`/`UpdateGroupProxy`/`DeleteGroupProxy` (via
CLI `group create`/`update`/`delete`), and `UpdateInvitationProxy` (via CLI
`invite revoke`) — all reached through `internal/cli/common.InitializeCoreService()`,
which under client mode (`storage.type: remote`) constructs a
`core.KeyorixCore` backed by `RemoteStorage`.

Tracing the actual CLI command source for all five of those commands (not
just the core-method call graph) found each one has an **earlier** branch
that the inventory's core-layer trace didn't see:

```go
// internal/cli/user/update.go, internal/cli/group/{create,update,delete}.go,
// internal/cli/invite/revoke.go — identical shape in every one:
if rc, ok := common.NewRemoteClient(); ok {
    // raw HTTP call to the HUMAN-FACING route, e.g. PUT /api/v1/users/{id}
    return runUpdateRemote(rc, active)
}
service, err := common.InitializeCoreService()  // only reached if NewRemoteClient() fails
```

`common.NewRemoteClient()` and `common.InitializeCoreService()`'s client-mode
branch (`internal/cli/modes.go`'s `initClientMode`) resolve their
endpoint/token from **overlapping config sources**
(`common.ResolveRemote()`: `KEYORIX_SERVER`/`KEYORIX_TOKEN` env vars,
`~/.keyorix/cli.yaml` in client mode, then `./keyorix.yaml`'s
`storage.type: remote` block as a last resort) — so in essentially every real
deployment where a client-mode config exists at all, `NewRemoteClient()`
succeeds and the command returns immediately via a raw HTTP call to the
**human-facing** REST route, never reaching `InitializeCoreService()`,
`RemoteStorage`, or `/system` at all. The `RemoteStorage`/`/system` path for
these five commands is reachable only in a narrow edge case: a config that
`ValidateRemoteEndpointURL` (which `ResolveRemote()` checks) rejects as
malformed but that `initClientMode` (which does not validate the URL at
construction time) would still accept.

Repo-wide check, not just these five files: of the CLI command files that
call `InitializeCoreService()` at all, only 3 do **not** also have a
`NewRemoteClient()` branch — `internal/cli/common/common.go` (the function
definitions themselves), `internal/cli/config/cli_config.go`, and
`internal/cli/main.go` (bootstrap/wiring, not a business-logic command). Every
actual command file that calls `InitializeCoreService()` also has a
`NewRemoteClient()` branch checked first. This was spot-checked directly on
five files (the four above, plus this file-list comparison across the
package) — it was **not** traced per-command to confirm the two branches
always cover the exact same operation (a file could theoretically have a
`NewRemoteClient()` branch for one subcommand and an `InitializeCoreService()`-
only branch for a different capability in the same file). That per-command
confirmation is Phase 0 below, not assumed here.

**This means the "CLI needs `RemoteStorage`" premise behind keeping these 5
routes' authority fixes reachable is narrower than the caller inventory's
framing suggested** — real, but a rare fallback, not the primary path. It
does not change anything about whether this branch's fixes were correct
(a rare caller is still a caller, and the authority gap was real regardless
of call frequency) — flagged here as a correction to the inventory's
framing, not a reason to revisit the fixes themselves.

## Decision

CLI client mode's primary — and, after Phase 1 below, only — path for every
operation that has a human-facing REST equivalent is a direct HTTP call to
that REST API (the same one the web UI uses), via `common.RemoteClient`.
`core.KeyorixCore` backed by `RemoteStorage` (the raw-storage-proxy-over-
`/system` path) is retired as a CLI code path for those operations. This is
already true today for the overwhelming majority of CLI commands in
practice (see above); this ADR proposes making it true structurally, by
removing the `InitializeCoreService()`-under-client-mode fallback those
commands currently still carry as dead weight.

## Route count this would remove

**At least 11 of the 148 `/system` routes**, with high confidence more:

- The 6 routes (+`MarkTOTPStepUsedProxy`, 7 total) this branch's Step 2
  caller inventory already found have **zero** real caller today
  (`CreateSecretDependencyExclusiveProxy`, `TransitionSecretStatusProxy`,
  `RestoreGroupProxy`, `ExpireSetupTokenProxy`, `UpdateWebAuthnCredentialProxy`,
  `RevokeBreakGlassActivationProxy`, `CreateAccessReviewCampaignProxy`,
  `CreateAccessReviewItemsProxy`, `UpdateAccessReviewItemProxy`,
  `MarkTOTPStepUsedProxy` — 10 routes, already slated for the
  `chore/delete-uncalled-system-routes` branch, independent of this ADR.
- **5 more** (`UpdateUserIfActiveStateMatchesProxy`,
  `CreateGroupProxy`/`UpdateGroupProxy`/`DeleteGroupProxy`,
  `UpdateInvitationProxy`) become zero-caller once Phase 1 (below) removes
  their narrow `InitializeCoreService()` fallback — joinable to the same
  delete branch at that point.

That accounts for 15 of the 11-finding routes this campaign touched (note:
`MarkTOTPStepUsedProxy` was never one of the 10 *fixed* routes, so "11
findings" and "15 routes above" aren't the same count — 10 fixed + 1 open +
the 4 already-zero-caller routes among the fixed set overlap). The `/system`
group has 148 routes total; this investigation did not trace CLI callers for
the ~130+ routes outside this campaign's own 11 findings. Given the pattern
found here — every CLI command file with an `InitializeCoreService()` call
also has a `NewRemoteClient()` branch — it is likely many more of the 148
are in the same shape, but that requires the same per-file trace this ADR
did for 5 files, done for the rest. **Not claimed here**: a full 148-route
count. That is Phase 0/1's own deliverable, not a number this ADR invents in
advance.

**Routes NOT removable by this decision**: any `/system` route with no
human-facing REST sibling at all (CLI would need a *new* endpoint, not a
redirect — Phase 2), and anything intentionally serving a non-CLI purpose
this investigation didn't find evidence of (none confirmed; `/system` was
designed for a downstream-relay topology ADR-083 already closed, so a
surviving non-CLI purpose would itself be a new finding, not an assumption
this ADR makes).

## What the CLI loses

**Investigated directly for the 5 routes this campaign's findings touch, and
the answer is: nothing.**

- **`UpdateUserIfActiveStateMatchesProxy` (F5)**: its raw-proxy CAS
  (`WHERE id = ? AND is_active = ?`) exists to let a caller replay an
  already-computed conditional write atomically. But `core.UpdateUser`'s
  deactivating branch (`internal/core/users.go`) — the SAME method the
  human-facing `PUT /api/v1/users/{id}` route calls end-to-end — already
  routes through that identical conditional write internally, every time,
  regardless of caller. The raw proxy's CAS was never something the CLI
  itself performed; it was always performed server-side. Migrating to the
  human-facing route doesn't lose the CAS, it **removes a redundant round
  trip and a stale-read window**: today, CLI client-mode (`InitializeCoreService`
  path) does `GetUser` (one round trip) then `UpdateUserIfActiveStateMatches`
  (a second round trip) against its own locally-computed `deactivating`
  bool — two round trips with a race window between them. Calling
  `PUT /api/v1/users/{id}` directly is one round trip, and the CAS decision
  is made server-side against a single, current read.
- **`CreateGroupProxy`/`UpdateGroupProxy`/`DeleteGroupProxy`**: no CAS/
  conditional semantics found in either the raw proxy or `core.CreateGroup`/
  `UpdateGroup`/`DeleteGroup` — ordinary CRUD. Nothing to lose.
- **`UpdateInvitationProxy`** (backing `core.RevokeInvitation` via CLI
  `invite revoke`): same shape as F5. `core.RevokeInvitation`
  (`internal/core/invitations.go`) already does the read-check-conditional-write
  sequence against `storage.UpdateProjectInvitation`'s own
  `WHERE id = ? AND state = 'pending'` CAS internally — and a real
  human-facing REST sibling already exists and is already used:
  `DELETE /projects/{id}/invitations/{invitationId}` → `CatalogHandler.RevokeInvitation`,
  gated by `roles.assign` scoped to the project — the exact authority this
  branch's own fix reproduced by hand at the `/system` proxy layer. CLI
  switching to this route loses nothing and gains one fewer authority check
  to keep in sync by hand.

**Not yet investigated**: the other ~143 `/system` routes. The package docs
on this branch's own touched files name at least two other routes with
explicit CAS/TOCTOU framing not examined here —
`TransitionMachineIdentityState` and `TransitionSecretStatus` — where a
genuine capability gap is more plausible (both are explicitly about a
downstream caller replaying an atomic state transition, not incidental
proxy design). These are real, not hypothetical: they were found by grep,
not assumed clear. Phase 2 below is specifically for routes like these.

## Migration order

**Phase 0 — verify, no code change.** For every CLI command file with both
an `InitializeCoreService()` branch and a `NewRemoteClient()` branch,
confirm they cover the exact same operation (not two different capabilities
sharing a file). This investigation spot-checked 5 files and found the
pattern holds; extend to the full ~50-file list mechanically (a diff read,
not new logic).

**Phase 1 — delete the fallback (low risk, confirmed no capability loss).**
For every command Phase 0 confirms, remove the `InitializeCoreService()`-
under-client-mode fallback: CLI in client mode either succeeds via
`RemoteClient` against the human-facing REST API, or fails loudly with a
clear "remote configuration required" error — it never silently falls
through to a raw storage-proxy call a user didn't ask for. Named candidates
already confirmed by this ADR: `internal/cli/user/update.go`,
`internal/cli/group/{create,update,delete}.go`,
`internal/cli/invite/revoke.go`. This alone makes
`UpdateUserIfActiveStateMatchesProxy`, `CreateGroupProxy`, `UpdateGroupProxy`,
`DeleteGroupProxy`, and `UpdateInvitationProxy` zero-caller, joinable to
`chore/delete-uncalled-system-routes`.

**Phase 2 — new REST capability first (higher risk, do not start speculatively).**
For any `/system` route Phase 0's full trace finds is reachable *only*
through `InitializeCoreService()` with no `NewRemoteClient()` sibling in its
command file (none confirmed yet — Phase 0 found zero among the 5 checked,
but the full ~50-file trace isn't done), and for the two named CAS-shaped
routes above (`TransitionMachineIdentityState`, `TransitionSecretStatus`) if
CLI is later found to genuinely depend on them: design and add the missing
REST capability (e.g., a conditional-PUT semantics on the existing
human-facing route, following the same "server owns the CAS end to end"
pattern F5 and UpdateInvitation already demonstrate is sufficient) before
that command can drop the raw-proxy path. Not started here.

**Phase 3 / out of scope.** The 10 already-zero-caller routes
(`CreateSecretDependencyExclusiveProxy` through `MarkTOTPStepUsedProxy`) —
handled entirely by `chore/delete-uncalled-system-routes`, independent of
whether this ADR is ever accepted.

## Consequences

**Positive.**

- Removes the duplicated-authority-check surface this security campaign had
  to hand-audit and hand-fix, for every route this migration reaches — the
  human-facing REST route's own `RequirePermission`/`RequireScopedPermission`
  check becomes the *only* check for that operation, not a second one a
  `/system` proxy has to independently re-derive and can silently drift
  from.
- Once `/system`'s CLI-facing routes are gone, a `chi.Walk`-driven
  completeness test over `/api/v1/*` (excluding whatever legitimately-
  narrow surface remains) can assert every mutating route enforces some
  permission check — the same structural guarantee
  `TestSystemWriteOnlyCeilingWalk` gives today for `/system` specifically —
  without needing a second, hand-maintained ceiling test for a proxy tier
  that duplicates the primary API's authority model.
- Matches this repo's own stated preference order (CLAUDE.md: "prefer the
  machine-checked over the asserted") — one source of authority truth per
  operation, not two kept in sync by hand.

**Negative.**

- Phase 2's scope is genuinely unknown until Phase 0's full trace runs — if
  it turns up real CAS-dependent commands with no REST equivalent, those
  need new API surface before they can migrate, which is real engineering
  effort, not just deletion.
- CLI response shapes for migrated commands already differ slightly from
  the raw-proxy shape in practice (confirmed: `runUpdateRemote` in
  `user/update.go` already parses a different response struct than the
  embedded-mode branch) — this is pre-existing, not newly introduced by
  this ADR, but any command still on the `InitializeCoreService()` path
  today will need its output format double-checked against the RemoteClient
  branch's existing shape when Phase 1 removes the fallback.
- This ADR does not resolve ADR-102's open (a)/(b) blast-radius question for
  `system.write` — it narrows the surface ADR-102 eventually applies to,
  nothing more.

## Open questions (not resolved by code reading — need a product/architecture decision)

1. Should Phase 1's fallback removal happen per-command as each is verified
   (rolling), or as one batch once Phase 0's full trace is done? Affects how
   much of the CLI surface is mid-migration at once.
2. Is there any deployment shape (e.g., an intentionally storage-only,
   REST-API-less "hub" configuration) where CLI genuinely needs the raw
   `RemoteStorage` path as a deliberate fallback rather than dead weight?
   Nothing in the code or existing ADRs suggests one exists, but this ADR's
   investigation was scoped to the 5 routes this campaign's findings touch,
   not an exhaustive deployment-topology audit.
3. Once Phase 1 and the `chore/delete-uncalled-system-routes` branch both
   land, does `RemoteStorage` still need to exist as a `storage.Storage`
   implementation at all, or does CLI client mode collapse entirely onto
   `RemoteClient` (a plain REST client, no `storage.Storage` interface
   conformance)? That is a larger question than this ADR — flagged, not
   answered.
