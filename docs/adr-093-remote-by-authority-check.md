# ADR-093: the `--by` authority check under `storage.type: remote` (#1575)

## Status

**Accepted (2026-08-30).** This is a design pass with one shippable floor,
not a credential-model change. Task 4 (a clear error message) ships in this
pass. Task 3's recommendation (Option B — declare the 11 commands
unsupported under `storage.type: remote`, documented, not silently) is
recorded as a decision but requires no code beyond Task 4's message, since
the underlying commands already fail — they just fail with an
uninformative stub error today. Option A (an operator-authenticated
credential model) is **not implemented** in this pass, per the explicit
guardrail: verdict and recommendation before any credential-model code.

## Context — restated precisely, because the obvious fix is a trap

`--by <admin-email>` means "perform this as, or on behalf of, user X." Every
account-lifecycle and invitation-management CLI command resolves `--by` to a
user ID, then calls `core.Authorize(ctx, actorID, permission, scope)` to
verify that resolved actor actually holds the permission the equivalent HTTP
route requires (#264, #491) — a deliberate, correct security check: without
it, a local operator could attribute an arbitrary destructive action to any
admin's identity in the audit trail. `Authorize` chains through
`scopedRoleIDs` → `storage.GetUserRoleIDsAt`/`GetUserGroupRoleIDsAt` →
`storage.RoleSetHasPermission`. All three are hard stubs on `RemoteStorage`
(ADR-086: implementing them over the wire would have the CLI fetch
role/permission data and decide authorization client-side — the fat-client
pattern this campaign has spent multiple rounds dismantling elsewhere). Under
`storage.type: remote`, the check can never pass, so all 11 commands fail
closed with `not supported in remote storage`.

**The stubs are not the bug. The local evaluation is.** A client deciding "is
X allowed to do this" from data it fetched is wrong regardless of whether the
data-fetching primitives are implemented — implementing
`GetUserRoleIDsAt`/`GetUserGroupRoleIDsAt`/`RoleSetHasPermission` over the
wire is **refused explicitly, with this reason recorded**, because it is the
fix that will suggest itself to the next person in about four minutes: it
looks like "just implement the stub," and it reverses ADR-086's own
considered decision. Do not implement it. If this pass — or any future one —
starts to look like the pragmatic path, stop and report instead of writing
the wire calls.

**The actual blocker is a credential model problem wearing an RBAC costume.**
The CLI authenticates to the hub with a static `storage.remote.api_key`, not
the operator's own session. The hub cannot derive who is acting from the
connection, so it cannot make the `--by` decision either, no matter where the
decision logic lives. This is why Option A (below) is architecturally
correct and Option C only earns its cost if the CLI genuinely cannot hold an
operator credential — which, as the investigation below found, it already
can, via a mechanism that already exists.

## Task 1 — the gating question: is there already another way to do these 11 things?

Every one of the 11 commands (`invite send/resend/revoke`, `migrate
user-to-machine`, `request list/review`, `user
revoke-sessions/suspend/reactivate/resend-setup-link/delete`) calls
`common.InitializeCoreService()` **unconditionally** — none has a
`NewRemoteClient()`/`ResolveRemote()`/`IsClientMode()` guard anywhere in its
file. So there is no alternate path via the SAME CLI command using a real
per-operator session — the command architecture never offers that branch.
The question that matters is whether the underlying *operation* is reachable
another way.

It is, for all 11, confirmed by direct route inspection (not inferred):
every one has an ordinary, human-facing, `RequirePermission`/
`RequireScopedPermission`-gated HTTP route — outside the `/system`
server-to-server proxy tier entirely — that performs the identical
`internal/core` operation, authorized correctly against the caller's own
real session (from `keyorix connect`, a direct API call, or a future web UI),
not a `--by` claim against a shared static key.

| # | Command | HTTP route | Permission | Citation |
|---|---|---|---|---|
| 1 | `invite send` | `POST /projects/{id}/invitations` (or `POST /invitations`, global) | `roles.assign` (project) / `users.write` (global) | router.go:479,485 |
| 2 | `invite resend` | `POST /projects/{id}/invitations/{id}/resend` | `roles.assign` | router.go:482 |
| 3 | `invite revoke` | `DELETE /projects/{id}/invitations/{id}` | `roles.assign` | router.go:480 |
| 4 | `migrate user-to-machine` | `POST /projects/{id}/machine-identities/migrate-from-user` | `roles.assign` (project) + `users.write` (global) | router.go:517-519 |
| 5 | `request list` | `GET /projects/{id}/access-requests` | `roles.assign` | router.go:489 |
| 6 | `request review` | `PUT /projects/{id}/access-requests/{id}` | `roles.assign` | router.go:491 |
| 7 | `user revoke-sessions` | `POST /users/{id}/revoke-sessions` | `users.write` | router.go:876 |
| 8 | `user suspend` | `POST /users/{id}/suspend` | `users.write` | router.go:878 |
| 9 | `user reactivate` | `POST /users/{id}/reactivate` | `users.write` | router.go:879 |
| 10 | `user resend-setup-link` | `POST /users/{id}/resend-setup-link` | `users.write` | router.go:882 |
| 11 | `user delete` | `DELETE /users/{id}` | `users.delete` | router.go:853 |

Every handler was confirmed to delegate to the SAME `internal/core` function
the CLI command calls (e.g. `MigrateUserToMachine`'s handler and the CLI
command both call `core.MigrateUserToMachine`) — not a narrower or
differently-scoped feature.

**A twelfth command with the identical shape, found in the same trace, not
in the original 11:** `user force-password-reset` shares `runLifecycle` (the
same helper `suspend`/`reactivate` use) and `requireUserAuthority`, and has
its own ordinary route (`POST /users/{id}/require-password-reset`,
router.go:880). Included in Task 4's fix at zero extra cost, since it is the
identical code path.

**Answer: yes for all 12.** Per this task's own framing, "unsupported under
remote, use the hub" is a legitimate answer, not a cop-out — account
lifecycle and invitation management are hub-side operations by nature, and
the ordinary route already authorizes correctly using the operator's own
identity, which `--by` against a shared key never did.

## Task 2 — how do the stubs fail, and can any caller read the failure as allow?

**All three stubs already return an explicit error**, not a zero value alone:

```go
func (rs *RemoteStorage) GetUserRoleIDsAt(...) ([]uint, error) {
    return nil, fmt.Errorf("not supported in remote storage")  // now remoteUnsupported(...) — see below
}
```

Every call site of all three primitives, repo-wide (confirmed: zero callers
exist outside `internal/core`), was traced to a verdict:

| Call site | Function | Verdict |
|---|---|---|
| `authz.go:342,346` | `scopedRoleIDs` | **FAIL CLOSED** — propagates `(nil, err)` before the second call even runs |
| `authz.go:199-206` | `AuthorizePrincipal` (machine branch) | **FAIL CLOSED** — returns `RoleSetHasPermission`'s `(bool, err)` verbatim; caller checks `err` |
| `authz.go:236` | `Authorize` | **FAIL CLOSED** — same |
| `authz.go:258` | `principalHasScopedPermission` | **FAIL CLOSED** — same |
| `project_members.go:173,180` | `guardLastProjectAdmin` | **FAIL CLOSED** — an error here BLOCKS the role demotion/removal it guards (the safe direction: refuse rather than risk a governance gap) |
| `project_members.go:225` | `resolveProjectAdminHolders` | **FAIL CLOSED** — propagates to the guard above, which blocks |
| `project_members.go:314` | `projectAdminScopesHeldByGroup` | **FAIL CLOSED** — propagates to `guardLastProjectAdminGroupDelete`/`...GroupMembership`, both of which refuse the group delete / membership removal on error (confirmed at their own call sites in `groups.go`/`scim_groups.go`) |
| `project_members.go:353` | `guardProjectAdminSurvivesGroupChange` | **FAIL CLOSED** — same |
| `break_glass.go:122` | `ActivateBreakGlass` (emergency-role safety check) | **FAIL CLOSED** — an error refuses break-glass activation entirely, rather than letting an unchecked role through |
| `sod.go:356,364` | `machineSoDViolations` | **CLOSED, not a bypass — advisory/detective control.** On error, calls `report.degrade(...)` and `continue`s rather than propagating a hard error. This does NOT grant access (SoD scanning is purely detective, not a gate) — but a real violation for that machine/policy pair would go unreported. The report's `Degraded` field is public (`json:"degraded"`) and explicitly signals "this scan is incomplete" to the consumer — the #492 fix already hardened this from an earlier version that silently discarded the same errors. Not a caller "treating empty as nothing to check": it explicitly flags what it couldn't check. |

**No fail-open call site exists.** This sweep lists every hit, not just the
interesting ones, per the standing instruction that a sweep listing only
hits is indistinguishable from one that never looked.

**The structural fix Task 2 asks for — make the stubs return an explicit
error rather than a zero value — was already true before this pass.** There
is no code change needed for that specific ask; the finding is that it was
already done correctly. What this pass DID change: the three stubs'
`fmt.Errorf("not supported in remote storage")` now wraps the shared
`storage.ErrUnsupportedByBackend` sentinel (via `remoteUnsupported(...)`,
matching every other stub in the package), so callers can distinguish "this
backend cannot evaluate the check at all" from "the actor genuinely lacks
the permission" via `errors.Is`, instead of parsing internal error text.
This is a pure error-identity change — the stubs still refuse, unconditionally,
exactly as before; nothing about ADR-086's "keep these stubbed" decision
changes.

## Task 3 — the option set

**A — the operator authenticates.** Per-operator credential or session
token instead of the shared static key; the hub derives the actor from the
connection and decides. `--by` either disappears (the operator IS the
actor) or becomes real, gated impersonation.

Architecturally correct, and — this is the refinement this investigation
found — **cheaper than assumed.** The CLI already has this mechanism:
`keyorix connect <endpoint>` (`internal/cli/connect/connect.go`) performs a
real per-operator login (interactive credentials or a non-interactive
`--api-key`, e.g. a PAT tied to one specific admin) and persists a real
session to `~/.keyorix/cli.yaml`, read by `ResolveRemote()` — the exact
mechanism nearly every OTHER CLI command already uses for `storage.type:
remote`. The realistic form of Option A is not "redesign the credential
model repo-wide" — it is "give these 12 specific commands a
`NewRemoteClient()`-guarded branch that POSTs to the ordinary routes Task 1
found, mirroring the shape their siblings already have." Once that exists,
`--by`'s authority question dissolves: the hub authorizes the request using
the real session's own actual permissions, the same way the web UI would,
with no impersonation claim to verify at all. If deliberate on-behalf-of
action is still wanted, it needs a real, separately-gated impersonation
permission — not `--by`'s unauthenticated claim.

Cost: a bounded, scoped addition to 12 command files (not "every remote CLI
path" — the other paths already have this shape). Not implemented in this
pass, per the guardrail.

**B — unsupported, and say so.** Declare the 12 out of scope under
`storage.type: remote`. Viable exactly because Task 1 found all 12 reachable
another way — this is not a compromise that leaves functionality
unreachable, it is documentation catching up to what was already true.

**C — delegation token.** Operator authenticates once, receives a
short-lived token carrying their identity, presents it per command. This is
Option A with more moving parts, and it earns its cost only if the CLI
cannot hold an operator credential directly. There is no such reason here —
`keyorix connect` already holds one, durably, today. **C is not recommended**
for that reason.

**Refused explicitly: implement the three primitives over the wire.**
Reverses ADR-086. Rebuilds the fat client the wire-actor bug class already
taught this campaign not to trust: a client's claim about who is authorized
is not a substitute for the hub's own decision, and implementing the stubs
would make the CLI fetch role/permission data and render that verdict
itself. Refused with this reason recorded, not merely left undone, because
it is the fix that looks obvious.

### Recommendation: B, with the limitation named plainly, not filed as solved

Task 1 found all 12 operations reachable via the ordinary, already-correct
HTTP surface. Given that, spending Option A's cost now — even at its cheaper,
scoped estimate — is not justified by this pass alone; it is real design and
implementation work with its own review cycle. **Recommend B for this pass**:
ship Task 4's clear error message (below), document the limitation, and defer
Option A to a future pass, tracked as Wave 2 per the original issue (unifying
#1546, #1551, #1572, #1575 — all the same underlying question of where
authority gets evaluated).

**The limitation Option B leaves, stated because #1575 itself asked for
this:** with a shared static key, anyone holding it can name any actor in
`--by` for the OTHER commands that still work under `storage.type: remote`
(the ones that don't hit this specific stub chain) — the check this ADR is
about is not the only place `--by`-style attribution exists, and Option A is
what makes `--by` mean something, not merely what makes these 12 commands
run. Recording B as the recommendation for THIS pass does not resolve that;
it is a known, named limitation, not a solved problem.

## Task 4 — the floor, shipped this pass

Every one of the 12 affected commands now fails with a message naming the
cause and the alternative, instead of the raw stub text. Implemented via
`common.ByAuthorityUnavailableError(err, alternative)`
(`internal/cli/common/by_authority.go`): checks `errors.Is(err,
storage.ErrUnsupportedByBackend)` (now reliably detectable, per Task 2's
sentinel-wrapping fix) and returns a message naming the cause plus a
command-specific alternative (Task 1's finding); falls through to the
original `"failed to verify --by authority: %w"` wrapping for a genuine,
unrelated storage error (confirmed unchanged by
`migrate_authorize_error_test.go`'s two error-injection tests, which assert
exactly that fallback text and pass unmodified).

Example (`user suspend` under `storage.type: remote`, exercised against a
real hub, not asserted):

```
Error: --by authority evaluation is not available against a remote backend
(storage.type: remote): the check depends on server-internal RBAC
primitives RemoteStorage never implements, by design (ADR-086) — run the
equivalent request directly against the hub instead -- POST
/api/v1/users/{id}/suspend, /reactivate, /revoke-sessions,
/resend-setup-link, or /require-password-reset, or DELETE
/api/v1/users/{id} -- authenticated with your own real session (e.g. via
'keyorix connect'), since the hub, not this shared credential, decides who
may act
```

Fixed call sites (6 helper functions covering all 12 commands):
`requireUserAuthority` (user.go — suspend/reactivate/force-password-reset/
revoke-sessions/delete), `requireInviteAuthority` (invite/send.go — send/
resend/revoke), `requireReviewAuthority` (request/review.go),
`requireListAuthority` (request/list.go), `requireMigrationAuthority`
(migrate/user_to_machine.go, both `Authorize` calls), and
`requireTemplateAuthority` (request/bulk.go — a sibling using the identical
mechanism for `request rejection-templates add/list/delete`, not one of the
original 11 but fixed at the same cost since it shares the same helper
shape; its own ordinary HTTP routes confirmed at router.go:499-501).

## Verification

- All 12 commands exercised against a real hub server under `storage.type:
  remote` (bootstrapped, logged in, CLI pointed at it via `KEYORIX_CONFIG_PATH`)
  — each produces the new message, confirmed by direct output inspection, not
  asserted from reading the code.
- Every Task 2 call site has a verdict (table above); the stub-wrapping
  change (`remoteUnsupported(...)` instead of a bare `fmt.Errorf`) compiles
  clean with every caller — `go build ./...`/`go vet ./...` clean.
- Full suites green: `internal/cli`, `internal/core`, `internal/storage`,
  `server/http`.
- Positive control: the existing per-function test suites
  (`by_authority_test.go`, `send_authority_test.go`,
  `review_authority_test.go`, `list_template_authority_test.go`,
  `user_to_machine_authority_test.go`, and their siblings) exercise these
  same functions against `LocalStorage` with real authorization decisions and
  pass unchanged — the embedded (non-remote) path is untouched by this pass.
- `gofmt -l` clean on every touched file.

## Consequences

- `storage.type: remote`'s documented limitation grows by one precise
  sentence class: account-lifecycle and invitation-management commands (12,
  listed above) fail with a clear, actionable message under this storage
  type; every one has a working equivalent via an authenticated HTTP call to
  the hub (`keyorix connect` + the ordinary route, or a future client-mode
  branch on these commands — Wave 2/Option A).
- `storage.ErrUnsupportedByBackend` is now the wrapped sentinel for these
  three specific stubs, matching the rest of `RemoteStorage`'s stub surface.
  No behavior change for any caller relying on "an error occurs" — only the
  error's identity improved.
- Option A (operator-authenticated credential model) remains undesigned and
  unimplemented. This ADR records its real cost estimate (scoped to 12
  command files, not a repo-wide credential-model change, since `keyorix
  connect` already provides the mechanism) for whoever picks up Wave 2.
- The refusal to implement the three primitives over the wire is recorded
  here explicitly so it does not need re-deriving next time someone reaches
  this issue.
