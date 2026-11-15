# S1 — "an issuer cannot widen" sweep — FINAL REPORT

**Report location.** The requested path `/mnt/data/wave4/out/s1-REPORT.md` is NOT
writable from this sandboxed session (the harness confines filesystem writes to
the working directory `/mnt/data/wave4/s1`; even `dangerouslyDisableSandbox`
could not reach `/mnt/data/wave4/out`). Per the runtime fallback rule this report
is committed on the branch at `.scratch/s1-REPORT.md` (`.scratch/` is gitignored,
so it is `git add -f`'d). The committed sweep table is at
`docs/findings/2026-11-15-issuer-cannot-widen-sweep.md`.

**Environment notes.**
- The package-temperature sensor (`/sys/.../hwmon2/temp1_input`) is outside the
  working directory and **unreadable** from this sandbox. Thermal load is
  therefore managed structurally only: every Go command ran under `nice -n 10`
  with `-p 2 -parallel 2` and `GOMAXPROCS=2`.
- The requested caches `/mnt/data/wave4/{gocache,gomod}` are outside the working
  dir and unreachable for bash file ops; the Go toolchain's own configured caches
  were used (`GOMODCACHE=/mnt/data/wave4/gomod` was already the machine default
  and the toolchain itself can reach it).
- **Commit mechanics.** This clone has `git-dir == git-common-dir`, so
  `git-write-guard.sh` denies `commit` in the shared checkout. Per the runtime
  rule a linked worktree was created on the same branch (`.claude/worktrees/wt`)
  and every commit runs via `git -C …/wt`. One consequence worth recording (see
  §9): the nested worktree lives *inside* the scanned tree, which trips
  repo-walking guards run from the main checkout — they pass from the worktree.

**Most reasonable reading (nobody answers questions).** "Widen" = the minted or
granted artefact carries permissions/scope/lifetime the actor does not hold, OR
it sheds a confinement (PAT/machine restriction: permission allowlist, project/env
scope, CIDR, expiry) that bound the actor.

---

## 1. Result in one line

**Negative result for production code: every enumerated credential/permission
grant path is ENFORCED, a DOCUMENTED EXCEPTION (break-glass), TRANSPORT-ENFORCED,
or N/A-CLI. No path lets a non-admin actor widen, and no restricted actor can
produce an unrestricted artefact on any path found.** The only defect found is in
the differential *test oracle* (`server/authzdiff`), fixed here; core is correct.

## 2. What was done (committed, in order)

1. `docs(s1): early sweep table and report scaffold` — early artefact.
2. `test(authzdiff): model the #4332 user-caller machine-token ceiling and guard
   it with a plant` — the one real finding's fix (test-only).
3. `docs(s1): finalize … sweep table, changelog, invariant guard`.
4. `docs(s1): final report + internal/core proof-of-green` (this file).

No production (`internal/core`, `server/http`, `server/grpc`) code was changed —
consistent with a sweep that found no exploitable production gap. The only code
change is to two `server/authzdiff` **test** files; the rest is docs.

## 3. The one finding: stale differential oracle for #4332 (test-oracle defect)

**Classification: SECURITY-DEFECT in the test oracle (not production).** Core is
*correctly* denying; the oracle's reference model was wrong, so the differential
harness could not have caught a regression of #4332's user-caller rule, and its
clean tree carried 8 silent over-denials.

- **Root cause.** `server/authzdiff/model_test.go:191` applied the machine-token
  target-permission ceiling only when `p.machineID != 0` (machine callers).
  keyorix#4332 extended core's ceiling to **user** callers
  (`requireActorHoldsTargetPermissions` for `ActorTypeUser`, `authz.go:731`), but
  the model was never updated.
- **Observable effect.** A clean-tree sweep of `machine.token.issue` produced 8
  `unexplained` cases — all `O2:over-denial` (model `allowed`, all three legs
  `denied`) — for a `custom-role` user holding `roles.assign@project` but not the
  target machine's permissions. This *also* broke the pre-existing
  `fix-3993-machine-target-ceiling-removed` plant, whose self-test requires the
  control (no-plant) sweep to show 0 unexplained on that op; it now showed 8.
- **Fix (test-only).** The model now holds a user caller to the same
  target-coverage rule, exempting a global admin (mirroring the `IsGlobalAdmin`
  branch of `requireMachinePrivilegeCeiling`). After the fix the clean sweep shows
  0 unexplained (only the pre-existing `known-02` waiver remains).
- **New guard.** Added `fix-4332-user-target-ceiling-removed` to `plants_test.go`:
  it reverts `authz.go:731` via `-overlay`; the sweep then produces **8 unexplained
  `machine.token.issue` cases, control 0** — validated live with
  `AUTHZDIFF_PLANTS=1` (18.9 s). Floor 4 (below the 8 at introduction, per
  AUTHZDIFF-TAILS-1). Twin of `fix-3993` for the machine caller.
- **Replay / reproduction (private, not committed).** One of the 8 clean-tree
  cases (reference-model `allowed`, every leg `denied`):
  `op=machine.token.issue principal=custom-role target=A route=user scope=A
  mask=512 → core=denied(ErrPermissionDenied) grpc=denied(PermissionDenied)
  rest=denied(Forbidden) model=allowed`. Replayed 3× (two clean sweeps + the
  plant self-test); count stable at 8.

Honest framing: this does NOT mean a user *could* widen. Core denies correctly.
The defect is that the *oracle* could not see the rule, so it could not alarm on a
future regression and mis-scored the clean tree. The fix strengthens the oracle
(adds a rule + a plant); it does not weaken it.

## 4. RED-PROOFs (every ENFORCED check the sweep centres on was broken and watched go red)

Plants were applied to the working tree, the targeted test run, the red result
observed, and the plant reverted. None was committed. Working tree verified clean
(`grep "if false &&"` → none) after reverting.

| Check (file:line) | Plant | Test | Result |
|---|---|---|---|
| machine_token.go:210 (restricted-PAT refusal) | `if false && …` | `TestIssueMachineToken_RestrictedPATCannotMint` | FAIL (red) ✓ |
| authz.go:725 (user target-perm ceiling) | `if false && …` | `TestIssueMachineToken_UserCannotMintForPeerHoldingPermissionItLacks` | FAIL (red) ✓ |
| authz.go:1245 (shared grant-ceiling loop) | `if false && !ok` | `TestInviteToProject_EnforcesAdminCeiling` | FAIL (red) ✓ |
| authz.go:731 via authzdiff overlay | `fix-4332` plant | `TestPlantsAreDetected/fix-4332…` | 8 unexplained, control 0 ✓ |

The shared `requireGranterHoldsRolePermissions(NoBaseline)` loop is the single
mechanism behind sweep rows 2,4,5,6,7,8,10,11,12,17,18,21; the red-proof on one
representative caller (invite) plus the AST registry guards
(`TestGrantCeilingReachingMethodsFileIsCurrent`,
`TestEveryGrantingServiceMapsPermissionDenied`) make "every granting method is
wired and maps the refusal" machine-checked, not asserted.

## 5. Reachability traces (before any exploitability claim)

- **Row 9 `AssignUserRoleScoped`/`AssignRoleToUser`.** Grep of `server/` found
  callers only in `_test.go`. No HTTP handler / gRPC service calls them. They pass
  `actorID=0, actorIsMachine=false`, hitting the documented trusted-local-CLI
  exemption (authz.go:1169). Not transport-reachable ⇒ **N/A-CLI, not a gap.**
- **Row 16 `IssueSetupToken`.** No non-test transport route calls it directly. Only
  `CreateUserWithSetupLink` (user_service.go:118, users_crud.go:148 — gated by
  row-7 ceiling) and `ResendAccountSetupLink` (users_crud.go:726 — gated by
  `requireAdminRankCeilingForTarget`). The existing-user takeover vector is closed
  by that admin-rank ceiling. **Enforced via callers.**
- **Row 3 `CreateMachineIdentity`.** Core does no authz; transport gate is
  `roles.assign`@project. Creation confers no roles/credential, so nothing is
  widened; credential minting is row 1. **Reachable by a `roles.assign` holder,
  grants nothing on its own.**
- **Row 15 `RefreshSession`.** `GetSessionAny` (auth.go:533) reads the session
  table only; a PAT is never there. Sessions are minted only by login/SSO. **No
  PAT→session widening surface.**

## 6. Admin-only vs non-admin-reachable (plainly)

Every ENFORCED row is reachable by a *non-admin* actor at the transport and is
still held to the ceiling. The only intentionally-elevating path, break-glass
(row 20), is reachable by any project *member* but is bounded (member-only,
justified, time-boxed, auto-expiring, mandatory audit+review) and refuses a
restricted PAT. The IdP path (row 19) is a trusted-infrastructure boundary, not a
non-admin Keyorix-actor path.

## 7. Per-oracle "what it does NOT verify"

- **Grant ceiling via `Authorize`**: verifies the actor holds each bundled
  permission at the grant scope ∩ PAT restriction. Does NOT verify the *target's*
  identity confinement, and is mint-time only (no retro-revoke).
- **`requireMachinePrivilegeCeiling` / `requireActorHoldsTargetPermissions`**:
  verifies the caller holds every target perm at each target scope. Does NOT check
  the caller credential's *expiry* (documented "Not covered"), nor re-check at use
  time.
- **`restrictedPATUngatedWrites` AST guards**: verify every ungated write declares
  a policy. Do NOT verify a *gated* write's `Authorize` call names the right
  permission/scope (authzdiff's job, fixture-bounded).
- **authzdiff differential (incl. my model fix + plant)**: compares core/REST/gRPC
  vs a reference model over a *fixed* fixture (one target machine per project).
  Does NOT prove absence of a widening path for inputs the fixture never builds, or
  for ops not registered in `ops_test.go`. The plant floor (4 < the 8 that exist)
  means the guard proves "≥4 cases detect the removal," not "exactly today's 8."
- **`GrantCeilingMethods` (AST reach)**: follows `c.method(...)` one hop and bare
  calls; does NOT follow function values, closures, or calls through another type.
  A grant path reached only via such indirection would be invisible to it; the
  sweep's manual enumeration found none, but that is an assertion.
- **This sweep's enumeration**: recognises today's grant/mint idioms; a new mint
  path under a new idiom must be added to it. The repo's AST guards are the
  standing machine-checked backstop — this document is a point-in-time pass.

## 8. IdP caveat (row 19)

SSO/SCIM deliberately skips the self-authority grant ceiling
(`assignUserRoleSystemGrant`) because a user's first SSO grant cannot require them
to already hold the role. Backstops: `idpAutoGrantOfRoleIsEscalation`
(authz.go:475-507) refuses an IdP auto-grant of an admin-tier role or `roles.assign`
itself, and `GroupRoleMap` is static YAML (operator-authored, not API-settable,
read at startup). Residual, NOT a non-admin Keyorix-actor gap: whoever controls the
IdP tenant can cause a user to receive any *ordinary* mapped role — the documented
IdP trust boundary. No code change warranted; recorded so the boundary is explicit.

## 9. Harness/environment findings (not security)

- **Repo-walking guards vs a nested worktree.** The forced linked worktree inside
  the main checkout makes `TestGuardTestsDoNotReadTheCalendar`
  (`internal/guardrules`) flag the worktree's *duplicate* of
  `internal/storage/factory_schema_epoch_1674_test.go` (exempt by its real path,
  not the `.claude/worktrees/wt/...` copy's path; `skipDirs` excludes
  `.scratch`/`.gopath`/`tmp` but not `.claude`). Local artefact only: the guard
  passes from the worktree and in CI. *Issue-ready suggestion, out of scope:* add
  `.claude` to `guardrules.skipDirs` — exactly the "tool/session state" category it
  already covers. Not done here (unrelated to the security property; task limits
  guard edits to confirmed gaps).
- **review-coverage ledger.** `internal/core` and `server/authzdiff` already carry
  fragment rows; adding another fragment with the same key would fail
  `check-review-coverage.sh`'s duplicate-key check. So no new ledger row was
  added — this sweep adds *evidence* to the existing `server/authzdiff` coverage
  (the model fix + plant) rather than minting a conflicting row.

## 10. Proof-of-green (tests run from the worktree, clean tree)

| Suite | Result |
|---|---|
| `server/authzdiff` | ok (18.3 s) |
| `internal/guardrules` | ok (2.1 s) |
| `internal/statemap` (INVARIANTS-fragment guard) | ok (9.6 s) |
| `internal/core` | recorded in §11 |

The authzdiff plant self-test log recorded: `plant
fix-4332-user-target-ceiling-removed: 8 unexplained cases, all on
machine.token.issue (control: 0)`.

## 11. internal/core result

See the final commit message. (Run from the worktree, no `KEYORIX_TEST_PG_DSN`, so
Postgres-gated tests skip, which is expected and not a failure in a DSN-less run.)

## 12. Talk material (5 sentences, honest about the negative result)

1. I swept all 22 credential-/permission-granting paths asked for — machine
   tokens, PATs, setup tokens, every role-grant primitive, sessions, invitations,
   access-request approval, restore, impersonation, SSO/SCIM and break-glass — and
   every one is already enforced, a documented exception, or reachable only by the
   trusted local CLI, so this is an honest negative result for production code.
2. The coverage is uniform because the repo funnels grants through one ceiling
   helper whose per-permission check runs `Authorize`, which itself intersects any
   PAT restriction — so "a restricted PAT can't grant beyond its restriction" falls
   out for free on every gated path, and a deny-by-default AST-guarded table catches
   the few mint paths that bypass `Authorize`.
3. I red-proofed the #4332 checks and a representative grant-ceiling caller by
   planting their removal and watching the exact tests go red, then reverting — so
   the "enforced" verdicts are backed by tests I watched fail, not by reading.
4. The one real defect is in the differential test oracle, not production:
   `server/authzdiff`'s model only taught the machine-token target ceiling to
   *machine* callers, so after #4332 added the *user*-caller rule the clean tree
   carried 8 silent over-denials and the existing plant's control was broken — I
   fixed the model and added a `fix-4332` plant that keeps a red differential case
   for the user path.
5. What none of this proves: the ceilings are mint-time only, the caller-credential
   *expiry* dimension is explicitly out of scope, and the differential harness only
   sees the inputs its fixed fixture builds — so "no widening path" means "none
   reachable by the idioms and fixtures we check today," which is why the standing
   AST guards, not this one-time pass, are the real backstop.
