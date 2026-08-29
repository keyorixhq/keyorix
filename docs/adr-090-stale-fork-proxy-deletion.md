# ADR-090: Deleting the 3 stale-fork `/system` proxies #1592's sweep found — no live caller, under any topology

## Status

**Accepted (2026-08-28).** #1585, #1586, #1587. Deletion executed in this pass.

## What this is

#1592 swept every `/system` proxy for the "stale fork" shape: a proxy
calling a plain, unconditional `storage.Storage` write method that
`internal/core` was rewritten to stop calling, in favor of a safe
CAS/exclusive/guarded sibling built specifically to close a race the
plain method cannot. Three proxies matched:

- **`UpdateMachineIdentityProxy`** (#1585) — called
  `storage.UpdateMachineIdentity` (a raw, unconditional full-row `Save`)
  where `core.ClassifyMachineIdentity`/related callers now exclusively use
  `TransitionMachineIdentityState`, the `WHERE id = ? AND state = ?` CAS
  write built (#388/#518) to close the exact lost-update race a blind
  `Save` reproduces.
- **`UpdateMembershipProxy`** (#1586) — called
  `storage.UpdateProjectMembership` (same raw-`Save` shape) where
  `internal/core`'s membership-state transitions now exclusively use
  `TransitionProjectMembershipState`, built (#G42) to close the same class
  of TOCTOU the raw call reopens over an HTTP hop.
- **`CreateSecretDependencyProxy`** (#1587) — called
  `storage.CreateSecretDependency` (a raw, unconditional persist, no
  duplicate/cycle check) where `AddSecretDependency`
  (`internal/core/secret_dependencies.go`) now exclusively calls
  `CreateSecretDependencyExclusive`, built (#260) specifically because the
  caller-orchestrated list-then-create sequence this raw call implies
  cannot be made atomic across a request boundary.

Initial framing (per the user's Task 1 requirement to check the wire
shape first) treated these as live findings needing only a CAS-aware wire
payload — i.e., that the fix was to teach the existing proxies to carry an
expected-state field and swap to the safe sibling. **A full liveness
check, done to a deliberately higher evidence bar than ADR-089's, found
none of the three has any caller, under either server or CLI topology.**
All three are deleted here, on the same terms as ADR-089's MFA/purge
family: the `/system` handlers and their route registrations are removed,
the `RemoteStorage` client methods become `remoteUnsupported` stubs.

## Why the evidence bar was raised, not lowered, for this pass

ADR-089's error ran one direction: declaring LIVE too quickly, on the
strength of a real call site that turned out to be unreachable under
`storage.type: remote`. Here the risk runs the other way — declaring DEAD
too quickly costs deleted code, not a missed fix. The asymmetry means the
DEAD conclusion needed to survive a harder test than ADR-089's LIVE
retraction did, not an easier one. Five checks were run, all independently
confirmed rather than presumed from the previous ADR's method:

1. **Full call chain traced end to end**, not just to the nearest
   wrapper: for each of the three, every real `internal/core` caller of
   `ClassifyMachineIdentity`/the membership-transition path/
   `AddSecretDependency` was enumerated by grep, and none constructs a
   `RemoteStorage`-backed core that could reach the deleted proxy's client
   method — the same "call graph edge is not a deployment path" check
   ADR-089 names.
2. **Cross-checked against `remoteReachabilityRegistry`
   (#1590)**: none of the three methods appeared in it before this pass,
   because that registry only classifies stub-shaped methods —
   `UpdateMachineIdentity`/`UpdateProjectMembership`/
   `CreateSecretDependency` were real, non-stub implementations with zero
   callers, a gap the registry's own scope never covered. This gap is
   itself worth naming, not just worked around: a "no live caller" finding
   for a fully-implemented method is structurally invisible to a registry
   built to classify stubs. New `reachabilityDead` entries are added here
   to close it for these three specifically; the general gap (real,
   callerless implementations elsewhere) is not swept in this pass.
3. **All three CLI-reaching idioms checked by name**:
   `common.NewRemoteClient()`/`common.ResolveRemote()` (thin-HTTP mode,
   never touches `/system`), `CLIConfig.IsClientMode()` +
   `common.InitializeCoreService()` (embedded mode, can construct a
   `RemoteStorage`-backed core unvalidated by `Config.Validate()` — the
   path ADR-089's Ground 2 depends on), and the third idiom this pass
   named explicitly: **direct `internal/core.KeyorixCore` construction
   against a `LocalStorage` backend inside a CLI command that never touches
   `RemoteStorage` at all** (the overwhelming majority of CLI commands) —
   relevant here because it rules out a false-positive "the CLI calls
   this" match against a command that never goes through `RemoteStorage`
   in the first place.
4. **CLI commands checked by name, not by category**: `keyorix machine
   identity update` (`internal/cli/machineidentity/`),
   `keyorix project membership update`/`transition`
   (`internal/cli/project/` and `internal/cli/membership/` — no such
   subcommand exists; membership mutation goes through
   `TransitionProjectMembershipState`-backed commands only), and
   `keyorix secret dependency add` (`internal/cli/secret/` —
   `AddSecretDependency` is the only path, and it calls
   `core.AddSecretDependency`, which itself calls the safe
   `CreateSecretDependencyExclusive`, never the raw method). None of these
   command implementations calls the deleted `RemoteStorage` methods
   directly; all route through the same `internal/core` functions the
   server-side chain trace already covered.
5. **`Config.Validate()`/embedded-path applicability confirmed by name**:
   `validateRemoteStorageNotServer` (`internal/config/config.go:2057`)
   applies only to a process that calls `Config.Validate()` —
   `server/main.go` does, `internal/cli/common.InitializeCoreService()`
   does not. This asymmetry is why the CLI embedded path is the one that
   determines "dead" vs. "dead but revivable" here, exactly as it did in
   ADR-089: the server-side path for these three is structurally
   impossible (no server handler ever calls `UpdateMachineIdentity`/
   `UpdateProjectMembership`/`CreateSecretDependency` on its own local
   core — those calls exist ONLY inside the three deleted proxy handlers
   themselves), and the CLI path is genuinely open but unused today.

**One fix was made regardless of the liveness outcome**, per explicit
instruction: `UpdateMachineIdentityProxy`'s doc comment falsely claimed
`core.ClassifyMachineIdentity` was a caller. Corrected in PR #1597,
landed independently of this deletion's outcome.

## Three revival hazards, not one flattened claim

All three are dead for the same structural reason (no caller, and the
server-side path is impossible), but the ease with which a future change
could revive each — and thus how carefully re-review should be scoped
when that happens — is genuinely different per handler. Collapsing this
into a single "all three are equally dead" sentence would discard exactly
the information the next person needs.

- **#1585 (`UpdateMachineIdentityProxy`) — low hazard.** Revival requires
  someone to write a NEW, incorrectly-designed `internal/core` method that
  calls the raw `UpdateMachineIdentity` sibling instead of
  `TransitionMachineIdentityState` — i.e., a fresh design mistake, not the
  restoration of an existing command. `keyorix machine identity update`
  already exists and already goes through the safe path; there is no
  natural next CLI command whose obvious first draft would reach for the
  raw method.
- **#1586 (`UpdateMembershipProxy`) — low hazard.** No project-membership
  CLI surface exists at all today for direct field mutation (only
  transition-shaped commands exist), so reviving this requires both a new
  CLI command AND a design choice to bypass the transition primitive
  that command's neighbors already use as precedent. Slightly more
  friction than #1585 only in that the safe sibling isn't already the
  visible convention for an existing sibling command — but there is no
  live command to accidentally extend either.
- **#1587 (`CreateSecretDependencyProxy`) — lowest hazard.** The
  command that would need this exists today (`keyorix secret dependency
  add`) and already calls `core.AddSecretDependency`, which itself
  already calls `CreateSecretDependencyExclusive` — the safe sibling is
  not just conventionally preferred, it is the ONLY code path currently
  wired to this feature. Reviving the raw proxy would require actively
  rewiring an already-correct call chain to bypass its own existing
  cycle-check, the least likely of the three by a clear margin.

**All three are materially safer to delete than ADR-089's MFA family**,
where writing `keyorix mfa disable` would directly revive a dangerous
surface by giving an obvious, expected command a plausible naive
implementation. Here, reviving any of the three requires either
inventing a command that doesn't exist (#1586) or actively un-wiring a
command that already does the right thing (#1585, #1587) — there is no
"first thing you'd try" path back to the raw method the way there was for
MFA.

## Amending #1592's conclusion

#1592's sweep is not "we found and fixed three stale forks" — that
phrasing undersells what the sweep actually established. The correct,
stronger claim: **the stale-fork pattern's population was fully
enumerated, and its live extent turned out to be zero.** Every instance
the pattern could produce, across the entire `/system` proxy layer, was
either never built as a live caller or has since lost its only caller.
This is the more honest and more reassuring claim, and #1592 is amended
to state it exactly this way, not the weaker "found and fixed three"
framing.

## Population derivation

Two independent methods, cross-checked, both converging on the same three
candidates plus the two known-safe exceptions:

1. **Commit-message search**: each safe sibling's introducing commit
   names its own complete scope of callers it was meant to replace — `G42`
   (`TransitionProjectMembershipState`), `8ba2109d`/`#518`/`#517`
   (`TransitionMachineIdentityState`), `#260`/`#519`
   (`CreateSecretDependencyExclusive`), `#528`
   (`TransitionSecretStatus`/`TransitionDynamicSecretConfigDisabled`),
   `#525`/`#340` (`UpdateUserIfActiveStateMatches`), `#303`/`#304`
   (`RevokeRiskExceptionIfNotRevoked`/`ApproveRiskExceptionIfPending`).
2. **Structural scan**: every `internal/core/storage/interface.go` method
   with a `(bool, error)` CAS-return signature, or a doc comment
   containing "conditional"/"atomically"/"CAS", paired against its
   plain-write sibling by name.

Both derivations agree on the eleven pairs in `unsafeSiblingPairs`
(`server/http/unsafe_sibling_write_guard_test.go`). Cross-referencing
every `/system` route's handler body (AST-based, reusing
`extractAllRouterRoutes`/`handlerStorageCalls` from
`raw_storage_bypass_guard_test.go`) against those eleven keys found
exactly two allowlisted, reasoned exceptions
(`UpdateWebAuthnCredentialProxy`, `DeleteProjectProxy` — see the guard
file's comments for why each is safe despite matching) and the three
now-deleted instances. No other call site of this shape exists anywhere
in `server/http/handlers`.

**Stated residual gap**: a conditional-write method with neither a
telltale name, nor the `(bool, error)` signature, nor a
conditional/atomically/CAS doc comment would be invisible to both
derivations. None found, none ruled out as a category — this is a gap in
the derivation method itself, not a claim that no such method could ever
exist.

## What was actually deleted

**RemoteStorage client methods** (now `remoteUnsupported` stubs):
`internal/storage/store/remote_machine_identities.go` —
`UpdateMachineIdentity`; `internal/storage/store/remote_memberships.go` —
`UpdateProjectMembership`; `internal/storage/store/remote_secret_dependencies.go`
— `CreateSecretDependency`.

**`/system` proxy handlers and route registrations**:
`server/http/handlers/machine_identities_proxy.go` —
`UpdateMachineIdentityProxy`; `server/http/handlers/project_memberships_proxy.go`
— `UpdateMembershipProxy`; `server/http/handlers/secret_dependencies_proxy.go`
— `CreateSecretDependencyProxy`. Route registrations removed from
`server/http/router.go`: `PUT /machine-identities/{id}`, `PUT
/project-memberships/{id}`, `POST /secret-dependencies`.

**Left untouched, deliberately**: `machineIdentityProxyWire`/its `toModel()`
helper, `membershipProxyWire`, and `secretDependencyProxyWire` — all still
used by other, live handlers in the same files. `TransitionMachineIdentityStateProxy`,
`TransitionProjectMembershipStateProxy`, and
`CreateSecretDependencyExclusiveProxy` — the safe siblings these three
were stale forks of — are all real, live, and unaffected.

## The new preventive guard

`server/http/unsafe_sibling_write_guard_test.go`
(`TestNoProxyCallsUnsafeSiblingWhenSafeExists`) makes the "zero" durable:
it fails if any FUTURE `/system` proxy calls a key of `unsafeSiblingPairs`
without a reasoned `unsafeSiblingAllowlist` entry, naming the safe sibling
in the failure message. This is narrower and more specific than
`TestNoUnjustifiedRawStorageBypass` (which requires a reason for any
unreviewed raw write generally) — this guard names the exact unsafe→safe
relationship so the fix is self-evident from the failure message, not
just "add a reason."

Verified both directions:
- **Green** on the cleaned tree: exactly the two allowlisted calls
  (`UpdateWebAuthnCredentialProxy`, `DeleteProjectProxy`) remain flagged
  and excused; zero unallowlisted hits.
- **Red**: a synthetic `if false { _ =
  h.coreService.Storage().UpdateMachineIdentity(r.Context(), nil) }` block
  temporarily added to `GetMachineIdentityProxy` produced the expected
  failure naming `GetMachineIdentityProxy`/`UpdateMachineIdentity`/
  `TransitionMachineIdentityState`; reverted, guard re-confirmed green.

## Verification

- `go build ./...`, `go vet ./...`, `gofmt -l`: clean.
- `go test ./server/http/...`, `go test ./internal/storage/store/...`:
  clean except the same two pre-existing, unrelated failures noted in
  ADR-089 (`TestListShares_ExcludeExpiredIncludeActive`,
  `TestListSharesBySecretIDs`), unaffected by this change.
- Guards green: `TestNoUnjustifiedRawStorageBypass`,
  `TestEveryStructuralStubHasReachabilityVerdict`,
  `TestRemoteUnsupportedStubsAreAllowlisted`,
  `TestRemoteStorageWireCalls_HaveMatchingRoute`,
  `TestNoProxyCallsUnsafeSiblingWhenSafeExists`.
- `git tag pre-1585-1586-1587-stale-fork-deletion` placed before removal,
  annotated with what it preserves.
- Zero functional (non-comment) grep hits for `UpdateMachineIdentityProxy`,
  `UpdateMembershipProxy`, or `CreateSecretDependencyProxy` anywhere
  outside this ADR and the deletion comments left in their place.

## Precondition this decision depends on

Same structure as ADR-089's: sound only while `validateRemoteStorageNotServer`
continues to reject `storage.type: remote` for every server process, and
while no CLI command reaches these three `internal/core` methods through
their raw `RemoteStorage` siblings. If a CLI command is later added for
machine-identity field updates, membership field updates, or a
create-only secret-dependency path, this decision must be re-derived for
that family, not assumed to still hold — the guard above only prevents a
NEW `/system` proxy from reintroducing the raw call; it says nothing
about whether restoring the deleted proxy would be correct if a real
caller ever needs it.

## What this does not resolve

- #1592 itself remains filed, now amended per the section above.
- The relay-principal problem (`IngestAuditEventProxy`, deferred to Wave
  4) — unaffected.
- `IncrementSecretReadCount`'s dead-code status, noted during #1592's
  sweep — left for a future pass, not fixed here.
- Wave 2 proper (#1546/#1551/#1572/#1575), Wave 4, and the decision
  closures (#1523/#1509/#1494) — unaffected, unstarted.

## Addendum: #1579/#1580 (2026-08-29) — same methodology, a different shape

Not stale forks of a superseded unsafe primitive (this ADR's original
scope, #1585/#1586/#1587) — these two are orphaned relays: a `/system`
proxy whose backing `RemoteStorage` method never had ANY live caller in
this codebase's history, under either topology, closer in shape to
ADR-089's MFA/purge family than to #1585/86/87. Filed here rather than a
fourth standalone ADR because the deciding methodology — liveness-first,
report both verdicts before writing either fix, graduated revival-hazard
classification on deletion — is identical to what this document already
establishes, and a two-handler addendum did not warrant its own document.

- **`ConsumeSetupTokenProxy` (#1579)** — filed as a real, human-reachable
  purpose-blindness DoS (any `system.write` holder could burn an active
  setup token by ID regardless of intended purpose), which IS accurate
  as a standalone code-shape observation but never traced whether the
  route is reachable at all. It is not: `core.ConsumeSetupToken`'s only
  caller repo-wide is `server/http/handlers/auth.go`'s `CompleteSetup`
  (human-facing, unreachable from any process backed by `RemoteStorage`
  per `validateRemoteStorageNotServer`), and no CLI command calls
  `ConsumeSetupToken`/`CompleteSetup` either. Revival hazard:
  **true-today-but-unbuilt, low.** Nothing prevents a future CLI
  "complete setup non-interactively" command from being added (e.g. for
  scripted provisioning), but completing setup means supplying a NEW
  password only the subject knows — inherently self-service, unlike the
  admin-driven account-lifecycle operations (deactivate, suspend, revoke)
  a CLI operator legitimately performs on another user's behalf — so no
  existing convention points toward this being built. A revival must
  re-derive the purpose check this deletion removes (`tok.Purpose !=
  expectedPurpose`, `internal/core/setup_token.go`'s
  `consumeInspectedToken`) at the wire layer before trusting a caller-
  supplied token ID again.
- **`CreateDynamicSecretConfigProxy` (#1580)** — filed as a real
  reference-confusion gap (no `EnvironmentID`-belongs-to-`ProjectID`
  cross-reference check), same shape: accurate as a code-shape
  observation, never traced for reachability. It is not reachable: the
  G80 158-method classification pass
  (`remote_reachability_registry_test.go`'s `UpdateDynamicSecretConfig`
  entry, `entries=[ClassifyDynamicSecretConfig,CreateDynamicSecretConfig]`)
  had ALREADY classified this exact method `reachabilityDead` — the verdict
  existed before #1580 was filed; the code was simply never updated to
  match it. Independently re-confirmed here: `core.CreateDynamicSecretConfig`'s
  only callers are `server/http/handlers/dynamic_secrets.go` and
  `server/grpc/services/dynamic_secret_service.go` (both human-facing,
  server-only). The one CLI command that creates dynamic-secret configs
  (`internal/cli/dynamic/config_create.go`) uses the ordinary thin-HTTP
  client (`common.RemoteClient`) against the human-facing
  `/api/v1/dynamic-secrets/configs` route — NOT an embedded
  `core.KeyorixCore`+`RemoteStorage` instance — so it never reaches this
  proxy or its backing storage method at all. Revival hazard:
  **structurally unlikely, low.** A working, correct, idiomatic CLI path
  for this operation already exists (the thin-HTTP command above); a
  future feature need would naturally extend that path, not resurrect the
  embedded-core/RemoteStorage relay, so reviving this proxy specifically
  has no plausible trigger.

Both deletions follow this ADR's established "both sides" pattern exactly:
`RemoteStorage` client method → `remoteUnsupported` stub;
`/system` handler + router.go registration → removed;
`remoteUnsupportedAllowlist`/`remoteReachabilityRegistry` → new entries,
not left stale; `knownUnfixedRawStorageBypasses` → entries removed (no
longer reproduce, not silently left inaccurate). Verified by full test
suite (`internal/storage/store`, `server/http`, `server/http/handlers`,
`internal/core`, `internal/config`) green after every edit.
