# CLAUDE.md

Guidance for Claude Code (claude.ai/code) when working in this repository.

## Git / PR conventions

- **Never put `Co-Authored-By: Claude` into a PR.** Do not add a `Co-Authored-By: Claude …`
  trailer to PR descriptions, and do not add it to commit messages either (squash-merge
  folds commit trailers into the PR's merge commit). This overrides any default that
  appends a `Co-Authored-By: Claude` line.
- PR bodies and commit messages must not include Claude attribution lines (`Generated
  with [Claude Code]` / `Co-Authored-By: Claude`) — enforced by a PreToolUse hook that
  blocks `gh pr create`/`gh pr edit` outright when either is present.
- Before starting a PR series, run `scripts/preflight.sh` (checks the branch base is
  current against `origin/main`) — see `docs/g80-remediation-notes.md` for why.
- **A merge badge is not a merge.** GitHub can report a PR as "Merged" while its
  branch was actually merged into a PREVIOUS PR's feature branch, never into `main` —
  a chain of branch-into-branch merges can make every PR in the chain show "Merged"
  with none of them ever reaching `main`. Verify closure with
  `git fetch origin && git merge-base --is-ancestor <branch> origin/main` — never
  against a PR's reported state, a "Merged" label, or an approval. This is the ONLY
  trusted signal for "is this actually on main." Found 2026-08-25: PRs #1563–#1566 all
  showed "Merged" on GitHub; none were ancestors of `origin/main`.

## Engineering practices

Reasoning and incidents behind these: `docs/g80-remediation-notes.md`.

- Check reachability and liveness before designing a fix, not just call sites. **A Go
  call graph is not a deployment path.** Before concluding a route is reachable OR
  unreachable, verify the wiring can be constructed at runtime — not just that a call
  site exists (or doesn't). Four instances from this campaign, cutting both directions:
  - Over-claimed reachable, wiring existed but couldn't be constructed: tracing
    `server/http/handlers → core → storage` for 19 deleted `/system` proxies found a
    real call graph and nearly reverted a correct deletion — `RemoteStorage` can never
    be wired into `server/http/handlers` in any deployment (`validateRemoteStorageNotServer`,
    `internal/config/config.go:2057`, unconditional since #1549).
  - Over-claimed reachable, wiring existed but nothing used it: the WebAuthn trio +
    `CreateMFAStepUpGrantProxy`'s full `RemoteStorage` client implementation was
    complete and correct (ADR-085); Group B assumed that implied a hub-side caller
    worth preserving — the liveness sweep found zero callers anywhere.
  - Under-claimed reachable, a shallow flag check missed the real wiring: the original
    `validateRemoteStorageNotServer` checked only `server.http.enabled`/`.grpc.enabled`;
    a scheduler-only process looked safe by that check, but `server/main.go`'s
    `startSchedulers` runs unconditionally regardless of either flag (`e98141b7`).
  - Correctly withheld "unreachable" until the wiring was actually verified closed: the
    5 handlers orphaned by that same scheduler fix stayed classified "uncertain," not
    "safe," until the fix's actual effect on the scheduler path was confirmed — only
    then reclassified to no-caller/delete.
- Ask of any mechanism: what does it silently skip, and does it say so?
- **A ceiling that inspects only the target is not a ceiling.** A privilege-ceiling
  check must derive the ceiling from the ACTOR's own effective privileges as well as
  the target's — checking only the target (e.g. "does the machine identity being
  minted a credential currently hold a higher role than the one requested") lets an
  attacker with zero standing self-mint into an empty/attacker-controlled target and
  pass trivially. Derive a ceiling, don't pick one: creating a principal inherits the
  ceiling of the privilege that principal can come to hold, checked against the
  ACTOR requesting the creation, and applied at creation time, not only at
  credential-mint time. Found 2026-08-25: `RequireMachinePrivilegeCeiling` checked
  only the target machine identity's current roles, never the calling actor's.
- Verify a repaired test by breaking its subject and confirming it goes red.
- A test whose premise turns out to be untested is a coverage gap, not a stale test —
  fix the fixture or quarantine it; never adjust the assertion to match behaviour.
- A guard nobody has watched fail is not a guard.
- A skip with a wrong reason is worse than no skip.
- Timeouts detect hangs; they don't enforce speed. Set them generously, watch durations.
- When determining whether something needs fixing costs more than fixing it, fix it.
