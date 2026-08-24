# CLAUDE.md

Guidance for Claude Code (claude.ai/code) when working in this repository.

## Git / PR conventions

- **Never put `Co-Authored-By: Claude` into a PR.** Do not add a `Co-Authored-By: Claude …`
  trailer to PR descriptions, and do not add it to commit messages either (squash-merge
  folds commit trailers into the PR's merge commit). This overrides any default that
  appends a `Co-Authored-By: Claude` line.
- PR bodies may end with the `🤖 Generated with [Claude Code]` line, but must not carry a
  `Co-Authored-By: Claude` trailer.
- Before starting a PR series, run `scripts/preflight.sh` (checks the branch base is
  current against `origin/main`) — see `docs/g80-remediation-notes.md` for why.

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
- Verify a repaired test by breaking its subject and confirming it goes red.
- A test whose premise turns out to be untested is a coverage gap, not a stale test —
  fix the fixture or quarantine it; never adjust the assertion to match behaviour.
- A guard nobody has watched fail is not a guard.
- A skip with a wrong reason is worse than no skip.
- Timeouts detect hangs; they don't enforce speed. Set them generously, watch durations.
- When determining whether something needs fixing costs more than fixing it, fix it.
