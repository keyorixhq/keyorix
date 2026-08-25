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
- **A merge badge is not a merge — but `--is-ancestor <branch> origin/main` is not
  the fix either.** GitHub can report a PR as "Merged" while its branch was actually
  merged into a PREVIOUS PR's feature branch, never into `main` — a chain of
  branch-into-branch merges can make every PR in the chain show "Merged" with none of
  them ever reaching `main`. Found 2026-08-25: PRs #1563–#1566 all showed "Merged" on
  GitHub; none were ancestors of `origin/main`. **That check is unsound as a general
  rule, not just in this one case**: this repo squash-merges every PR, which mints a
  brand-new commit SHA, so a correctly-landed branch's own pre-squash commits are
  NEVER ancestors of that squash commit either — `--is-ancestor <branch> origin/main`
  returns false unconditionally, for every PR, landed or not. A check that always
  fails is exactly as uninformative as one that always passes, and worse, because it
  looks like evidence. The actual check: `gh pr view <N> --json baseRefName` (a PR
  based on a feature branch, not `main`, did not reach `main` no matter what its
  reported state says) plus `git diff <branch> origin/main --stat` (empty means the
  content is already there). Guard closures on artifacts present in the tree (a
  marker: a test that must exist, a symbol that must exist or must be absent), or on
  the baseRefName+diff check above — never on `--is-ancestor` across a squash
  boundary. Checking `--is-ancestor <sha> HEAD` for one already-resolved commit SHA
  against your own branch's own live history is a different, sound question (is this
  specific object included) — the unsound case is specifically a whole branch tip
  checked against a squash-merge target.

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
- A check that always fails is as useless as one that always passes — and worse,
  because it teaches people to ignore it (or, if CI-enforced, blocks everything
  indiscriminately until someone routes around it). Before adding a guard, confirm
  it is green on a known-good case as well as red on a known-bad one — both
  directions, not just the failure you set out to catch.
- A skip with a wrong reason is worse than no skip.
- Timeouts detect hangs; they don't enforce speed. Set them generously, watch durations.
- When determining whether something needs fixing costs more than fixing it, fix it.
- On Postgres, catching a constraint violation after the failing statement is not
  recovery — the transaction is already aborted at the protocol level, and a
  subsequent COMMIT is silently downgraded to a ROLLBACK. Prevent the conflict
  (`INSERT ... ON CONFLICT DO NOTHING`, then read back), don't catch it. A caught
  violation that returns a non-nil error (triggering ROLLBACK) is fine — ROLLBACK
  succeeds on an already-aborted transaction; only a caught violation that returns
  `nil` (intending COMMIT) is dead code on Postgres. `TryAcquireSchedulerLock`
  (`local_scheduler_lock_lease.go`) was the confirmed instance; a full-repo sweep of
  every other `isUniqueViolation`/constraint-catch site found no other dead ones —
  every other site either isn't inside a multi-statement transaction at all, or
  returns a non-nil error.
- A test named for a condition it does not create proves nothing. The original
  `TestConcurrency_BootstrapSystem_CrossReplicaExactlyOneAdmin` handed every
  simulated "replica" the SAME shared `storage.Storage` instance — one
  `LocalStorage`, one process-local mutex — so it would have passed identically
  even with the Postgres advisory lock deleted outright. The name asserted
  cross-replica safety; the fixture could not structurally exercise it (multiple
  independent `*gorm.DB` connections are required, not multiple wrapper objects
  sharing one).
- "Green when the lock is disabled" is ambiguous, and the ambiguity is unfalsifiable
  from that observation alone: it is equally consistent with *the lock is redundant*
  and with *this harness never exercised the lock*. Don't conclude redundancy from a
  disabling-mutation result by itself — first confirm the harness reproduces the
  production concurrency shape (same transaction boundaries as the real caller, same
  call sequence), and that the assertion states an invariant that holds under EVERY
  legal interleaving, not just the one the test author had in mind. The
  machine-identity row-lock test failed both checks at once, and each one masked the
  other: (1) it called `LockMachineIdentityForUpdate` and `TransitionMachineIdentityState`
  standalone rather than inside the same `WithTransaction` the real caller
  (`transitionMachineInTx`) uses — `SELECT ... FOR UPDATE` outside an explicit
  transaction is a no-op on Postgres (the lock releases the instant that single
  autocommit statement completes), so the "lock" was never actually held across the
  read+write; (2) its assertion ("exactly one of two racing transitions may win")
  was false as an invariant regardless of locking, because `active`→`revoked` is
  itself a legal transition — if `active` wins the race to go first, `revoked`
  legitimately gets a second, later, ALSO-successful write, and the assertion never
  checked the one thing that actually mattered: that `revoked` must always win the
  row's FINAL value. Fixing the transaction-wrapping bug alone made the flawed
  assertion flaky (2/10); only fixing both together — real transaction boundaries AND
  a correctly-derived invariant — made the lock's true load-bearing status visible
  (red 13/15 runs without it). A `securefiles.safeRelComponents` vs `resolveInside`
  case from earlier in this campaign IS genuine redundancy (confirmed by disabling
  both layers, with a harness that correctly reproduced the real call path
  throughout) — the lesson isn't "assume redundancy is always wrong," it's that the
  observation alone never tells you which one you're looking at. A same-worktree
  follow-up audit then traced every real production caller of all six FOR UPDATE
  sites in `internal/storage/store` (not test callers) and confirmed every one
  correctly shares one transaction with its guarded write — the standalone-lock bug
  the test harness had was a test-only defect, not a production one.
