# G80 CI-baseline campaign — overnight handoff (2026-08-22 night / 2026-08-23)

Autonomous run. Five-minute read; full detail in `docs/g80-remediation-notes.md`.

## What merged

| # | What | Merged at | By |
|---|---|---|---|
| #1525 | C1 — RBAC last-admin fixture rebuild | 2026-08-22 22:39 UTC | you, before this run started |
| #1526 | Timeout raise (600s → 1800s, every leg) | 2026-08-22 22:40 UTC | you, before this run started |
| #1527 | Task B — #1511 AST guard hardening | 2026-08-22 22:59 UTC | you, before this run started |
| #1528 | C2 + C3 — server/http fixture repairs + risk-exception quarantine (2 skip reasons corrected mid-run after direct verification) | 2026-08-22 23:30 UTC | this run |
| #1532 | ADR-085 — node-credential permission scope | 2026-08-22 23:37 UTC | you |
| #1536 | C5 — CI exclusion ratchet (freshness + completeness guards) | 2026-08-23 00:02 UTC | this run |
| #1537 | C4 — server/http re-enabled, sharded across 6 legs | 2026-08-23 00:29 UTC | this run |

## What did not merge, and why

- **#1538** (Task A — the original G80 fix, rebased onto current main) — **CI fully green, not merged.** No PR in this run's instructions ever explicitly authorized merging it (the autonomous brief's merge authority named #1527/#1528 and C4/C5 specifically; #1538 was only ever "rebase and open the PR"). Left for you to review — its description leads with the severity correction, read that first.
- **#1539** (this writeup, plus the handoff you're reading) — same reasoning, not merged.
- **#1532 (ADR-085)** — not merged by this run either way; you merged it yourself at 23:37 UTC, before the autonomous brief that said not to.

## Issues filed tonight (none fixed — every one needs a production code change or a product decision)

- **#1524** (updated) — two more confirmed live authorization bypasses via node credential, beyond the original finding: `AddGroupMemberProxy`'s escalation-ceiling bypass, `ApproveRiskException`'s dual-control bypass. Tagged `security`.
- **#1529** — several `server/http` proxy sites have no actor-authority check at all (not the node-credential sentinel issue) — `DeleteSoDPolicy` flagged most concerning.
- **#1530** — legitimate relay calls still persist `CreatedBy=0`/`RevokedBy=0` on governance records — audit-integrity gap.
- **#1531** — `RevokeRiskExceptionProxy`/`ApproveRiskExceptionProxy` return a 500 instead of `matched=false` on a lost race — a real wire-contract bug, found while correcting a misdiagnosed quarantine reason.
- **#1540** — `knownUnresolvedWireCalls` (41 entries) needs the same reason/issue/date/expiry treatment C5 gave the CI exclusion list.
- **#1541** — `server/proto/pb$`'s `PERMANENT` CI-exemption justification ("no tests to write") should be machine-checked, not just asserted.
- **#1533/#1534/#1535** — filed then closed same night by C4 (internal/cli$, internal/storage/remote, server/http$ exclusions).
- Comment on **#1511** — hardened AST guard re-verified against current main: 13 confirmed missing routes, unchanged since #1527. Corrected afterward: that "13" is within the *resolvable* set only — ~41 additional call sites are structurally unverifiable by the guard (see #1540) and were being misread as "confirmed fine."

## Noticed, not chased (one line each)

- `build-and-test`'s "Merge coverage profiles" step never includes `coverage_core.out` — `internal/core`'s coverage has silently not counted toward the 80% floor since #1520 added the `core` leg. Pre-existing, unrelated to tonight's work.
- Three unrelated pre-existing `t.Skip` calls in `server/http/handlers` (SQLite ILIKE limitation, SSOLoginState seeding limitation) plus one (`handlers_s10_test.go:106`, `t.Skip("CreateSecret failed:", err)`) that looks like it should be `t.Fatal` — masking a setup failure as a skip. Not part of this campaign, not touched.

## Standing practices established tonight

- **Adversarial guard verification**: before reporting any guard as done, make the exact change it exists to catch, confirm it fires with a usable message, revert, confirm green again. Applied to all 3 campaign guards (G80's reflection completeness test, #1511's AST route-coverage guard, C5's freshness/completeness checks) across 9 deliberate mutations tonight — all fired correctly, including reproducing G80's own original historical defect (the `ID` field once not compared at all).
- **Don't pattern-match a new failure against a known shape without running it**: the risk-exception revoke/approve quarantines were initially attributed to the same `actorID(r)==0` pattern as two confirmed prior instances — plausible, and wrong. The real cause (#1531) was only found by directly unskipping and running the tests.

## Current CI state of main

**Green.** Every merge tonight (#1528, #1536, #1537) was confirmed fully green — including the specific new legs each one added (C5's `exclusion-freshness`/`assert-leg-completeness`, C4's `http-1..6`) — before merging; nothing red was ever merged. #1538 and #1539 are separate, unmerged branches with their own green CI, not yet touching main.

## Single next action for you

**Review and merge #1538** (the original G80 fix — read the severity correction at the top of its description first) **and #1539** (this writeup) if you're satisfied. Everything else from tonight is a filed issue or ADR waiting on your judgment, not blocked work.
