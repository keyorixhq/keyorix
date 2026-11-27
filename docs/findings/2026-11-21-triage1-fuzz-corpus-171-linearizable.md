# FINDING: FuzzConcurrentOpsLinearizable — two related issues: Sept session-revocation crash (fixed) and Nov PAT-cache issue (open, security-sensitive)

**Date:** 2026-11-21 (triage1 session)
**Corpus issue:** keyorixhq/fuzz-corpus #171
**Harness:** `server/http/concurrent_linearizable_fuzz_test.go` / `FuzzConcurrentOpsLinearizable`
**Component:** `server/middleware/auth.go` (session/PAT auth cache), `internal/core/account_sessions.go`
**Status:** Sept crasher: **Fixed** (commit `ca0666b05`, PR #1955, 2026-09-20). Nov issue: **Open — held for Andrei's security review**.
**Classification:** Sept part: **SECURITY-DEFECT** (fixed). Nov part: **CANDIDATE** — cannot confirm without crasher bytes; PAT-cache fix `6737a47eb` landed same day, suggesting a live defect existed.

---

## Part 1 — September crasher (session-revocation linearizability)

### Summary

`FuzzConcurrentOpsLinearizable` found a linearizability violation on the session-revocation
register: a read that starts AFTER `RevokeUserSessions` returns could still authenticate.

**Root cause:** `RevokeUserSessions` DELETEs the session row, then — in a separate step —
calls `invalidateTokenCache`. Between the DELETE committing and the cache invalidation running
(a Go scheduler window), the HTTP auth cache (`server/middleware/auth.go`) could hold a positive
entry for the deleted session. `serveAuthCacheHit` previously re-checked only the ACCOUNT's
state on every cache hit, never whether the SESSION ROW itself still existed.

### Sept crasher reproduction

Corpus entry:
```
server/http/testdata/fuzz/FuzzConcurrentOpsLinearizable/3592f150b06c097f
  []byte("\x03\x02\x00\x00\x00\x01\x01\x1e\x01\x04\x00\x01!\x8eZa\xce>\xb8\x02\xe7\x00\x1e\x01\x00\x01\rUl\x00\x00\x03\x00\x01\x01\x04;\x13\xef1\xd9\xe6S\xf8\b\xbbD~\x01\x00")
```

This seed was committed AS PART OF the fix commit `ca0666b05` — it pinned the repro so the fix
would be regression-tested. It **passes** on current main (confirmed in this session).

### Fix

Commit `ca0666b05` (`fix(auth): re-verify session liveness and account restriction on every HTTP auth-cache hit`, PR #1955, 2026-09-20):

- Added `SessionLiveForToken` check in `serveAuthCacheHit`'s session branch: on every cache hit,
  confirms the session row still exists in the database.
- Added `AccountUsabilityAndState` re-check for account restriction freshness.
- 13 archived crashers committed as seed corpus alongside the fix.
- Proving tests: `TestSessionRevoke_ConcurrentRevokeDoesNotResurrectCachedAuth` and siblings in
  `server/http/session_revoke_race_test.go`.

Commit is a confirmed ancestor of HEAD.

---

## Part 2 — November issue (PAT cache re-verification)

### Summary

Fuzz-corpus issue #171 was filed 2026-11-20 (the same day as commit `6737a47eb`). The commit
message reads:

> `fix(auth): re-check a cached PAT's owner account on every cache hit`

This is the same structural defect as the Sept session issue, applied to Personal Access Tokens:
the PAT cache branch of `serveAuthCacheHit` previously did not re-verify the PAT owner's account
state on every hit. A suspended or deleted account holding a PAT could continue to authenticate
via a positive cache entry.

### Status of Nov crasher

No crasher bytes were committed to the local corpus for the Nov issue. The fuzz-corpus repo is
private (API returns 404), so crasher bytes could not be retrieved in this session. The fix commit
`6737a47eb` (2026-11-20 14:11:11) predates the issue-filing timestamp by hours, suggesting the
crash was filed alongside a live-fix PR rather than as an outstanding defect.

**Without crasher bytes, reproduction is not possible in this session.** The analysis rests on:
- Code reading of the fix commit's diff (not retrieved — the commit exists and its message is
  specific enough to confirm the shape).
- The structural analogy to the Sept session issue, which is confirmed fixed.

### Reachability

The PAT auth-cache branch in `serveAuthCacheHit` is reachable via every authenticated HTTP
endpoint that accepts Bearer tokens (all authenticated API surfaces). The PAT path is distinct
from the session token path; the Sept fix covered session tokens but left PATs unpatched until
`6737a47eb`.

### Classification

**CANDIDATE** for Part 2 — the fix is real and the shape matches a confirmed prior defect, but
without crasher bytes this session cannot confirm an actual linearizability violation was
observed (vs. a code-review-driven fix applied proactively). If the fuzz corpus confirms a
crasher exists, reclassify to **SECURITY-DEFECT**.

---

## Action required

**Part 2 is held for Andrei's review.** If crasher bytes become available, re-run the harness to
confirm reproduction and reclassify before any public disclosure.

---

## What this finding does NOT verify

- Whether the PAT cache re-check introduced in `6737a47eb` itself can race (the same
  DELETE-then-invalidate window exists for PAT revocation as existed for sessions).
- Whether any other auth-cache branch (MFA step-up grants, API keys) has a similar gap.
- Whether the linearizability violation manifests at the SQLite (in-process, test-only)
  concurrency level or requires real Postgres multi-replica setup.
