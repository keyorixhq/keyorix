- **INV-CORE-posture-audit-verdict-never-better-than-persisted** The compliance posture's
  audit-integrity verdict (and the digest, control framework and evidence pack built from
  the same snapshot) is never a better verdict than the persisted verification state's
  when its own chain check could not run. A failed posture refresh shows
  `AuditVerificationStatus` (so a break or discontinuity the scheduler or a full job
  recorded, and the overdue `not_proven` after two scheduler intervals, are shown), marked
  stale; it never serves an older posture walk. Inside the five-minute cache window a
  break the persisted state records forces a new walk. Not covered: a break recorded by
  another replica's state between the cache's persisted read and the response (bounded by
  one request). Why: REVIEW-4539 MEDIUM-1 (a failing refresh froze "chain verified").
  Guard: `TestPostureAuditCheck_FailedRefreshShowsRecordedBreak`,
  `TestPostureAuditCheck_FailedRefreshAgesToNotProven`,
  `TestPostureAuditCheck_RecordedBreakBypassesTheCache` (`internal/core`).
