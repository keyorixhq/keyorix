### Fixed
- **Compliance posture no longer reads a degraded break-glass activation as clean.** An activation committed while the audit log refused its rows (BREAKGLASS-OWED-1), whose owed rows the backfill has not yet written, is now counted in `emergency_access.degraded_activations` and marks the snapshot `degraded` with one `emergency_access_audit:project=<id>` reason per project (it makes the emergency-access control Unknown, not the independent-reviewer control), so an evidence pack does not claim a complete audit record for it. It reads clean again once the backfill settles it. The web tile and `keyorix compliance` do not show the new field yet.
- **`POST /api/v1/users/{id}/unlock` is now in the OpenAPI spec** (`unlockUser`), including its typed 503 `audit_unavailable` response (the unlock is audited fail-closed and safe to retry).

### Testing
- `TestFailureNamedAuditEvents_AreWrittenWithSuccessFalse` now has calibration cases on synthetic sources (literal, constant and wrapper violations red; clean and allowlisted sources green; stale entry and run-time event types reported), so the guard cannot go vacuous.
