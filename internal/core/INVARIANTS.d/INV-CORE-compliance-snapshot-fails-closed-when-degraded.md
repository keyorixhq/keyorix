- **INV-CORE-compliance-snapshot-fails-closed-when-degraded** A `CompliancePostureSnapshot` row is
  an audit artefact and is written only from a posture in which EVERY sub-rollup was read
  (`CompliancePosture.Degraded == false`). `TakeComplianceSnapshot` (POST /api/v1/compliance/snapshots)
  returns `ErrCompliancePostureDegraded` (HTTP 503, naming the unreadable areas, not the raw storage
  error) and persists nothing when any count/list read failed, and returns the save error instead of
  swallowing it; `GetCompliancePosture` still returns a degraded posture to its caller (flagged
  `Degraded`/`DegradedReasons`) but does not persist it either. No `compliance.snapshot_taken` audit
  event is written on any failure. Why: #2834 -- a stored snapshot with partial counts reported
  SUCCESS, and nothing forces every consumer to read `DegradedControls`. Guard:
  `TestTakeComplianceSnapshot_DegradedPostureFailsClosed_2834`,
  `TestTakeComplianceSnapshot_HandlerDegradedFailsClosed_2834`, and the fuzz oracle (a) replay
  `TestComplianceSnapshotFailsClosed_2834` (server/faultops) with no tolerance entry.
